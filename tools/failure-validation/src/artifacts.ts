import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { CML, Constr, Data, getAddressDetails, validatorToScriptHash, type OutRef, type ProtocolParameters, type UTxO } from "@lucid-evolution/lucid";
import type { Validators } from "./blueprint.ts";
import { ARGUMENT_MODES, parseBuiltins, type ArgumentMode, type Builtin } from "./builtins.ts";
import type { Network } from "./network.ts";
import type { Effects } from "./runtime.ts";
import { inputReferences } from "./transactions.ts";

export type TransactionRecord = {
  id: string; scope: string; name: string; hash: string; cbor: string; effects: Effects;
  requiredInputs: OutRef[]; referenceInputs: OutRef[]; consumedInputs: OutRef[];
  status: "signed" | "submitting" | "submitted" | "confirmed" | "stopped";
  signedAt: string; submittedAt?: string; includedAt?: string; confirmedAt?: string;
  confirmation?: unknown; error?: string;
};
export type SavedScripts = { networkTag: 0 | 1; builtin: Builtin; withdrawal: Validators["withdrawal"];
  parameters: Validators["parameters"]; mint: Validators["mint"]; hashes: { withdrawal: string; parameters: string; mint: string } };
export type Resource = {
  output: UTxO; role: "ordinary" | "nonce" | "setup-collateral" | "fee" | "withdrawal-collateral" | "collateral-return" | "argument" | "reference" | "parameters" | "proof-bundle";
  scope: string; createdBy: string; adopted?: boolean; confirmed: boolean;
  release: "immediate" | "cleanup" | "preserve" | string[];
  releasedBy?: string; consumedBy?: string;
};
export type CleanupCheckpoint = { started: boolean; complete: boolean; transactions: string[]; ordinary?: OutRef; proofBundle?: OutRef; parameters?: OutRef };
export type SharedSetupCheckpoint = {
  nonce?: OutRef;
  signers?: string[];
  threshold?: number;
  protocol?: ProtocolParameters;
  parametersPolicy?: string;
  parametersAddress?: string;
  parametersUnit?: string;
  parametersInput?: OutRef;
  parametersReference?: OutRef;
  mintCollateral?: OutRef;
  ready?: boolean;
};
export type SetupCheckpoint = {
  withdrawalReference?: OutRef;
  mintReference?: OutRef;
  rewardAddress?: string;
  stakeAlreadyRegistered?: boolean;
  ready?: boolean;
};
export type CaseCheckpoint = {
  mode?: ArgumentMode;
  argumentReferences?: OutRef[];
  argumentIndexes?: number[];
  resolvedArguments?: string;
  redeemer?: string;
  protocol?: ProtocolParameters;
  feePasses?: number;
  stage?: string;
  collateralInput?: OutRef;
  collateralInputLovelace?: bigint;
  failureReturn?: OutRef;
};
export type RunManifest = {
  version: 4; network: Network; walletAddress: string; paymentKeyHash: string; status: "running" | "passed" | "stopped";
  resources: Record<string, Resource>; proofBundle?: OutRef; cleanup: CleanupCheckpoint;
  selection: Builtin[]; scripts: Record<string, SavedScripts>; setup: Record<string, SetupCheckpoint>;
  shared: SharedSetupCheckpoint; cases: Record<string, CaseCheckpoint>; transactions: TransactionRecord[]; reports: Record<string, Record<string, unknown>>;
};

function transactionInfo(cbor: string) {
  assert(/^(?:[0-9a-f]{2})+$/i.test(cbor), "Invalid saved transaction CBOR.");
  const transaction = CML.Transaction.from_cbor_hex(cbor);
  const body = transaction.body();
  const bodyHash = CML.hash_transaction(body);
  try {
    return { hash: bodyHash.to_hex(), requiredInputs: [
      ...inputReferences(body.inputs()), ...inputReferences(body.collateral_inputs()),
    ], referenceInputs: inputReferences(body.reference_inputs()),
      consumedInputs: inputReferences(transaction.is_valid() ? body.inputs() : body.collateral_inputs()) };
  } finally { bodyHash.free(); body.free(); transaction.free(); }
}

export class Artifacts {
  readonly directory: string;
  readonly records: TransactionRecord[] = [];
  readonly savedAtOpen = new Set<string>();
  manifest?: RunManifest;
  #redact: (text: string) => string;
  constructor(root: string, network: Network, redact = (text: string) => text, existing?: string) {
    this.directory = existing ? resolve(existing) : join(root, network, `${new Date().toISOString().replaceAll(":", "-")}-${randomUUID()}`);
    this.#redact = redact;
    if (!existing) mkdirSync(this.directory, { recursive: true });
  }
  static resume(directory: string, redact = (text: string) => text): Artifacts {
    let raw: unknown;
    try { raw = JSON.parse(readFileSync(join(directory, "manifest.json"), "utf8")); }
    catch { throw new Error("Missing or corrupt manifest.json."); }
    assert(raw && typeof raw === "object", "Invalid manifest.json.");
    const manifest = raw as RunManifest;
    assert.equal(manifest.version, 4, "Unsupported manifest version.");
    assert(["Mainnet", "Preprod", "Preview"].includes(manifest.network), "Resume requires a live-network run.");
    assert(typeof manifest.walletAddress === "string" && /^[0-9a-f]{56}$/.test(manifest.paymentKeyHash), "Invalid manifest wallet.");
    assert(Array.isArray(manifest.selection) && manifest.selection.length > 0 && manifest.scripts && manifest.setup && manifest.shared && manifest.cases && Array.isArray(manifest.transactions) && manifest.reports && manifest.resources && manifest.cleanup && Array.isArray(manifest.cleanup.transactions),
      "Invalid manifest structure.");
    for (const checkpoint of Object.values(manifest.cases)) {
      if (checkpoint.collateralInputLovelace !== undefined) checkpoint.collateralInputLovelace = BigInt(checkpoint.collateralInputLovelace);
    }
    for (const [key, resource] of Object.entries(manifest.resources)) {
      assert.equal(key, `${resource.output.txHash}#${resource.output.outputIndex}`, "Invalid resource reference.");
      resource.output.assets = Object.fromEntries(Object.entries(resource.output.assets).map(([unit, quantity]) => [unit, BigInt(quantity)]));
      assert(typeof resource.createdBy === "string" && typeof resource.confirmed === "boolean" &&
        (["immediate", "cleanup", "preserve"].includes(resource.release as string) || Array.isArray(resource.release)), "Invalid resource lifecycle.");
    }
    assert(["running", "passed", "stopped"].includes(manifest.status), "Invalid manifest status.");
    const names = new Set<string>();
    for (const builtin of manifest.selection) {
      assert(typeof builtin.name === "string" && Array.isArray(builtin.cases) && builtin.cases.length > 0, "Invalid manifest selection.");
      assert(!names.has(builtin.name), "Duplicate saved builtin.");
      names.add(builtin.name);
      const signature = `${builtin.name}(${Array(builtin.arity).fill("ByteArray").join(", ")}) -> ${builtin.returnType}`;
      const cases = builtin.cases.map((testCase) => `${builtin.name}/${testCase.name}|${testCase.outcome}|${testCase.arguments}`);
      assert.deepEqual(parseBuiltins([signature], cases), [builtin], "Invalid saved builtin cases.");
      const scripts = manifest.scripts[builtin.name];
      assert(scripts && scripts.builtin.name === builtin.name && scripts.networkTag === (manifest.network === "Mainnet" ? 1 : 0), "Invalid saved scripts.");
      assert.deepEqual(scripts.builtin, builtin, "Saved scripts do not match selected cases.");
      for (const name of ["withdrawal", "parameters", "mint"] as const) {
        assert(scripts[name]?.type === "PlutusV3" && scripts.hashes[name] === validatorToScriptHash(scripts[name]), `Invalid saved ${name} script hash.`);
      }
    }
    const ids = new Set<string>();
    for (const record of manifest.transactions) {
      assert(/^[a-z0-9_-]+(?:\/[a-z0-9_-]+){0,2}$/.test(record.scope) && /^[a-z0-9-]+$/.test(record.name), "Invalid saved transaction path.");
      assert(typeof record.id === "string" && record.id === `${record.scope}/${record.name}` && !ids.has(record.id), "Invalid or duplicate transaction step ID.");
      ids.add(record.id);
      const info = transactionInfo(record.cbor);
      assert.equal(record.hash, info.hash, `Saved transaction hash mismatch: ${record.id}.`);
      assert.deepEqual(record.requiredInputs, info.requiredInputs, `Saved transaction inputs mismatch: ${record.id}.`);
      assert.deepEqual(record.consumedInputs, info.consumedInputs, `Saved transaction consumption mismatch: ${record.id}.`);
      assert.deepEqual(record.referenceInputs, info.referenceInputs, `Saved transaction references mismatch: ${record.id}.`);
      assert(record.effects && Array.isArray(record.requiredInputs) &&
        ["signed", "submitting", "submitted", "confirmed", "stopped"].includes(record.status), "Invalid transaction record.");
    }
    const caseScopes = new Map<string, { mode: ArgumentMode; arity: number; arguments: string }>(manifest.selection.flatMap((builtin) => builtin.cases.flatMap((testCase) =>
      ARGUMENT_MODES.map((mode) => [`${builtin.name}/${testCase.name}/${mode}`, { mode, arity: builtin.arity, arguments: testCase.arguments }] as const))));
    for (const [scope, checkpoint] of Object.entries(manifest.cases)) {
      const selection = caseScopes.get(scope);
      assert(selection && checkpoint.mode === selection.mode, "Invalid saved case mode or path.");
      if (checkpoint.argumentReferences) {
        assert(Array.isArray(checkpoint.argumentReferences) && checkpoint.argumentIndexes?.length === checkpoint.argumentReferences.length
          && typeof checkpoint.redeemer === "string", "Invalid saved argument checkpoint.");
        assert.equal(new Set(checkpoint.argumentReferences.map((ref) => `${ref.txHash}#${ref.outputIndex}`)).size,
          checkpoint.argumentReferences.length, "Duplicate saved argument references.");
        assert.equal(checkpoint.argumentReferences.length, checkpoint.mode === "referenced" ? selection.arity : 0,
          "Saved argument reference count changed.");
        assert(checkpoint.argumentIndexes!.every((index) => Number.isSafeInteger(index) && index >= 0 && index <= selection.arity)
          && new Set(checkpoint.argumentIndexes).size === checkpoint.argumentIndexes!.length, "Invalid saved argument indexes.");
        assert.equal(checkpoint.resolvedArguments, Data.to(Data.from(selection.arguments)), "Saved resolved arguments changed.");
        assert.equal(checkpoint.redeemer, Data.to(checkpoint.mode === "direct"
          ? new Constr(0, [Data.from(selection.arguments)]) : new Constr(1, [checkpoint.argumentIndexes!.map(BigInt)])),
          "Saved builtin redeemer changed.");
      }
    }
    for (const scope of Object.keys(manifest.reports))
      assert(scope === "" || /^[a-z0-9_-]+(?:\/[a-z0-9_-]+){0,2}$/.test(scope), "Invalid saved report path.");
    const artifacts = new Artifacts("", manifest.network, redact, directory);
    artifacts.manifest = manifest;
    artifacts.records.push(...manifest.transactions);
    for (const record of artifacts.records) artifacts.savedAtOpen.add(record.id);
    manifest.transactions = artifacts.records;
    return artifacts;
  }
  initialize(network: Network, walletAddress: string, paymentKeyHash: string, selection: Builtin[], scripts: Validators[]) {
    assert(!this.manifest, "Manifest already initialized.");
    this.manifest = {
      version: 4, network, walletAddress, paymentKeyHash, status: "running", selection,
      scripts: Object.fromEntries(scripts.map((item) => [item.builtin.name, {
        ...item, hashes: { withdrawal: validatorToScriptHash(item.withdrawal),
          parameters: validatorToScriptHash(item.parameters), mint: validatorToScriptHash(item.mint) },
      }])),
      resources: {}, cleanup: { started: false, complete: false, transactions: [] },
      setup: {}, shared: {}, cases: {}, transactions: this.records, reports: {},
    };
    this.saveManifest();
  }
  saveManifest() {
    if (this.manifest) this.write("manifest.json", this.manifest);
  }
  setup(name: string, changes: SetupCheckpoint) {
    assert(this.manifest, "Missing manifest.");
    this.manifest.setup[name] = { ...this.manifest.setup[name], ...changes };
    this.saveManifest();
  }
  shared(changes: SharedSetupCheckpoint) {
    assert(this.manifest, "Missing manifest.");
    this.manifest.shared = { ...this.manifest.shared, ...changes };
    this.saveManifest();
  }
  case(scope: string, changes: CaseCheckpoint) {
    assert(this.manifest, "Missing manifest.");
    this.manifest.cases[scope] = { ...this.manifest.cases[scope], ...changes };
    this.saveManifest();
  }
  write(path: string, value: unknown) {
    const target = join(this.directory, path);
    mkdirSync(join(target, ".."), { recursive: true });
    const json = JSON.stringify(value, (_, v: unknown) => typeof v === "bigint" ? v.toString()
      : typeof v === "string" ? this.#redact(v) : v, 2);
    writeFileSync(`${target}.tmp`, `${json}\n`);
    renameSync(`${target}.tmp`, target);
  }
  report(scope: string, changes: Record<string, unknown>) {
    const path = join(scope, "report.json");
    const previous = this.manifest?.reports[scope] ?? (existsSync(join(this.directory, path)) ? JSON.parse(readFileSync(join(this.directory, path), "utf8")) : {});
    const report = { ...previous, ...changes };
    if (changes.status && changes.status !== "stopped") delete report.error;
    if (this.manifest) { this.manifest.reports[scope] = report; this.saveManifest(); }
    this.write(path, report);
  }
  find(scope: string, name: string) { return this.records.find((record) => record.id === `${scope}/${name}`); }
  signed(scope: string, name: string, cbor: string, hash: string, effects: Effects = {}) {
    const existing = this.find(scope, name);
    if (existing) {
      assert.equal(existing.cbor, cbor, `Saved bytes changed for ${existing.id}.`);
      assert.equal(existing.hash, hash, `Saved hash changed for ${existing.id}.`);
      return existing;
    }
    const info = transactionInfo(cbor);
    assert.equal(info.hash, hash, "Transaction hash does not match signed CBOR.");
    const record: TransactionRecord = { id: `${scope}/${name}`, scope, name, cbor, hash, effects,
      requiredInputs: info.requiredInputs, referenceInputs: info.referenceInputs, consumedInputs: info.consumedInputs,
      status: "signed", signedAt: new Date().toISOString() };
    this.records.push(record);
    this.flush(record);
    return record;
  }
  signedPair(scope: string, first: { name: string; cbor: string; hash: string; effects: Effects }, second: { name: string; cbor: string; hash: string; effects: Effects }) {
    assert(!this.find(scope, first.name) && !this.find(scope, second.name), "Funding pair already saved.");
    for (const entry of [first, second]) {
      const info = transactionInfo(entry.cbor);
      assert.equal(info.hash, entry.hash);
      this.records.push({ id: `${scope}/${entry.name}`, scope, ...entry, requiredInputs: info.requiredInputs,
        referenceInputs: info.referenceInputs, consumedInputs: info.consumedInputs,
        status: "signed", signedAt: new Date().toISOString() });
    }
    this.saveManifest();
    this.renderTransactions();
  }
  flush(_record: TransactionRecord) {
    this.saveManifest();
    this.renderTransactions();
  }
  renderTransactions() {
    const scopes = new Set(["", ...this.records.map((record) => record.scope)]);
    for (const scope of scopes) {
      const records = scope ? this.records.filter((r) => r.scope === scope) : this.records;
      this.write(join(scope, "transactions.json"), records.map(({ cbor }) => ({ cbor })));
      this.write(join(scope, "transaction-status.json"), records.map(({ cbor: _, ...status }) => status));
      for (const record of records) {
        if (scope !== record.scope) continue;
        writeFileSync(join(this.directory, scope, `${record.name}.cbor`), `${record.cbor}\n`);
        writeFileSync(join(this.directory, scope, `${record.name}.hash`), `${record.hash}\n`);
      }
    }
  }
  renderAll() {
    for (const [scope, report] of Object.entries(this.manifest?.reports ?? {})) this.write(join(scope, "report.json"), report);
    this.renderTransactions();
  }
}

export function restoreProtocol(raw: ProtocolParameters): ProtocolParameters {
  return { ...raw, keyDeposit: BigInt(raw.keyDeposit), poolDeposit: BigInt(raw.poolDeposit),
    drepDeposit: BigInt(raw.drepDeposit), govActionDeposit: BigInt(raw.govActionDeposit),
    maxTxExMem: BigInt(raw.maxTxExMem), maxTxExSteps: BigInt(raw.maxTxExSteps),
    coinsPerUtxoByte: BigInt(raw.coinsPerUtxoByte) };
}

export function validateResumeIdentity(manifest: RunManifest, walletAddress: string, explicitNetwork?: string) {
  if (explicitNetwork && explicitNetwork !== manifest.network) throw new Error("NETWORK conflicts with the saved run network.");
  assert.equal(walletAddress, manifest.walletAddress, "Wallet does not match the saved run.");
  assert.equal(getAddressDetails(walletAddress).paymentCredential?.hash, manifest.paymentKeyHash,
    "Wallet key does not match the saved run.");
}
