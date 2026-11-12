import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { CML, getAddressDetails, validatorToScriptHash, type OutRef, type ProtocolParameters } from "@lucid-evolution/lucid";
import type { Validators } from "./blueprint.ts";
import { parseBuiltins, type Builtin } from "./builtins.ts";
import type { Network } from "./network.ts";
import type { Effects } from "./runtime.ts";
import { inputReferences } from "./transactions.ts";

export type TransactionRecord = {
  id: string; scope: string; name: string; hash: string; cbor: string; effects: Effects;
  requiredInputs: OutRef[]; referenceInputs: OutRef[];
  status: "signed" | "submitting" | "submitted" | "confirmed" | "stopped";
  signedAt: string; submittedAt?: string; includedAt?: string; confirmedAt?: string;
  confirmation?: unknown; error?: string;
};
export type SavedScripts = { networkTag: 0 | 1; builtin: Builtin; withdrawal: Validators["withdrawal"];
  parameters: Validators["parameters"]; mint: Validators["mint"]; hashes: { withdrawal: string; parameters: string; mint: string } };
export type SetupCheckpoint = { nonce?: OutRef; stakeAlreadyRegistered?: boolean; ready?: boolean; protocol?: ProtocolParameters };
export type CaseCheckpoint = { protocol?: ProtocolParameters; feePasses?: number; stage?: string };
export type RunManifest = {
  version: 1; network: Network; walletAddress: string; paymentKeyHash: string; status: "running" | "passed" | "stopped";
  selection: Builtin[]; scripts: Record<string, SavedScripts>; setup: Record<string, SetupCheckpoint>;
  cases: Record<string, CaseCheckpoint>; transactions: TransactionRecord[]; reports: Record<string, Record<string, unknown>>;
};

function transactionInfo(cbor: string) {
  assert(/^(?:[0-9a-f]{2})+$/i.test(cbor), "Invalid saved transaction CBOR.");
  const transaction = CML.Transaction.from_cbor_hex(cbor);
  const body = transaction.body();
  const bodyHash = CML.hash_transaction(body);
  try {
    return { hash: bodyHash.to_hex(), requiredInputs: [
      ...inputReferences(body.inputs()), ...inputReferences(body.collateral_inputs()),
    ], referenceInputs: inputReferences(body.reference_inputs()) };
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
    assert.equal(manifest.version, 1, "Unsupported manifest version.");
    assert(["Mainnet", "Preprod", "Preview"].includes(manifest.network), "Resume requires a live-network run.");
    assert(typeof manifest.walletAddress === "string" && /^[0-9a-f]{56}$/.test(manifest.paymentKeyHash), "Invalid manifest wallet.");
    assert(Array.isArray(manifest.selection) && manifest.selection.length > 0 && manifest.scripts && manifest.setup && manifest.cases && Array.isArray(manifest.transactions) && manifest.reports,
      "Invalid manifest structure.");
    assert(["running", "passed", "stopped"].includes(manifest.status), "Invalid manifest status.");
    const names = new Set<string>();
    for (const builtin of manifest.selection) {
      assert(typeof builtin.name === "string" && Array.isArray(builtin.cases) && builtin.cases.length > 0, "Invalid manifest selection.");
      assert(!names.has(builtin.name), "Duplicate saved builtin.");
      names.add(builtin.name);
      const signature = `${builtin.name}(${Array(builtin.arity).fill("ByteArray").join(", ")}) -> ${builtin.returnType}`;
      const cases = builtin.cases.map((testCase) => `${builtin.name}/${testCase.name}|${testCase.outcome}|${testCase.redeemer}`);
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
      assert(/^[a-z0-9_-]+(?:\/[a-z0-9_-]+)?$/.test(record.scope) && /^[a-z0-9-]+$/.test(record.name), "Invalid saved transaction path.");
      assert(typeof record.id === "string" && record.id === `${record.scope}/${record.name}` && !ids.has(record.id), "Invalid or duplicate transaction step ID.");
      ids.add(record.id);
      const info = transactionInfo(record.cbor);
      assert.equal(record.hash, info.hash, `Saved transaction hash mismatch: ${record.id}.`);
      assert.deepEqual(record.requiredInputs, info.requiredInputs, `Saved transaction inputs mismatch: ${record.id}.`);
      assert.deepEqual(record.referenceInputs, info.referenceInputs, `Saved transaction references mismatch: ${record.id}.`);
      assert(record.effects && Array.isArray(record.requiredInputs) &&
        ["signed", "submitting", "submitted", "confirmed", "stopped"].includes(record.status), "Invalid transaction record.");
    }
    for (const scope of Object.keys(manifest.reports))
      assert(scope === "" || /^[a-z0-9_-]+(?:\/[a-z0-9_-]+)?$/.test(scope), "Invalid saved report path.");
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
      version: 1, network, walletAddress, paymentKeyHash, status: "running", selection,
      scripts: Object.fromEntries(scripts.map((item) => [item.builtin.name, {
        ...item, hashes: { withdrawal: validatorToScriptHash(item.withdrawal),
          parameters: validatorToScriptHash(item.parameters), mint: validatorToScriptHash(item.mint) },
      }])),
      setup: {}, cases: {}, transactions: this.records, reports: {},
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
      requiredInputs: info.requiredInputs, referenceInputs: info.referenceInputs,
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
        referenceInputs: info.referenceInputs,
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
