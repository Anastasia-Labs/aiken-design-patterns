import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import {
  CML, Lucid, coreToTxOutput, fromHex, getAddressDetails, validatorToScriptHash,
  type EvalRedeemer, type EvaluatorAdapter, type LucidEvolution, type OutRef, type ProtocolParameters, type UTxO, type Wallet,
} from "@lucid-evolution/lucid";
import { CardanoInfo, Emulator, Utxo, Value, evaluator } from "scalus";
import { LiveProvider } from "./live-provider.ts";
import { ScalusProvider, REDEEMER_TAGS, toScalusUtxo } from "./scalus-provider.ts";
import { BLOCKFROST_URLS, type Network, type NetworkConfig } from "./network.ts";
import type { Artifacts, CleanupCheckpoint, Resource } from "./artifacts.ts";
import { inputReferences } from "./transactions.ts";

export function testKey(seed: number) {
  const privateKey = CML.PrivateKey.from_normal_bytes(new Uint8Array(32).fill(seed));
  const publicKey = privateKey.to_public();
  const hash = publicKey.hash();
  try { return { key: privateKey.to_bech32(), hash: hash.to_hex() }; }
  finally { hash.free(); publicKey.free(); privateKey.free(); }
}
export const referenceKey = (ref: OutRef) => `${ref.txHash}#${ref.outputIndex}`;
export type Runtime = {
  network: Network; provider: ScalusProvider | LiveProvider; emulator?: Emulator;
  lucid: LucidEvolution; wallet: Wallet; walletAddress: string; referenceAddress: string;
  info: CardanoInfo; slotConfig: CardanoInfo["slotConfig"]; parameters: ProtocolParameters;
  evaluationOptions: { plutusVersion: "PlutusV3"; protocolMajorVersion: number; costModel: number[]; maxBudget: { memory: bigint; steps: bigint } };
  localEvaluator: EvaluatorAdapter;
  signers: { hash: string; key?: string }[]; threshold: number; reserved: Set<string>;
  resources: Record<string, Resource>; completedScopes: Set<string>; referenceUses: Map<string, string[]>;
  proofBundle?: UTxO; cleanup: CleanupCheckpoint;
  signal: AbortSignal; artifacts?: Artifacts; scope: string;
  now: () => number; sleep: (ms: number) => Promise<void>; confirmationTimeout: number;
};

export function localEvaluator(parameters: ProtocolParameters): EvaluatorAdapter {
  return { name: "scalus", async evaluate({ tx, additionalUTxOs, context }): Promise<EvalRedeemer[]> {
    return evaluator.evaluateTx(fromHex(tx), additionalUTxOs.map(toScalusUtxo), context.slotConfig,
      parameters.costModels, parameters.protocolMajorVersion!,
      { memory: parameters.maxTxExMem, steps: parameters.maxTxExSteps }).map((result) => ({
        redeemer_tag: REDEEMER_TAGS[result.tag], redeemer_index: result.index,
        ex_units: { mem: Number(result.budget.memory), steps: Number(result.budget.steps) },
      }));
  } };
}

function scriptOptions(parameters: ProtocolParameters) {
  return { plutusVersion: "PlutusV3" as const, protocolMajorVersion: parameters.protocolMajorVersion!,
    costModel: parameters.costModels.PlutusV3,
    maxBudget: { memory: parameters.maxTxExMem, steps: parameters.maxTxExSteps } };
}

function assertParameters(parameters: ProtocolParameters) {
  assert(parameters.protocolMajorVersion && parameters.costModels.PlutusV3?.length &&
    parameters.maxTxExMem > 0n && parameters.maxTxExSteps > 0n,
  "Incomplete Plutus V3 protocol parameters.");
}

export async function createRuntime(config: NetworkConfig, signal = new AbortController().signal): Promise<Runtime> {
  const info = config.network === "Mainnet" ? CardanoInfo.mainnet() : config.network === "Preprod" ? CardanoInfo.preprod() : CardanoInfo.preview();
  const emulator = config.network === "Custom" ? Emulator.create(info, { slot: 1_000_000 }) : undefined;
  const provider = config.network === "Custom" ? new ScalusProvider(emulator!) : new LiveProvider(BLOCKFROST_URLS[config.network], config.apiKey);
  const parameters = await provider.getProtocolParameters();
  assertParameters(parameters);
  const evaluation = localEvaluator(parameters);
  const lucid = await Lucid(provider, config.network, { slotConfig: info.slotConfig, presetProtocolParameters: parameters, evaluator: evaluation });
  if (config.network === "Custom") lucid.selectWallet.fromPrivateKey(testKey(1).key);
  else lucid.selectWallet.fromSeed(config.seed, { accountIndex: 0, addressType: "Base" });
  const wallet = lucid.wallet();
  const walletAddress = await wallet.address();
  const payment = getAddressDetails(walletAddress).paymentCredential;
  assert(payment?.type === "Key");
  if (emulator) {
    emulator.addUtxo(new Utxo("00".repeat(32), 0, walletAddress, Value.ada(1000n)));
  }
  return {
    network: config.network, provider, ...(emulator ? { emulator } : {}), lucid, wallet, walletAddress,
    referenceAddress: walletAddress,
    info, slotConfig: info.slotConfig, parameters, evaluationOptions: scriptOptions(parameters), localEvaluator: evaluation,
    signers: emulator ? [testKey(1), testKey(3), testKey(4)] : [{ hash: payment.hash }], threshold: emulator ? 2 : 1,
    reserved: new Set(), resources: {}, completedScopes: new Set(), referenceUses: new Map(),
    cleanup: { started: false, complete: false, transactions: [] }, signal, scope: "", now: Date.now,
    sleep: (ms) => delay(ms, undefined, { signal }), confirmationTimeout: 600_000,
  };
}

export async function refreshProtocol(runtime: Runtime) {
  if (runtime.network === "Custom") return;
  const parameters = await runtime.provider.getProtocolParameters();
  assertParameters(parameters);
  runtime.parameters = parameters;
  runtime.evaluationOptions = scriptOptions(parameters);
  runtime.localEvaluator = localEvaluator(parameters);
  const lucid = await Lucid(runtime.provider, runtime.network, {
    slotConfig: runtime.slotConfig, presetProtocolParameters: parameters, evaluator: runtime.localEvaluator,
  });
  lucid.config().wallet = runtime.wallet;
  runtime.lucid = lucid;
}

export async function ordinaryFunding(runtime: Runtime) {
  return (await runtime.provider.getUtxos(runtime.walletAddress))
    .filter((u) => !runtime.reserved.has(referenceKey(u)) && !u.scriptRef && !u.datum && !u.datumHash && Object.keys(u.assets).length === 1)
    .sort((a, b) => a.assets.lovelace! === b.assets.lovelace! ? referenceKey(a).localeCompare(referenceKey(b)) : a.assets.lovelace! > b.assets.lovelace! ? -1 : 1);
}

export function resourceInventory(runtime: Runtime) {
  if (runtime.artifacts?.manifest) {
    runtime.resources = runtime.artifacts.manifest.resources;
    runtime.cleanup = runtime.artifacts.manifest.cleanup;
    for (const [scope, checkpoint] of Object.entries(runtime.artifacts.manifest.cases))
      if (checkpoint.stage === "completed") runtime.completedScopes.add(scope);
  }
  return runtime.resources;
}

export function releaseResources(runtime: Runtime) {
  for (const resource of Object.values(resourceInventory(runtime))) {
    const key = referenceKey(resource.output);
    const eligible = resource.release === "immediate" || (Array.isArray(resource.release)
      && resource.release.every((scope) => runtime.completedScopes.has(scope)));
    if (eligible && !resource.releasedBy) resource.releasedBy = runtime.scope;
    if (resource.consumedBy || eligible) runtime.reserved.delete(key);
    else runtime.reserved.add(key);
  }
  runtime.artifacts?.saveManifest();
}

export function completeCase(runtime: Runtime, scope = runtime.scope) {
  runtime.completedScopes.add(scope);
  if (runtime.artifacts?.manifest) runtime.artifacts.case(scope, { stage: "completed" });
  releaseResources(runtime);
}

export function recordResources(runtime: Runtime, name: string, cbor: string, hash: string, confirmed: boolean) {
  const inventory = resourceInventory(runtime);
  const transaction = CML.Transaction.from_cbor_hex(cbor);
  const body = transaction.body();
  const outputs = body.outputs();
  const inputs = inputReferences(transaction.is_valid() ? body.inputs() : body.collateral_inputs());
  const save = (output: UTxO, role: Resource["role"], release: Resource["release"]) => {
    const key = referenceKey(output);
    inventory[key] ??= { output, role, release, scope: runtime.scope, createdBy: hash, confirmed };
    if (confirmed) inventory[key]!.confirmed = true;
    if (role === "proof-bundle" && confirmed && !inventory[key]!.consumedBy) {
      runtime.proofBundle = output;
      if (runtime.artifacts?.manifest) runtime.artifacts.manifest.proofBundle = { txHash: hash, outputIndex: output.outputIndex };
    }
  };
  try {
    if (transaction.is_valid()) {
      for (let outputIndex = 0; outputIndex < outputs.len(); outputIndex++) {
        const raw = outputs.get(outputIndex);
        let output: UTxO;
        try { output = { txHash: hash, outputIndex, ...coreToTxOutput(raw) }; }
        finally { raw.free(); }
        if (output.scriptRef) {
          const uses = runtime.referenceUses.get(validatorToScriptHash(output.scriptRef));
          save(output, "reference", uses ?? "cleanup");
        } else if (output.address !== runtime.walletAddress) save(output, "parameters", "preserve");
        else if (Object.keys(output.assets).length > 1) save(output, "proof-bundle", "preserve");
        else if (name === "00-prepare-wallet" && outputIndex === 0) save(output, "nonce", "cleanup");
        else if (name === "00-prepare-wallet" && outputIndex === 1) save(output, "setup-collateral", "cleanup");
        else if (name === "03-funding" && outputIndex < 2)
          save(output, outputIndex === 0 ? "fee" : "withdrawal-collateral", [runtime.scope]);
        else if (name === "02-arguments" && output.datum) save(output, "argument", [runtime.scope]);
        else save(output, "ordinary", "immediate");
      }
    } else {
      const returned = body.collateral_return();
      assert(returned);
      try { save({ txHash: hash, outputIndex: outputs.len(), ...coreToTxOutput(returned) }, "collateral-return", [runtime.scope]); }
      finally { returned.free(); }
    }
    if (confirmed) for (const input of inputs) {
      const resource = inventory[referenceKey(input)];
      if (resource) {
        assert(!resource.consumedBy || resource.consumedBy === hash, `Resource ${referenceKey(input)} has conflicting consumers.`);
        resource.consumedBy = hash;
      }
    }
  } finally { outputs.free(); body.free(); transaction.free(); }
  releaseResources(runtime);
}

export async function restoreResources(runtime: Runtime) {
  resourceInventory(runtime);
  for (const record of runtime.artifacts?.records ?? []) {
    if (runtime.network === "Custom" && record.scope !== runtime.scope) continue;
    if ((await runtime.lucid.transactionStatus(record.hash)).status !== "confirmed") continue;
    const scope = runtime.scope;
    runtime.scope = record.scope;
    recordResources(runtime, record.name, record.cbor, record.hash, true);
    runtime.scope = scope;
  }
  const proof = Object.values(runtime.resources).filter((resource) => resource.role === "proof-bundle" && resource.confirmed && !resource.consumedBy);
  assert(proof.length <= 1, "Multiple current proof bundles in resource inventory.");
  if (proof[0]) runtime.proofBundle = proof[0].output;
  releaseResources(runtime);
}

export type Effects = { present?: OutRef[]; absent?: OutRef[]; addresses?: string[]; stakeRegistered?: string | string[] };

export async function submitTransaction(runtime: Runtime, name: string, cbor: string, effects: Effects = {}) {
  runtime.signal.throwIfAborted();
  const transaction = CML.Transaction.from_cbor_hex(cbor);
  const body = transaction.body();
  const bodyHash = CML.hash_transaction(body);
  const hash = bodyHash.to_hex();
  const valid = transaction.is_valid();
  bodyHash.free(); body.free(); transaction.free();
  const record = runtime.artifacts?.signed(runtime.scope, name, cbor, hash, effects);
  recordResources(runtime, name, cbor, hash, false);
  effects = record?.effects ?? effects;
  const update = () => { if (record) runtime.artifacts!.flush(record); };
  try {
    const inventory = resourceInventory(runtime);
    const required = record?.requiredInputs ?? transactionInputs(cbor);
    const unknown = required.filter((ref) => !inventory[referenceKey(ref)]);
    if (unknown.length) for (const output of await runtime.provider.getUtxosByOutRef(unknown))
      inventory[referenceKey(output)] = { output, role: "ordinary", scope: runtime.scope,
        createdBy: output.txHash, adopted: true, confirmed: true, release: "immediate" };
    runtime.artifacts?.saveManifest();
    const deadline = runtime.now() + runtime.confirmationTimeout;
    const initial = await runtime.lucid.transactionStatus(hash);
    if (initial.status === "failed") throw new Error(`Transaction ${hash} was rejected.`);
    if (initial.status === "confirmed") {
      await checkValidity(runtime, hash, valid);
      if (record) { record.includedAt ??= new Date().toISOString(); record.confirmation = initial.confirmation; update(); }
      await waitForEffects(runtime, hash, await remainingEffects(runtime, effects), deadline);
      recordResources(runtime, name, cbor, hash, true);
      if (record) { record.status = "confirmed"; record.confirmedAt ??= new Date().toISOString(); delete record.error; update(); }
      return hash;
    }
    if (initial.status === "not_found") {
      const inputs = record ? [...record.requiredInputs, ...record.referenceInputs] : transactionInputs(cbor);
      const current = await currentInputs(runtime, inputs);
      if (!inputs.every((input) => current.has(referenceKey(input)))) {
        const confirmation = await waitForInclusion(runtime, hash, deadline);
        if (record) { record.includedAt = new Date().toISOString(); record.confirmation = confirmation; update(); }
        await checkValidity(runtime, hash, valid);
        await waitForEffects(runtime, hash, await remainingEffects(runtime, effects), deadline);
        recordResources(runtime, name, cbor, hash, true);
        if (record) { record.status = "confirmed"; record.confirmedAt = new Date().toISOString(); delete record.error; update(); }
        return hash;
      }
      if (!record || !runtime.artifacts?.savedAtOpen.has(record.id))
        assert(cbor.length / 2 <= runtime.parameters.maxTxSize,
          `${name}: signed transaction is ${cbor.length / 2} bytes; maximum is ${runtime.parameters.maxTxSize}.`);
      if (record) { record.status = "submitting"; update(); }
      assert.equal(await runtime.provider.submitTx(cbor), hash);
      if (record) { record.status = "submitted"; record.submittedAt = new Date().toISOString(); update(); }
    }
    const confirmation = await waitForInclusion(runtime, hash, deadline);
    if (record) { record.includedAt = new Date().toISOString(); record.confirmation = confirmation; update(); }
    await checkValidity(runtime, hash, valid);
    await waitForEffects(runtime, hash, effects, deadline);
    recordResources(runtime, name, cbor, hash, true);
    if (record) { record.status = "confirmed"; record.confirmedAt = new Date().toISOString(); delete record.error; update(); }
    return hash;
  } catch (error) {
    if (record) { record.status = "stopped"; record.error = error instanceof Error ? error.message : "Transaction stopped."; update(); }
    throw error;
  }
}

function transactionInputs(cbor: string): OutRef[] {
  const tx = CML.Transaction.from_cbor_hex(cbor);
  const body = tx.body();
  try { return [...inputReferences(body.inputs()), ...inputReferences(body.collateral_inputs()),
    ...inputReferences(body.reference_inputs())]; }
  finally { body.free(); tx.free(); }
}

async function currentInputs(runtime: Runtime, refs: OutRef[]) {
  const current: UTxO[] = [];
  for (const address of new Set([runtime.walletAddress, runtime.referenceAddress]))
    current.push(...await runtime.provider.getUtxos(address));
  const known = new Set(current.map(referenceKey));
  const missing = refs.filter((ref) => !known.has(referenceKey(ref)));
  const confirmedHashes = new Set<string>();
  for (const hash of new Set(missing.map((ref) => ref.txHash))) {
    if ((await runtime.lucid.transactionStatus(hash)).status === "confirmed") confirmedHashes.add(hash);
  }
  const discoverable = missing.filter((ref) => confirmedHashes.has(ref.txHash));
  if (discoverable.length) current.push(...await runtime.provider.getUtxosByOutRef(discoverable));
  return new Set(current.map(referenceKey));
}

async function remainingEffects(runtime: Runtime, effects: Effects): Promise<Effects> {
  const consumed = new Set<string>();
  for (const record of runtime.artifacts?.records ?? []) {
    if (!effects.present?.some((ref) => record.consumedInputs.some((input) => referenceKey(input) === referenceKey(ref)))) continue;
    if ((await runtime.lucid.transactionStatus(record.hash)).status === "confirmed")
      for (const input of record.consumedInputs) consumed.add(referenceKey(input));
  }
  return { ...effects, present: (effects.present ?? []).filter((ref) => !consumed.has(referenceKey(ref))) };
}

async function waitForEffects(runtime: Runtime, hash: string, effects: Effects, deadline: number) {
  if (!effects.present?.length && !effects.absent?.length && !effects.stakeRegistered) return;
  while (true) {
    runtime.signal.throwIfAborted();
    if (runtime.now() >= deadline) throw new Error(`Confirmation timed out for ${hash}; check this hash before another run.`);
    const current: UTxO[] = [];
    for (const address of new Set(effects.addresses ?? [runtime.walletAddress])) current.push(...await runtime.provider.getUtxos(address));
    const present = new Set(current.map(referenceKey));
    const rewardAddresses = effects.stakeRegistered === undefined ? []
      : Array.isArray(effects.stakeRegistered) ? effects.stakeRegistered : [effects.stakeRegistered];
    const ready = (effects.present ?? []).every((ref) => present.has(referenceKey(ref)))
      && (effects.absent ?? []).every((ref) => !present.has(referenceKey(ref)))
      && (await Promise.all(rewardAddresses.map((address) => runtime.provider.getRewardAccount(address)))).every((account) => account.registered);
    if (ready) return;
    await runtime.sleep(Math.min(3_000, Math.max(1, deadline - runtime.now())));
  }
}

async function waitForInclusion(runtime: Runtime, hash: string, deadline: number) {
  try {
    return await runtime.lucid.awaitTxConfirmation(hash, {
      checkInterval: 3_000, timeout: Math.max(1, deadline - runtime.now()), signal: runtime.signal,
    });
  } catch (error) {
    if (error instanceof Error && /Timed out waiting/.test(error.message))
      throw new Error(`Confirmation timed out for ${hash}; check this hash before another run.`);
    throw error;
  }
}

export async function checkValidity(runtime: Runtime, hash: string, valid: boolean) {
  if (!(runtime.provider instanceof LiveProvider)) return;
  const response = await fetch(`${runtime.provider.url}/txs/${hash}`, {
    headers: { project_id: runtime.provider.projectId },
  });
  assert(response.ok, `Could not check confirmed transaction validity (HTTP ${response.status}).`);
  const observed = await response.json() as { valid_contract: boolean };
  assert.equal(observed.valid_contract, valid, "Confirmed script validity differs from submitted envelope.");
}
