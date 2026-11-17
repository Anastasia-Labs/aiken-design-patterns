import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import {
  CML, Lucid, coreToTxOutput, fromHex, getAddressDetails, validatorToScriptHash,
  type EvalRedeemer, type EvaluatorAdapter, type LucidEvolution, type OutRef, type ProtocolParameters, type UTxO, type Wallet,
} from "@lucid-evolution/lucid";
import { CardanoInfo, Emulator, Utxo, Value, evaluator } from "scalus";
import { LiveProvider, type TransactionObservation } from "./live-provider.ts";
import { ScalusProvider, REDEEMER_TAGS, toScalusUtxo } from "./scalus-provider.ts";
import { BLOCKFROST_URLS, type Network, type NetworkConfig } from "./network.ts";
import type { Artifacts, CleanupCheckpoint, Resource } from "./artifacts.ts";
import { inputReferences } from "./transactions.ts";
import { executeChain, prepareTransaction, makeChain } from "./case-chain.ts";

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
  snapshot?: Map<string, UTxO>; reconciledArtifacts?: Artifacts; observations: Map<string, TransactionObservation>;
  recoveryScans: number;
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
  const provider = config.network === "Custom" ? new ScalusProvider(emulator!) : new LiveProvider(BLOCKFROST_URLS[config.network], config.apiKey, signal);
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
    observations: new Map(), recoveryScans: 0, reserved: new Set(), resources: {}, completedScopes: new Set(), referenceUses: new Map(),
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
  return (runtime.snapshot ? [...runtime.snapshot.values()].filter((u) => u.address === runtime.walletAddress) : await runtime.provider.getUtxos(runtime.walletAddress))
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
}

export function completeCase(runtime: Runtime, scope = runtime.scope) {
  const complete = () => {
    runtime.completedScopes.add(scope);
    if (runtime.artifacts?.manifest) runtime.artifacts.case(scope, { stage: "completed" });
    releaseResources(runtime);
    runtime.artifacts?.saveManifest();
  };
  if (runtime.artifacts) runtime.artifacts.batch(complete); else complete();
  runtime.artifacts?.renderTransactions();
}

export function recordResources(runtime: Runtime, name: string, cbor: string, hash: string, confirmed: boolean) {
  const inventory = resourceInventory(runtime);
  const transaction = CML.Transaction.from_cbor_hex(cbor);
  const body = transaction.body();
  const outputs = body.outputs();
  const inputs = inputReferences(transaction.is_valid() ? body.inputs() : body.collateral_inputs());
  const save = (output: UTxO, role: Resource["role"], release: Resource["release"]) => {
    const key = referenceKey(output);
    if (runtime.provider instanceof LiveProvider) runtime.provider.remember([output]);
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

export async function observeTransaction(runtime: Runtime, hash: string): Promise<TransactionObservation> {
  runtime.signal.throwIfAborted();
  return runtime.provider instanceof LiveProvider
    ? runtime.provider.observe(hash, { signal: runtime.signal }) : runtime.provider.getTransactionStatus(hash);
}

export function assertValidity(observation: TransactionObservation, valid: boolean) {
  assert.equal(observation.status, "confirmed", "Transaction is not confirmed.");
  if (observation.valid !== undefined)
    assert.equal(observation.valid, valid, "Confirmed script validity differs from submitted envelope.");
}

export async function takeSnapshot(runtime: Runtime, addresses: string[] = []) {
  const current = (await Promise.all([...new Set([runtime.walletAddress, runtime.referenceAddress, ...addresses])]
    .map((address) => runtime.provider.getUtxos(address)))).flat();
  return new Map(current.map((output) => [referenceKey(output), output]));
}

export async function restoreResources(runtime: Runtime) {
  resourceInventory(runtime);
  const artifacts = runtime.artifacts;
  if (!artifacts || runtime.reconciledArtifacts === artifacts) return;
  runtime.reconciledArtifacts = artifacts;
  // Fresh cases do not perform recovery scans. Reopening reconciles the saved journal once.
  if (artifacts.savedAtOpen.size) {
    runtime.recoveryScans++;
    for (const record of artifacts.records) {
      if (!artifacts.savedAtOpen.has(record.id)) continue;
      const observation = await observeTransaction(runtime, record.hash);
      runtime.observations.set(record.hash, observation);
      if (observation.status !== "confirmed") continue;
      const transaction = prepareTransaction(record.name, record.cbor, record.effects);
      assertValidity(observation, transaction.valid);
      const scope = runtime.scope;
      runtime.scope = record.scope;
      recordResources(runtime, record.name, record.cbor, record.hash, true);
      runtime.scope = scope;
    }
    artifacts.saveManifest();
  }
  const proofs = Object.values(runtime.resources).filter((resource) => resource.role === "proof-bundle" && resource.confirmed && !resource.consumedBy);
  assert(proofs.length <= 1, "Multiple current proof bundles in resource inventory.");
  if (proofs[0]) runtime.proofBundle = proofs[0].output;
  releaseResources(runtime);
}

export type Effects = { present?: OutRef[]; absent?: OutRef[]; addresses?: string[]; stakeRegistered?: string | string[] };

// Setup and cleanup use the same broadcast/confirmation machinery for one transaction.
export async function submitTransaction(runtime: Runtime, name: string, cbor: string, effects: Effects = {}) {
  const saved = runtime.artifacts?.find(runtime.scope, name);
  const transaction = prepareTransaction(name, cbor, saved?.effects ?? effects);
  const chain = makeChain(runtime.scope, runtime.parameters, [transaction]);
  await executeChain(runtime, chain, false);
  return transaction.hash;
}
