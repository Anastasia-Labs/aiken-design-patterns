import assert from "node:assert/strict";
import { Cbor, CborArray, CborMap, CborUInt } from "@harmoniclabs/cbor";
import {
  CML, Constr, Data, Lucid, ScriptContextData, applyParamsToScript, coreToTxOutput,
  fromText, makeScriptContext, sortUTxOs, toHex, toUnit,
  validatorToAddress, validatorToRewardAddress, validatorToScriptHash,
  type EvaluatorAdapter, type OutRef, type Script, type TxSigned, type TxSignBuilder, type UTxO,
} from "@lucid-evolution/lucid";
import { evaluator } from "scalus";
import { restoreProtocol } from "./artifacts.ts";
import type { Validators } from "./blueprint.ts";
import { ARGUMENT_MODES, WITHDRAWAL_RESULTS, type ArgumentMode, type BuiltinCase } from "./builtins.ts";
import { completeCase, createRuntime, localEvaluator, ordinaryFunding, referenceKey, refreshProtocol, releaseResources, resourceInventory, restoreResources, submitTransaction, takeSnapshot, type Effects, type Runtime } from "./runtime.ts";
import {
  completeWithMinimumCollateral, conservativeScriptFee, finalizeWithdrawal, inputReferences, minimumCollateral, minimumOutputAda,
  minimumFee, outRef, outRefData, signedSize, withKeyWitnesses, type Budget,
} from "./transactions.ts";

import { assertOutput, executeChain, makeChain, prepareTransaction, projectSnapshot, savedChain, type PreparedTransaction } from "./case-chain.ts";

const ADA = 1_000_000n;
const PARAMETERS_NAME = fromText("FAILURE_PARAMETERS");

export function parametersDatum({ memory, steps }: Budget): string {
  return Data.to(new Constr(0, [memory, steps]));
}

export function readParameters(input: UTxO): Budget {
  assert(input.datum && !input.datumHash, "Expected inline failure parameters.");
  const value = Data.from(input.datum);
  assert(value instanceof Constr && value.index === 0 && value.fields.length === 2);
  const [memory, steps] = value.fields;
  assert(typeof memory === "bigint" && typeof steps === "bigint");
  return { memory, steps };
}

type SignedView = Pick<TxSigned, "toCBOR" | "toHash" | "toTransaction" | "submit">;

function savedSigned(cbor: string): SignedView {
  const transaction = CML.Transaction.from_cbor_hex(cbor);
  const body = transaction.body();
  const hash = CML.hash_transaction(body);
  try {
    const txHash = hash.to_hex();
    return { toCBOR: () => cbor, toHash: () => txHash, toTransaction: () => CML.Transaction.from_cbor_hex(cbor),
      submit: async () => { throw new Error("Submit saved transactions through the run journal."); } };
  } finally { hash.free(); body.free(); transaction.free(); }
}

function invalidEnvelope(signed: SignedView): string {
  const transaction = CML.Transaction.from_cbor_hex(signed.toCBOR());
  if (!transaction.is_valid()) { transaction.free(); return signed.toCBOR(); }
  const body = transaction.body();
  const witnesses = transaction.witness_set();
  const invalid = CML.Transaction.new(body, witnesses, false);
  const invalidBody = invalid.body();
  const invalidWitnesses = invalid.witness_set();
  try {
    assert.equal(invalidBody.to_cbor_hex(), body.to_cbor_hex());
    assert.equal(invalidWitnesses.to_cbor_hex(), witnesses.to_cbor_hex());
    return invalid.to_cbor_hex();
  } finally {
    invalidWitnesses.free(); invalidBody.free(); invalid.free(); witnesses.free(); body.free(); transaction.free();
  }
}

function createdOutputs(signed: SignedView) {
  const transaction = CML.Transaction.from_cbor_hex(signed.toCBOR());
  const body = transaction.body();
  const outputs = body.outputs();
  try { return Array.from({ length: outputs.len() }, (_, outputIndex) => ({ txHash: signed.toHash(), outputIndex })); }
  finally { outputs.free(); body.free(); transaction.free(); }
}

function consumedInputs(signed: SignedView) {
  const transaction = CML.Transaction.from_cbor_hex(signed.toCBOR());
  const body = transaction.body();
  try { return inputReferences(body.inputs()); }
  finally { body.free(); transaction.free(); }
}

export type BuiltinSetup = {
  runtime: Runtime; scripts: Validators; walletAddress: string; referenceAddress: string;
  rewardAddress: string; withdrawalHash: string; policyId: string; parametersScript: Script;
  parametersPolicy: string; parametersAddress: string; parametersUnit: string; parametersInput: UTxO;
  nonce: OutRef; signers: Runtime["signers"]; threshold: number; references: UTxO[];
  withdrawalReference: UTxO; parametersReference: UTxO; mintReference: UTxO; mintCollateral: UTxO;
  transactions: Record<string, string>; deploymentHash: string; setupHash: string; registered: boolean;
};

type SetupReference = { kind: "reference"; hash: string; name: string; script: Script };
type SetupRegistration = { kind: "registration"; hash: string; rewardAddress: string; script: Script };
type SetupItem = SetupReference | SetupRegistration;

function transactionOutputs(signed: SignedView): UTxO[] {
  const transaction = CML.Transaction.from_cbor_hex(signed.toCBOR());
  const body = transaction.body();
  const outputs = body.outputs();
  try {
    return Array.from({ length: outputs.len() }, (_, outputIndex) => {
      const output = outputs.get(outputIndex);
      try { return { txHash: signed.toHash(), outputIndex, ...coreToTxOutput(output) }; }
      finally { output.free(); }
    });
  } finally { outputs.free(); body.free(); transaction.free(); }
}

export async function buildWithReclamation(
  runtime: Runtime,
  build: (reclaim: UTxO[], funding: UTxO[]) => Promise<TxSignBuilder>,
  final = false,
): Promise<TxSignBuilder> {
  releaseResources(runtime);
  const owned = Object.values(runtime.resources).filter((resource) => resource.confirmed && !resource.consumedBy);
  const snapshot = runtime.snapshot ?? await takeSnapshot(runtime, owned.map((resource) => resource.output.address));
  if (!runtime.snapshot) for (const { output } of owned)
    assert(snapshot.has(referenceKey(output)), `Run resource ${referenceKey(output)} was unexpectedly spent outside the journal.`);
  const resources = owned.filter((resource) => snapshot.has(referenceKey(resource.output))
    && resource.role !== "parameters" && resource.role !== "proof-bundle" && (final || resource.releasedBy !== undefined))
    .sort((a, b) => referenceKey(a.output).localeCompare(referenceKey(b.output)));
  const previous = runtime.snapshot;
  runtime.snapshot = snapshot;
  const ordinary = final ? [] : await ordinaryFunding(runtime);
  if (previous) runtime.snapshot = previous; else delete runtime.snapshot;
  let best: TxSignBuilder | undefined;
  let lastError: unknown;
  for (let count = 0; count <= resources.length; count++) {
    if (final && count === 0) continue;
    const reclaim = resources.slice(0, count).map(({ output }) => output);
    const selected = new Set(reclaim.map(referenceKey));
    const funding = ordinary.filter((input) => !selected.has(referenceKey(input)));
    runtime.wallet.overrideUTxOs([...reclaim, ...funding]);
    try {
      const candidate = await build(reclaim, funding);
      if (signedSize(candidate) > runtime.parameters.maxTxSize) {
        lastError = new Error("Reclamation transaction exceeds the signed transaction size limit.");
        break;
      }
      best = candidate;
    } catch (error) {
      lastError = error;
      if (best) break;
    } finally { runtime.wallet.clearUTxOOverride?.(); }
  }
  assert(best, `Insufficient ADA funding or no reclamation batch fits before funding submission: ${String(lastError)}`);
  return best;
}

async function signSelected(runtime: Runtime, completed: TxSignBuilder, inputs?: UTxO[]) {
  if (inputs || runtime.snapshot) runtime.wallet.overrideUTxOs(inputs ?? [...runtime.snapshot!.values()]);
  try {
    const signed = await completed.sign.withWallet().complete();
    assert(signed.toCBOR().length / 2 <= runtime.parameters.maxTxSize, "Final signed transaction exceeds maximum size.");
    return signed;
  } finally { runtime.wallet.clearUTxOOverride?.(); }
}

export async function cleanupRun(runtime: Runtime) {
  await restoreResources(runtime);
  const manifest = runtime.artifacts?.manifest;
  if (manifest) assert(manifest.selection.every((builtin) => builtin.cases.every((testCase) => ARGUMENT_MODES.every((mode) =>
    manifest.cases[`${builtin.name}/${testCase.name}/${mode}`]?.stage === "completed"))), "Final cleanup requires every scheduled execution to complete.");
  const scope = runtime.scope;
  runtime.scope = runtime.network === "Custom" ? scope : "cleanup";
  const checkpoint = runtime.cleanup;
  checkpoint.started = true;
  runtime.artifacts?.saveManifest();
  const transactions: Record<string, string> = {};
  let index = 0;
  while (true) {
    const name = `06-cleanup-${String(index).padStart(2, "0")}`;
    const saved = runtime.artifacts?.find(runtime.scope, name);
    if (saved) {
      transactions[name] = saved.cbor;
      await submitTransaction(runtime, name, saved.cbor, saved.effects);
      if (!checkpoint.transactions.includes(saved.hash)) checkpoint.transactions.push(saved.hash);
      index++;
      continue;
    }
    const remaining = Object.values(runtime.resources).filter((resource) => resource.confirmed && !resource.consumedBy
      && resource.role !== "parameters" && resource.role !== "proof-bundle");
    if (!remaining.length || (remaining.length === 1 && remaining[0]!.role === "ordinary")) break;
    const completed = await buildWithReclamation(runtime, (reclaim) => runtime.lucid.newTx().collectFrom(reclaim)
      .complete({ coinSelection: false, canonical: true }), true);
    const signed = await signSelected(runtime, completed);
    const effects = { present: createdOutputs(signed), absent: consumedInputs(signed), addresses: [runtime.walletAddress] };
    checkpoint.transactions.push(signed.toHash());
    runtime.artifacts?.signed(runtime.scope, name, signed.toCBOR(), signed.toHash(), effects);
    runtime.artifacts?.saveManifest();
    transactions[name] = signed.toCBOR();
    await submitTransaction(runtime, name, signed.toCBOR(), effects);
    index++;
  }
  const remaining = Object.values(runtime.resources).filter((resource) => resource.confirmed && !resource.consumedBy);
  assert(remaining.filter((resource) => resource.role === "ordinary").length <= 1);
  assert(remaining.every((resource) => ["ordinary", "parameters", "proof-bundle"].includes(resource.role)), "Cleanup left unreclaimed resources.");
  const actual = await runtime.provider.getUtxosByOutRef(remaining.map(({ output }) => outRef(output)));
  assert.equal(actual.length, remaining.length, "Final run outputs are unavailable.");
  for (const { output } of remaining) assert.deepEqual(actual.find((value) => referenceKey(value) === referenceKey(output))?.assets, output.assets);
  const ordinary = remaining.find((resource) => resource.role === "ordinary");
  const proof = remaining.find((resource) => resource.role === "proof-bundle");
  const parameters = remaining.find((resource) => resource.role === "parameters");
  if (ordinary) checkpoint.ordinary = outRef(ordinary.output);
  if (proof) checkpoint.proofBundle = outRef(proof.output);
  if (parameters) checkpoint.parameters = outRef(parameters.output);
  checkpoint.complete = true;
  runtime.artifacts?.saveManifest();
  runtime.artifacts?.report(runtime.scope, { cleanup: checkpoint, resources: runtime.resources });
  if (manifest) for (const caseScope of Object.keys(manifest.cases)) {
    runtime.artifacts!.report(caseScope, {
      finalOutputs: checkpoint,
      resourceLifecycle: Object.values(runtime.resources).filter((resource) => resource.scope === caseScope
        || (resource.role === "reference" && (resource.release === "cleanup"
          || (Array.isArray(resource.release) && resource.release.includes(caseScope)))))
        .map(({ output, role, release, releasedBy, consumedBy }) => ({ outRef: outRef(output), role, release, releasedBy, consumedBy })),
    });
  }
  runtime.scope = scope;
  return { checkpoint, transactions };
}

async function shareRuntimeProtocol(runtime: Runtime, parameters: Runtime["parameters"]) {
  runtime.parameters = parameters;
  runtime.localEvaluator = localEvaluator(parameters);
  runtime.evaluationOptions = {
    plutusVersion: "PlutusV3", protocolMajorVersion: parameters.protocolMajorVersion!,
    costModel: parameters.costModels.PlutusV3,
    maxBudget: { memory: parameters.maxTxExMem, steps: parameters.maxTxExSteps },
  };
  const lucid = await Lucid(runtime.provider, runtime.network, {
    slotConfig: runtime.slotConfig, presetProtocolParameters: parameters, evaluator: runtime.localEvaluator,
  });
  lucid.config().wallet = runtime.wallet;
  runtime.lucid = lucid;
}

function referenceItems(scripts: Validators[], parametersScript: Script): { items: SetupReference[]; byBuiltin: Map<string, { withdrawal: string; mint: string }> } {
  const references = new Map<string, SetupReference>();
  const add = (name: string, script: Script) => {
    const hash = validatorToScriptHash(script);
    const existing = references.get(hash);
    if (existing) assert.deepEqual(existing.script, script, "A reference script hash maps to different scripts.");
    else references.set(hash, { kind: "reference", hash, name, script });
    return hash;
  };
  add("parameters", parametersScript);
  const byBuiltin = new Map<string, { withdrawal: string; mint: string }>();
  for (const item of scripts) {
    const withdrawalHash = validatorToScriptHash(item.withdrawal);
    const parametersPolicy = validatorToScriptHash(parametersScript);
    const mintScript: Script = {
      ...item.mint,
      script: applyParamsToScript(item.mint.script, [withdrawalHash, parametersPolicy]),
    };
    byBuiltin.set(item.builtin.name, {
      withdrawal: add(`${item.builtin.name}-withdrawal`, item.withdrawal),
      mint: add(`${item.builtin.name}-mint`, mintScript),
    });
  }
  return { items: [...references.values()], byBuiltin };
}

export async function prepareRun(
  scripts: Validators[],
  runtime: Runtime,
  progress: (message: string) => void = () => {},
) {
  assert(scripts.length > 0);
  for (const item of scripts) assert.equal(item.networkTag, runtime.network === "Mainnet" ? 1 : 0);
  const { artifacts } = runtime;
  const checkpoint = artifacts?.manifest?.shared;
  const setupScope = runtime.network === "Custom" ? runtime.scope : "setup";
  runtime.scope = setupScope;
  await refreshProtocol(runtime);
  const parameters = checkpoint?.protocol ? restoreProtocol(checkpoint.protocol) : runtime.parameters;
  await shareRuntimeProtocol(runtime, parameters);
  const { lucid, provider, walletAddress, referenceAddress, signers, threshold, network } = runtime;
  const signerHashes = signers.map(({ hash }) => hash);
  if (checkpoint?.signers) assert.deepEqual(checkpoint.signers, signerHashes, "Saved parameters signers changed.");
  if (checkpoint?.threshold !== undefined) assert.equal(checkpoint.threshold, threshold, "Saved parameters threshold changed.");
  const budget = { memory: parameters.maxTxExMem, steps: parameters.maxTxExSteps };

  resourceInventory(runtime);
  await restoreResources(runtime);
  const savedSplit = artifacts?.find(setupScope, "00-prepare-wallet");
  const transactions: Record<string, string> = {};
  const maximumFee = conservativeScriptFee(parameters, scripts.map((item) => ({ ...item.mint,
    script: applyParamsToScript(item.mint.script, [validatorToScriptHash(item.withdrawal), "00".repeat(28)]),
  })));
  const collateralRequired = minimumCollateral(maximumFee, parameters.collateralPercentage)
    + minimumOutputAda(walletAddress, {}, parameters);
  const collateralValue = collateralRequired > 20n * ADA ? collateralRequired : 20n * ADA;
  let split: SignedView;
  if (savedSplit) split = savedSigned(savedSplit.cbor);
  else if (checkpoint?.nonce) throw new Error("Missing saved wallet preparation transaction.");
  else {
    progress("Creating dedicated bootstrap and bounded setup/proof collateral outputs.");
    const available = await ordinaryFunding(runtime);
    assert(available.length, "Fund the account-0 wallet with ADA before running.");
    const prepared = await lucid.newTx()
      .pay.ToAddress(walletAddress, { lovelace: 2n * ADA })
      .pay.ToAddress(walletAddress, { lovelace: collateralValue })
      .complete({ presetWalletInputs: available, canonical: true });
    split = await prepared.sign.withWallet().complete();
  }
  transactions["00-prepare-wallet"] = split.toCBOR();
  await submitTransaction(runtime, "00-prepare-wallet", split.toCBOR(), {
    present: createdOutputs(split), absent: consumedInputs(split), addresses: [walletAddress],
  });
  const splitOutputs = transactionOutputs(split);
  const nonce = outRef(splitOutputs[0]!);
  const nonceInput = (await provider.getUtxosByOutRef([nonce]))[0];
  const nonceValue = splitOutputs[0]!.assets.lovelace!;
  const mintCollateral = splitOutputs[1]!;
  if (!runtime.cleanup.started) assert((await provider.getUtxosByOutRef([mintCollateral])).length,
    "Saved setup collateral is no longer spendable.");
  runtime.reserved.add(referenceKey(nonce));
  runtime.reserved.add(referenceKey(mintCollateral));
  const bootstrapNonce = outRef(nonce);
  const parametersScript: Script = {
    ...scripts[0]!.parameters,
    script: applyParamsToScript(scripts[0]!.parameters.script, [outRefData(bootstrapNonce), signerHashes, BigInt(threshold)]),
  };
  for (const item of scripts.slice(1)) assert.deepEqual(item.parameters, scripts[0]!.parameters,
    "Selected builtins do not share the same parameters validator.");
  const parametersPolicy = validatorToScriptHash(parametersScript);
  const parametersAddress = validatorToAddress(network, parametersScript);
  const parametersUnit = toUnit(parametersPolicy, PARAMETERS_NAME);
  if (checkpoint?.parametersPolicy) assert.equal(checkpoint.parametersPolicy, parametersPolicy, "Saved parameters policy changed.");
  if (checkpoint?.parametersAddress) assert.equal(checkpoint.parametersAddress, parametersAddress, "Saved parameters address changed.");
  if (checkpoint?.parametersUnit) assert.equal(checkpoint.parametersUnit, parametersUnit, "Saved parameters unit changed.");
  if (artifacts?.manifest) artifacts.shared({
    nonce: bootstrapNonce, signers: signerHashes, threshold, protocol: parameters,
    parametersPolicy, parametersAddress, parametersUnit,
    mintCollateral: checkpoint?.mintCollateral ?? outRef(mintCollateral),
  });

  const { items: refsToCreate, byBuiltin } = referenceItems(scripts, parametersScript);
  for (const item of refsToCreate) {
    if (item.hash === parametersPolicy) continue;
    const uses = scripts.flatMap((compiled) => {
      const hashes = byBuiltin.get(compiled.builtin.name)!;
      return compiled.builtin.cases.flatMap((testCase) => ARGUMENT_MODES.flatMap((mode) =>
        item.hash === hashes.withdrawal || (item.hash === hashes.mint && testCase.outcome !== "success")
          ? [compiled.builtin.name + "/" + testCase.name + "/" + mode] : []));
    });
    runtime.referenceUses.set(item.hash, uses);
  }
  const refsByHash = new Map<string, UTxO>();
  const originByHash = new Map<string, string>();
  let parametersInputRef: OutRef | undefined = checkpoint?.parametersInput;
  let parametersReferenceRef: OutRef | undefined = checkpoint?.parametersReference;
  const setupHashes: string[] = [];

  const inspectSetupOutputs = (signed: SignedView) => {
    for (const output of transactionOutputs(signed)) {
      if (output.scriptRef) {
        const hash = validatorToScriptHash(output.scriptRef);
        refsByHash.set(hash, output);
        originByHash.set(hash, output.txHash);
        const resource = runtime.resources[referenceKey(output)];
        if (resource) resource.release = runtime.referenceUses.get(hash) ?? "cleanup";
      }
      if ((output.assets[parametersUnit] ?? 0n) === 1n) parametersInputRef = outRef(output);

    }
  };

  let batchIndex = 0;
  while (true) {
    const name = `${String(batchIndex + 1).padStart(2, "0")}-setup-${String(batchIndex).padStart(2, "0")}`;
    const saved = artifacts?.find(setupScope, name);
    if (!saved) break;
    const signed = savedSigned(saved.cbor);
    transactions[name] = saved.cbor;
    await submitTransaction(runtime, name, saved.cbor, saved.effects);
    inspectSetupOutputs(signed);
    setupHashes.push(saved.hash);
    batchIndex++;
  }

  const emitted = new Set(refsByHash.keys());
  const parametersReferenceHash = validatorToScriptHash(parametersScript);
  if (parametersReferenceRef) emitted.add(parametersReferenceHash);
  const stakeBefore = new Map<string, boolean>();
  const registrations: SetupRegistration[] = [];
  for (const item of scripts) {
    const rewardAddress = validatorToRewardAddress(network, item.withdrawal);
    const hash = validatorToScriptHash(item.withdrawal);
    const existing = stakeBefore.get(hash);
    const state = existing ?? (await provider.getRewardAccount(rewardAddress)).registered;
    stakeBefore.set(hash, state);
    if (!state && !registrations.some((entry) => entry.hash === hash))
      registrations.push({ kind: "registration", hash, rewardAddress, script: item.withdrawal });
    const old = artifacts?.manifest?.setup[item.builtin.name];
    if (artifacts?.manifest && old?.stakeAlreadyRegistered === undefined)
      artifacts.setup(item.builtin.name, { rewardAddress, stakeAlreadyRegistered: state });
  }

  const outputsSaved = artifacts?.records.filter((record) => record.scope === setupScope && /^\d+-setup-\d+$/.test(record.name)) ?? [];
  for (const record of outputsSaved) {
    const signed = savedSigned(record.cbor);
    inspectSetupOutputs(signed);
  }
  for (const item of refsToCreate) {
    if (emitted.has(item.hash)) continue;
    const existing = refsByHash.get(item.hash);
    if (existing) emitted.add(item.hash);
  }

  const pendingReferences = () => refsToCreate.filter((item) => !emitted.has(item.hash));
  const pendingRegistrations = async () => {
    const pending: SetupRegistration[] = [];
    for (const item of registrations) {
      if (!(await provider.getRewardAccount(item.rewardAddress)).registered) pending.push(item);
    }
    return pending;
  };

  while (!parametersInputRef || pendingReferences().length || (await pendingRegistrations()).length) {
    progress(`Packing shared setup batch ${batchIndex + 1} by signed transaction size.`);
    const bootstrap = !parametersInputRef;
    if (bootstrap) assert.equal(batchIndex, 0, "The shared bootstrap must be the first setup transaction.");
    const currentReferences = pendingReferences();
    const currentRegistrations = await pendingRegistrations();
    const candidates: SetupItem[] = [...currentReferences, ...currentRegistrations];
    runtime.snapshot = await takeSnapshot(runtime);
    let best: { items: SetupItem[]; completed: TxSignBuilder } | undefined;
    const packed: SetupItem[] = [];
    for (const item of candidates) {
      const tryItems = [...packed, item];
      try {
        const candidate = await buildSetupBatch({
          items: tryItems, bootstrap, nonce: nonceInput, nonceValue, parametersScript,
          parametersAddress, parametersUnit, budget, mintCollateral, runtime,
        });
        const bytes = signedSize(candidate);
        if (bytes > parameters.maxTxSize) continue;
        best = { items: tryItems, completed: candidate };
        packed.push(item);
      } catch (error) {
        if (best) break;
        throw error;
      }
    }
    assert(best, "No shared setup batch fits within the network's maximum transaction size.");
    const name = `${String(batchIndex + 1).padStart(2, "0")}-setup-${String(batchIndex).padStart(2, "0")}`;
    const signed = await signSelected(runtime, best.completed);
    const effects: Effects = {
      present: createdOutputs(signed), absent: consumedInputs(signed), addresses: [walletAddress, parametersAddress],
    };
    const includedRegistrations = best.items.filter((item): item is SetupRegistration => item.kind === "registration");
    if (includedRegistrations.length) effects.stakeRegistered = includedRegistrations.map(({ rewardAddress }) => rewardAddress);
    const record = artifacts?.signed(setupScope, name, signed.toCBOR(), signed.toHash(), effects);
    transactions[name] = signed.toCBOR();
    await submitTransaction(runtime, name, signed.toCBOR(), effects);
    const savedView = record ? savedSigned(record.cbor) : signed;
    inspectSetupOutputs(savedView);
    for (const item of best.items) if (item.kind === "reference") emitted.add(item.hash);
    setupHashes.push(signed.toHash());
    batchIndex++;
    if (artifacts?.manifest && parametersInputRef) artifacts.shared({ parametersInput: parametersInputRef });
  }

  assert(parametersInputRef, "Shared parameters NFT was not created.");
  if (!parametersReferenceRef && refsByHash.has(parametersReferenceHash)) parametersReferenceRef = outRef(refsByHash.get(parametersReferenceHash)!);
  assert(parametersReferenceRef, "Shared parameters reference script was not created.");
  const [parametersInput] = await provider.getUtxosWithUnit(parametersAddress, parametersUnit);
  assert(parametersInput && referenceKey(parametersInput) === referenceKey(parametersInputRef), "Shared parameters NFT is not spendable.");
  const parametersReference = refsByHash.get(parametersReferenceHash)!;
  assert(parametersReference?.scriptRef && validatorToScriptHash(parametersReference.scriptRef) === parametersPolicy);

  const builtins: Record<string, BuiltinSetup> = {};
  // Construct the typed map after references and shared state have been confirmed.
  for (const item of scripts) {
    const referencesForBuiltin = byBuiltin.get(item.builtin.name)!;
    const withdrawalReference = refsByHash.get(referencesForBuiltin.withdrawal)!;
    const mintReference = refsByHash.get(referencesForBuiltin.mint)!;
    const rewardAddress = validatorToRewardAddress(network, item.withdrawal);
    const setupCheckpoint = artifacts?.manifest?.setup[item.builtin.name];
    const registered = setupCheckpoint?.stakeAlreadyRegistered ?? stakeBefore.get(validatorToScriptHash(item.withdrawal)) ?? false;
    builtins[item.builtin.name] = {
      runtime, scripts: item, walletAddress, referenceAddress, rewardAddress,
      withdrawalHash: validatorToScriptHash(item.withdrawal),
      policyId: validatorToScriptHash({ ...item.mint, script: applyParamsToScript(item.mint.script, [validatorToScriptHash(item.withdrawal), parametersPolicy]) }),
      parametersScript, parametersPolicy, parametersAddress, parametersUnit, parametersInput,
      nonce: bootstrapNonce, signers, threshold,
      references: [withdrawalReference, parametersReference, mintReference],
      withdrawalReference, parametersReference, mintReference, mintCollateral,
      transactions, deploymentHash: originByHash.get(referencesForBuiltin.withdrawal) ?? setupHashes.at(-1)!,
      setupHash: setupHashes[0]!, registered,
    } as BuiltinSetup;
  }
  runtime.reserved.add(referenceKey(parametersInput));
  runtime.reserved.add(referenceKey(parametersReference));
  runtime.reserved.add(referenceKey(mintCollateral));
  if (artifacts?.manifest) artifacts.shared({
    parametersInput: outRef(parametersInput), parametersReference: outRef(parametersReference),
    ready: true,
  });
  artifacts?.report(setupScope, {
    status: "ready", network, parametersPolicy, parametersUnit, parametersAddress,
    parametersInput: outRef(parametersInput), parametersReference: outRef(parametersReference),
    bootstrapNonce, budget, protocolParameters: parameters, authorizedSigners: signerHashes,
    threshold, mintCollateral: outRef(mintCollateral), setupTransactions: setupHashes,
    referenceScripts: [...refsByHash.values()].map(outRef),
  });
  releaseResources(runtime);
  return { builtins, setupHashes, parametersInput, parametersReference, mintCollateral };
}

async function buildSetupBatch(args: {
  items: SetupItem[]; bootstrap: boolean; nonce?: UTxO | undefined; nonceValue: bigint;
  parametersScript: Script; parametersAddress: string; parametersUnit: string; budget: Budget;
  mintCollateral: UTxO; runtime: Runtime;
}): Promise<TxSignBuilder> {
  const { items, bootstrap, nonce, parametersScript, parametersAddress, parametersUnit, budget, mintCollateral, runtime } = args;
  const { lucid, referenceAddress, parameters } = runtime;
  const references = items.filter((item): item is SetupReference => item.kind === "reference");
  const registrations = items.filter((item): item is SetupRegistration => item.kind === "registration");
  const referenceValues = references.map((item) => minimumOutputAda(referenceAddress, { lovelace: 5n * ADA }, parameters, item.script));
  const referenceAda = referenceValues.reduce((total, value) => total + value, 0n);
  const parameterAda = bootstrap ? 5n * ADA : 0n;
  const deposit = BigInt(registrations.length) * parameters.keyDeposit;
  const target = referenceAda + parameterAda + deposit + 8n * ADA - (bootstrap ? args.nonceValue : 0n);
  const funding: UTxO[] = [];
  let total = 0n;
  for (const source of await ordinaryFunding(runtime)) {
    if (bootstrap && nonce && referenceKey(source) === referenceKey(nonce)) continue;
    if (referenceKey(source) === referenceKey(mintCollateral)) continue;
    funding.push(source);
    total += source.assets.lovelace!;
    if (total >= target) break;
  }
  assert(total >= target, "Insufficient separate ADA funding for shared setup.");
  const build = async (collateral: bigint) => {
    let tx = lucid.newTx();
    const inputs = [...(bootstrap && nonce ? [nonce] : []), ...funding];
    if (inputs.length) tx = tx.collectFrom(inputs);
    if (bootstrap) {
      assert(nonce);
      tx = tx.mintAssets({ [parametersUnit]: 1n }, Data.to(0n))
        .attach.MintingPolicy(parametersScript)
        .pay.ToContract(parametersAddress, { kind: "inline", value: parametersDatum(budget) }, { lovelace: 5n * ADA, [parametersUnit]: 1n });
    }
    for (const [index, item] of references.entries())
      tx = tx.pay.ToAddressWithData(referenceAddress, undefined, { lovelace: referenceValues[index]! }, item.script);
    for (const item of registrations)
      tx = tx.register.Stake(item.rewardAddress, Data.void()).attach.CertificateValidator(item.script);
    return tx.complete({ coinSelection: false, presetWalletInputs: [mintCollateral], setCollateral: collateral, canonical: true });
  };
  if (!bootstrap && registrations.length === 0) {
    return build(0n);
  }
  return completeWithMinimumCollateral(parameters.collateralPercentage, build);
}

export async function prepareBuiltin(scripts: Validators, runtime: Runtime, progress: (message: string) => void = () => {}): Promise<BuiltinSetup> {
  return (await prepareRun([scripts], runtime, progress)).builtins[scripts.builtin.name]!;
}

export async function prepareScenario(
  scripts: Validators,
  testCase: BuiltinCase,
  mode: ArgumentMode,
  progress: (message: string) => void = () => {},
  sharedSetup?: BuiltinSetup,
) {
  const setup = sharedSetup ?? await prepareBuiltin(scripts, await createRuntime({ network: "Custom" }), progress);
  assert.equal(setup.scripts, scripts);
  const { runtime, withdrawalHash, rewardAddress, withdrawalReference, mintCollateral, walletAddress } = setup;
  runtime.scope = `${scripts.builtin.name}/${testCase.name}/${mode}`;
  assert(!savedChain(runtime, runtime.scope), "Execute saved case chains through recovery.");
  await refreshProtocol(runtime);
  const { lucid, provider, info, emulator, parameters, evaluationOptions } = runtime;
  const budget = readParameters(setup.parametersInput);
  assert.deepEqual(budget, { memory: parameters.maxTxExMem, steps: parameters.maxTxExSteps }, "Execution limits changed since bootstrap; stop this run.");
  runtime.snapshot = await takeSnapshot(runtime, [setup.parametersAddress]);
  const initialSnapshot = [...runtime.snapshot.values()];
  for (const resource of Object.values(resourceInventory(runtime))) if (resource.confirmed && !resource.consumedBy) {
    const current = runtime.snapshot.get(referenceKey(resource.output));
    assert(current, `Run resource ${referenceKey(resource.output)} was unexpectedly spent outside the journal.`);
    assertOutput(current, resource.output);
  }
  const transactions: Record<string, string> = runtime.network === "Custom" || !sharedSetup ? { ...setup.transactions } : {};
  const preparation: PreparedTransaction[] = [];
  let argumentsHash: string | undefined;
  let argumentReferences: UTxO[] = [];
  if (mode === "referenced") {
    const arguments_ = Data.from(testCase.arguments);
    assert(Array.isArray(arguments_), "Referenced arguments must be a Data list.");
    if (arguments_.length) {
      progress("Preparing one inline-datum reference output per argument.");
      const completed = await buildWithReclamation(runtime, (reclaim, funding) => {
        let tx = lucid.newTx();
        if (reclaim.length) tx = tx.collectFrom(reclaim);
        for (const argument of arguments_)
          tx = tx.pay.ToAddressWithData(runtime.referenceAddress, { kind: "inline", value: Data.to(argument) }, { lovelace: 2n * ADA });
        return tx.complete({ presetWalletInputs: funding, canonical: true });
      });
      const signed = await signSelected(runtime, completed);
      const transaction = prepareTransaction("02-arguments", signed.toCBOR());
      argumentReferences = transaction.created.slice(0, arguments_.length);
      assert.equal(argumentReferences.length, arguments_.length);
      preparation.push(transaction);
      projectSnapshot(runtime, transaction);
      transactions[transaction.name] = transaction.cbor;
      argumentsHash = transaction.hash;
    }
  }
  for (const reference of argumentReferences) runtime.reserved.add(referenceKey(reference));
  const withdrawalReferences = sortUTxOs([withdrawalReference, ...argumentReferences], "Canonical");
  const argumentIndexes = argumentReferences.map((argument) => withdrawalReferences.findIndex((reference) => referenceKey(reference) === referenceKey(argument)));
  const resolvedArguments = Data.to(mode === "direct" ? Data.from(testCase.arguments) : argumentReferences.map((reference) => Data.from(reference.datum!)));
  const redeemer = Data.to(mode === "direct" ? new Constr(0, [Data.from(testCase.arguments)]) : new Constr(1, [argumentIndexes.map(BigInt)]));
  const expected = WITHDRAWAL_RESULTS[testCase.outcome];
  const prescribedBudget: EvaluatorAdapter = {
    name: "configured-withdrawal-budget",
    async evaluate({ tx, additionalUTxOs, context }) {
      const transaction = CML.Transaction.from_cbor_hex(tx);
      try {
        inspectWithdrawalRedeemer(transaction, redeemer, withdrawalReferences);
        const scriptContext = makeScriptContext(transaction, { Rewarding: [{ ScriptCredential: [withdrawalHash] }] }, {
          resolvedInputs: additionalUTxOs, slotConfig: context.slotConfig,
        });
        const result = evaluator.evaluateScript(scripts.withdrawal.script, [Data.to(scriptContext, ScriptContextData)], { ...evaluationOptions, maxBudget: budget });
        assert.equal(result.isSuccess, expected === "success", result.error?.message);
        if (expected !== "success") assert.equal(result.error?.code, expected);
        assert(result.budget.memory <= budget.memory && result.budget.steps <= budget.steps);
        return [{ redeemer_tag: "withdraw", redeemer_index: 0, ex_units: { mem: Number(budget.memory), steps: Number(budget.steps) } }];
      } finally { transaction.free(); }
    },
  };
  const draftInput: UTxO = { txHash: "fe".repeat(32), outputIndex: 0, address: walletAddress, assets: { lovelace: 5n * ADA } };
  const templateBuilder = await lucid.newTx().collectFrom([draftInput]).readFrom(withdrawalReferences)
    .withdraw(rewardAddress, 0n, redeemer).setMinFee(draftInput.assets.lovelace!)
    .complete({ coinSelection: false, presetWalletInputs: [mintCollateral], setCollateral: 0n, evaluator: prescribedBudget, canonical: true });
  const template = CML.Transaction.from_cbor_hex(templateBuilder.toCBOR());
  let ready: { funding: TxSignBuilder; withdrawalCbor: string; fundingInput: UTxO; failureCollateral: UTxO; feePasses: number } | undefined;
  const minimumReturn = minimumOutputAda(walletAddress, {}, parameters);
  let futureName = 0n;
  while (runtime.proofBundle?.assets[toUnit(setup.policyId, futureName.toString(16).padStart(64, "0"))]) futureName++;
  const proofAssets = { ...(runtime.proofBundle?.assets ?? {}), lovelace: 0n, [toUnit(setup.policyId, futureName.toString(16).padStart(64, "0"))]: 1n };
  const bundleAda = minimumOutputAda(walletAddress, proofAssets, parameters);
  const growth = bundleAda > (runtime.proofBundle?.assets.lovelace ?? 0n) ? bundleAda - (runtime.proofBundle?.assets.lovelace ?? 0n) : 0n;
  assert(setup.mintReference.scriptRef);
  const returnReserve = testCase.outcome === "success" ? minimumReturn
    : conservativeScriptFee(parameters, [setup.mintReference.scriptRef]) + growth + minimumReturn;
  progress("Calculating the exact withdrawal fee and bounded collateral pair.");
  try {
    let fee = draftInput.assets.lovelace!;
    for (let attempt = 0; attempt < 8; attempt++) {
      const collateralValue = minimumCollateral(fee, parameters.collateralPercentage) + returnReserve;
      const funding = await buildWithReclamation(runtime, (reclaim, fundingSources) => {
        let tx = lucid.newTx();
        if (reclaim.length) tx = tx.collectFrom(reclaim);
        return tx.pay.ToAddress(walletAddress, { lovelace: fee }).pay.ToAddress(walletAddress, { lovelace: collateralValue })
          .complete({ presetWalletInputs: fundingSources, canonical: true });
      });
      const fundingHash = prepareTransaction("03-funding", funding.toCBOR()).hash;
      const fundingInput: UTxO = { txHash: fundingHash, outputIndex: 0, address: walletAddress, assets: { lovelace: fee } };
      const failureCollateral: UTxO = { txHash: fundingHash, outputIndex: 1, address: walletAddress, assets: { lovelace: collateralValue } };
      const finalized = finalizeWithdrawal(template, fundingInput, fee, failureCollateral, parameters.collateralPercentage, walletAddress);
      const sized = withKeyWitnesses(finalized);
      let required: bigint;
      try {
        required = minimumFee(sized, parameters, [scripts.withdrawal]);
        if (fee === required) ready = { funding, withdrawalCbor: finalized.to_cbor_hex(), fundingInput, failureCollateral, feePasses: attempt + 1 };
      } finally { sized.free(); finalized.free(); }
      if (ready) break;
      fee = required;
    }
  } finally { template.free(); }
  assert(ready, "Producing fee and funding did not converge after 8 builds; no funding transaction was submitted.");
  const funding = await signSelected(runtime, ready.funding);
  const fundingTransaction = prepareTransaction("03-funding", funding.toCBOR());
  preparation.push(fundingTransaction);
  projectSnapshot(runtime, fundingTransaction);
  runtime.reserved.add(referenceKey(ready.fundingInput));
  runtime.reserved.add(referenceKey(ready.failureCollateral));
  const withdrawal = await signSelected(runtime, lucid.fromTx(ready.withdrawalCbor), [ready.fundingInput, ready.failureCollateral]);
  const checkedWithdrawal = CML.Transaction.from_cbor_hex(withdrawal.toCBOR());
  try { assertWithdrawalBody(checkedWithdrawal, ready.fundingInput, ready.failureCollateral, withdrawalReferences, parameters, scripts.withdrawal, budget, redeemer, runtime.network); }
  finally { checkedWithdrawal.free(); }
  const withdrawalName = testCase.outcome === "success" ? "04-successful-withdrawal" : "04-failed-withdrawal";
  const withdrawalTransaction = prepareTransaction(withdrawalName, testCase.outcome === "success" ? withdrawal.toCBOR() : invalidEnvelope(withdrawal));
  preparation.push(withdrawalTransaction);
  projectSnapshot(runtime, withdrawalTransaction);
  transactions["03-funding"] = funding.toCBOR();
  transactions[withdrawalName] = withdrawalTransaction.cbor;
  return { ...setup, testCase, mode, redeemer, resolvedArguments, argumentReferences, argumentIndexes, withdrawalReferences, argumentsHash,
    info, emulator, provider, lucid, parameters, evaluationOptions, budget, transactions, preparation, initialSnapshot,
    fundingHash: funding.toHash(), fundingInput: ready.fundingInput, failureCollateral: ready.failureCollateral, withdrawal, feePasses: ready.feePasses };
}

export type PreparedScenario = Awaited<ReturnType<typeof prepareScenario>>;

function inspectWithdrawalRedeemer(transaction: CML.Transaction, expectedRedeemer: string, references: UTxO[]) {
  const witnesses = transaction.witness_set();
  const redeemers = witnesses.redeemers();
  assert(redeemers);
  const entries = redeemers.to_flat_format();
  assert.equal(entries.len(), 1, "Expected only the withdrawal redeemer.");
  const entry = entries.get(0);
  const units = entry.ex_units();
  const data = entry.data();
  try {
    assert.equal(entry.tag(), CML.RedeemerTag.Reward);
    assert.equal(entry.index(), 0n);
    const builtinRedeemer = Data.from(data.to_cbor_hex());
    assert.deepEqual(builtinRedeemer, Data.from(expectedRedeemer));
    assert(builtinRedeemer instanceof Constr && builtinRedeemer.fields.length === 1, "Expected a typed builtin redeemer.");
    let builtinArguments: Data;
    if (builtinRedeemer.index === 0) builtinArguments = builtinRedeemer.fields[0]!;
    else {
      assert.equal(builtinRedeemer.index, 1, "Unknown builtin argument mode.");
      const indexes = builtinRedeemer.fields[0];
      assert(Array.isArray(indexes), "Expected reference-input indexes.");
      assert.equal(new Set(indexes).size, indexes.length, "Repeated argument indexes.");
      builtinArguments = indexes.map((index) => {
        assert(typeof index === "bigint" && index >= 0n && index < BigInt(references.length), "Argument index is out of range.");
        const reference = references[Number(index)]!;
        assert(reference.datum && !reference.datumHash, "Expected inline argument data.");
        return Data.from(reference.datum);
      });
    }
    assert.equal(witnesses.plutus_datums(), undefined);
    return {
      declared: { memory: units.mem(), steps: units.steps() },
      builtinArguments, builtinRedeemer,
      redeemer: data.to_cbor_hex(),
      redeemerEncoding: new Constr(redeemers.kind() === CML.RedeemersKind.ArrLegacyRedeemer ? 0 : 1, []),
    };
  } finally {
    data.free(); units.free(); entry.free(); entries.free(); redeemers.free(); witnesses.free();
  }
}

function assertWithdrawalBody(
  transaction: CML.Transaction,
  funding: UTxO,
  collateral: UTxO,
  references: UTxO[],
  parameters: PreparedScenario["parameters"],
  script: Script,
  budget: Budget,
  redeemer: string,
  network: Runtime["network"],
) {
  const body = transaction.body();
  const withdrawals = body.withdrawals();
  const accounts = withdrawals?.keys();
  const account = accounts?.get(0);
  const returned = body.collateral_return();
  const returnedValue = returned?.amount();
  const returnedAddress = returned?.address();
  try {
    const decoded = Cbor.parse(body.to_cbor_bytes(), { keepRef: true });
    assert(decoded instanceof CborMap);
    assert.deepEqual(decoded.map.map(({ k }) => { assert(k instanceof CborUInt); return Number(k.num); }), [0, 1, 2, 5, 11, 13, 16, 17, 18]);
    const outputs = decoded.map.find(({ k }) => k instanceof CborUInt && k.num === 1n)?.v;
    assert(outputs instanceof CborArray && outputs.subCborRef);
    assert.equal(toHex(outputs.subCborRef.toBuffer()), "80");
    assert.deepEqual(inputReferences(body.inputs()), [outRef(funding)]);
    assert.deepEqual(inputReferences(body.collateral_inputs()), [outRef(collateral)]);
    assert.deepEqual(inputReferences(body.reference_inputs()), references.map(outRef));
    assert.equal(accounts?.len(), 1);
    assert(account && withdrawals);
    const reward = account.to_address();
    try { assert.equal(reward.to_bech32(), validatorToRewardAddress(network, script)); } finally { reward.free(); }
    assert.equal(withdrawals.get(account), 0n);
    assert.equal(body.fee(), funding.assets.lovelace);
    assert.equal(body.fee(), minimumFee(transaction, parameters, [script]));
    const charge = minimumCollateral(body.fee(), parameters.collateralPercentage);
    assert.equal(body.total_collateral(), charge);
    assert.equal(returnedValue?.coin(), collateral.assets.lovelace! - charge);
    assert((returnedValue?.coin() ?? 0n) >= minimumOutputAda(funding.address, {}, parameters),
      "Collateral return is below minimum ADA.");
    assert.equal(returnedAddress?.to_bech32(), funding.address);
    assert.equal(returned?.datum(), undefined);
    assert.equal(returned?.script_ref(), undefined);
    assert.deepEqual(inspectWithdrawalRedeemer(transaction, redeemer, references).declared, budget);
  } finally {
    returnedAddress?.free(); returnedValue?.free(); returned?.free(); account?.free(); accounts?.free(); withdrawals?.free(); body.free();
  }
}

export function prepareFailureEvidence(scenario: PreparedScenario) {
  const { testCase, scripts, info, evaluationOptions, budget, withdrawalHash, fundingInput, withdrawalReferences,
    redeemer, failureCollateral, withdrawal: signed, parameters, walletAddress, runtime } = scenario;
  assert(testCase.outcome !== "success", "Expected a failure case.");
  const expected = WITHDRAWAL_RESULTS[testCase.outcome];
  const transaction = CML.Transaction.from_cbor_hex(signed.toCBOR());
  const body = transaction.body();
  const failedHash = signed.toHash();
  try {
    const invocation = inspectWithdrawalRedeemer(transaction, redeemer, withdrawalReferences);
    const context = makeScriptContext(transaction, { Rewarding: [{ ScriptCredential: [withdrawalHash] }] }, {
      resolvedInputs: [fundingInput, ...withdrawalReferences], slotConfig: info.slotConfig,
    });
    assert.deepEqual([...context.scriptContextTxInfo.txInfoRedeemers.keys()].map((purpose) => Object.keys(purpose)[0]), ["Rewarding"]);
    const evaluation = evaluator.evaluateScript(scripts.withdrawal.script, [Data.to(context, ScriptContextData)], { ...evaluationOptions, maxBudget: budget });
    assert.equal(evaluation.isSuccess, false);
    assert.equal(evaluation.error?.code, expected);
    assert(evaluation.budget.memory <= budget.memory && evaluation.budget.steps <= budget.steps);
    const returnUtxo = prepareTransaction("04-failed-withdrawal", invalidEnvelope(signed)).created[0];
    assert(returnUtxo, "Missing finalized collateral return.");
    const charged = minimumCollateral(body.fee(), parameters.collateralPercentage);
    assert.equal(returnUtxo.address, walletAddress);
    assert.deepEqual(returnUtxo.assets, { lovelace: failureCollateral.assets.lovelace! - charged });
    const costModelData = CML.PlutusData.from_cbor_hex(Data.to(parameters.costModels.PlutusV3.map(BigInt)));
    const costModel = costModelData.to_canonical_cbor_hex();
    costModelData.free();
    const witness = new Constr(0, [body.fee(), inputReferences(body.inputs()).map(outRefData), invocation.builtinRedeemer,
      outRefData(failureCollateral), body.total_collateral()!, inputReferences(body.reference_inputs()).map(outRefData), invocation.redeemerEncoding, costModel]);
    return { failedHash, returnUtxo, witness,
      validation: {
        withdrawal: { scriptHash: withdrawalHash, code: expected, declared: invocation.declared, consumed: evaluation.budget },
        validFlagTrueRejected: runtime.network === "Custom" ? "ScriptFailure" : undefined, invalidFlagAccepted: true,
        localEvaluation: { code: expected, consumed: evaluation.budget }, effectsObservedOn: runtime.network === "Custom" ? "emulator" : "chain",
        ordinaryInputsUnspent: [outRef(fundingInput)], referenceScriptsUnspent: true, argumentReferencesUnspent: true,
      },
      collateral: { input: outRef(failureCollateral), inputLovelace: failureCollateral.assets.lovelace,
        transactionFeeLovelace: body.fee(), percentage: parameters.collateralPercentage, minimumLovelace: charged, chargedLovelace: charged,
        return: { ...outRef(returnUtxo), lovelace: returnUtxo.assets.lovelace! } },
    };
  } finally { body.free(); transaction.free(); }
}

export type FailureEvidence = ReturnType<typeof prepareFailureEvidence>;

export async function buildProofMint(
  scenario: PreparedScenario,
  evidence: FailureEvidence,
  witness = evidence.witness,
  parametersInput?: UTxO,
) {
  const { lucid, parameters } = scenario;
  const { provider, parametersUnit, parametersAddress, policyId, walletAddress, mintReference, mintCollateral, argumentReferences } = scenario;
  const snapshot = scenario.runtime.snapshot;
  const configuration = parametersInput ?? (snapshot ? [...snapshot.values()].find((output) => output.assets[parametersUnit] === 1n)
    : (await provider.getUtxosWithUnit(parametersAddress, parametersUnit))[0]);
  assert(configuration, "Missing live parameters NFT.");
  const currentArguments = snapshot ? argumentReferences.flatMap((reference) => snapshot.get(referenceKey(reference)) ?? [])
    : await provider.getUtxosByOutRef(argumentReferences);
  assert.equal(currentArguments.length, argumentReferences.length, "Original argument references are unavailable or changed.");
  for (const reference of argumentReferences) {
    const current = currentArguments.find((output) => referenceKey(output) === referenceKey(reference));
    assert(current, "Original argument references are unavailable or changed.");
    assertOutput(current, reference);
  }
  const references = sortUTxOs([mintReference, configuration, ...argumentReferences], "Canonical");
  const previous = scenario.runtime.proofBundle;
  const inputs = sortUTxOs([evidence.returnUtxo, ...(previous ? [previous] : [])], "Canonical");
  const unit = toUnit(policyId, evidence.failedHash);
  const bundleAssets = { ...(previous?.assets ?? {}), lovelace: 0n, [unit]: 1n };
  bundleAssets.lovelace = minimumOutputAda(walletAddress, bundleAssets, parameters);
  const redeemer = Data.to(new Constr(0, [BigInt(inputs.findIndex((input) => referenceKey(input) === referenceKey(evidence.returnUtxo))), BigInt(references.indexOf(configuration)), witness]));
  const completed = await completeWithMinimumCollateral(parameters.collateralPercentage, (collateral) =>
    lucid.newTx().collectFrom(inputs).readFrom(references)
      .mintAssets({ [unit]: 1n }, redeemer)
      .pay.ToAddress(walletAddress, bundleAssets)
      .complete({ coinSelection: false, presetWalletInputs: [mintCollateral], setCollateral: collateral, canonical: true }),
  );
  const transaction = CML.Transaction.from_cbor_hex(completed.toCBOR());
  const body = transaction.body();
  try {
    assert.deepEqual(inputReferences(body.inputs()), inputs.map(outRef));
    assert.deepEqual(inputReferences(body.reference_inputs()), references.map(outRef));
  } finally { body.free(); transaction.free(); }
  return completed;
}

export async function updateParameters(scenario: PreparedScenario, budget: Budget, signerIndices = [0, 1]) {
  assert.equal(scenario.runtime.network, "Custom", "Parameter rotation tests require Custom.");
  const { provider, lucid, parametersUnit, parametersAddress, parametersReference, walletAddress, fundingInput, failureCollateral,
    mintCollateral, signers, parameters } = scenario;
  const current = await provider.getUtxoByUnit(parametersUnit);
  const excluded = [fundingInput, failureCollateral, mintCollateral];
  const funding = (await provider.getUtxos(walletAddress)).filter((u) =>
    !excluded.some((e) => e.txHash === u.txHash && e.outputIndex === u.outputIndex),
  ).sort((a, b) => a.assets.lovelace! > b.assets.lovelace! ? -1 : 1)[0];
  assert(funding);
  const selected = signerIndices.map((index) => { const signer = signers[index]; assert(signer); return signer; });
  const completed = await completeWithMinimumCollateral(parameters.collateralPercentage, (collateral) => {
    const tx = lucid.newTx().collectFrom([current], Data.to(0n)).collectFrom([funding]).readFrom([parametersReference])
      .pay.ToContract(parametersAddress, { kind: "inline", value: parametersDatum(budget) }, current.assets);
    for (const signer of selected) tx.addSignerKey(signer.hash);
    return tx.complete({ coinSelection: false, presetWalletInputs: [mintCollateral], setCollateral: collateral });
  });
  completed.sign.withWallet();
  for (const signer of selected) { assert(signer.key); completed.sign.withPrivateKey(signer.key); }
  const signed = await completed.complete();
  const hash = await signed.submit();
  const updated = await provider.getUtxoByUnit(parametersUnit);
  assert.equal(updated.txHash, hash);
  assert.deepEqual(readParameters(updated), budget);
  assert.deepEqual(updated.assets, current.assets);
  assert.deepEqual(await provider.getUtxosByOutRef([current]), []);
  return updated;
}

async function runFreshScenario(scripts: Validators, testCase: BuiltinCase, mode: ArgumentMode, progress: (message: string) => void, sharedSetup?: BuiltinSetup) {
  const scenario = await prepareScenario(scripts, testCase, mode, progress, sharedSetup);
  const { runtime, transactions, walletAddress, referenceAddress, rewardAddress, withdrawalHash, policyId,
    withdrawalReference, mintReference, mintCollateral, references, fundingInput, deploymentHash, setupHash, failureCollateral,
    parametersInput, parametersUnit, parametersPolicy, parametersAddress, parametersReference, signers, threshold, budget, withdrawal, parameters,
    argumentReferences, argumentIndexes, withdrawalReferences, argumentsHash, redeemer } = scenario;
  const invocationTransaction = CML.Transaction.from_cbor_hex(withdrawal.toCBOR());
  const invocation = inspectWithdrawalRedeemer(invocationTransaction, redeemer, withdrawalReferences);
  invocationTransaction.free();
  const protectedReferences = [...references, ...argumentReferences, parametersInput, mintCollateral]
    .filter((reference) => runtime.snapshot!.has(referenceKey(reference)));
  const commonReport = {
    network: runtime.network, mode, evaluation: "local-scalus@1.3.0", protocolParameters: parameters, walletAddress, referenceAddress,
    invocation: { builtin: scripts.builtin.name, case: testCase.name, mode, arguments: invocation.builtinArguments,
      argumentReferences: argumentReferences.map(outRef), argumentIndexes, redeemer: invocation.redeemer, expectedOutcome: testCase.outcome },
    inputs: { ordinary: [outRef(fundingInput)], references: withdrawalReferences.map(outRef) },
    fee: { lovelace: fundingInput.assets.lovelace, minimum: true, calculationPasses: scenario.feePasses },
    validators: {
      withdrawal: { hash: withdrawalHash, rewardAddress, reference: outRef(withdrawalReference) },
      mint: { policyId, reference: outRef(mintReference) },
      parameters: { policyId: parametersPolicy, address: parametersAddress, reference: outRef(parametersReference), unit: parametersUnit,
        input: outRef(parametersInput), budget, authorizedSigners: signers.map(({ hash }) => hash), threshold, bootstrapNonce: scenario.nonce },
    },
  };
  const checkpoint = { mode, argumentReferences: argumentReferences.map(outRef), argumentIndexes, resolvedArguments: scenario.resolvedArguments,
    redeemer, protocol: parameters, feePasses: scenario.feePasses, collateralInput: outRef(failureCollateral), collateralInputLovelace: failureCollateral.assets.lovelace! };
  if (testCase.outcome === "success") {
    const evaluations = await localEvaluator(parameters).evaluate({ tx: withdrawal.toCBOR(), additionalUTxOs: [fundingInput, ...withdrawalReferences],
      context: { network: runtime.network, slotConfig: runtime.slotConfig, protocolParameters: parameters, costModels: runtime.lucid.config().costModels! } });
    assert.equal(evaluations.length, 1);
    const evaluation = evaluations[0]!;
    assert.equal(evaluation.redeemer_tag, "withdraw"); assert.equal(evaluation.redeemer_index, 0);
    assert(evaluation.ex_units.mem <= budget.memory && evaluation.ex_units.steps <= budget.steps);
    const hash = withdrawal.toHash();
    const report = { ...commonReport, resourcesReleased: argumentReferences.map(outRef),
      effectsObservedOn: runtime.network === "Custom" ? "emulator" : "chain", outcome: "success" as const,
      transactions: { deployment: deploymentHash, setup: setupHash, arguments: argumentsHash, funding: scenario.fundingHash, withdrawal: hash },
      validation: { withdrawal: { success: true, declared: budget, consumed: { memory: BigInt(evaluation.ex_units.mem), steps: BigInt(evaluation.ex_units.steps) } },
        ordinaryInputsConsumed: true, referenceScriptsUnspent: true, argumentReferencesUnspent: true },
      collateral: { input: outRef(failureCollateral), unspent: true, returnCreated: false, releasedToFunding: true }, nft: null };
    const chain = makeChain(runtime.scope, parameters, scenario.preparation, scenario.initialSnapshot, protectedReferences);
    runtime.artifacts?.batch(() => {
      if (runtime.artifacts!.manifest) runtime.artifacts!.case(runtime.scope, { ...checkpoint, result: report });
      runtime.artifacts!.report(runtime.scope, { ...commonReport, status: "prepared",
        localEvaluation: { success: true, declared: budget, consumed: evaluation.ex_units } });
      runtime.artifacts!.journalChain(chain);
    });
    progress("Broadcasting the prepared case, then confirming its net ledger effects.");
    await executeChain(runtime, chain);
    completeCase(runtime);
    const cleanup = runtime.network === "Custom" ? await cleanupRun(runtime) : undefined;
    Object.assign(transactions, cleanup?.transactions);
    return { report: { ...report, cleanup: cleanup?.checkpoint }, transactions };
  }
  const evidence = prepareFailureEvidence(scenario);
  progress("Preparing the proof from finalized collateral return and the producing protocol snapshot.");
  const mint = await buildProofMint(scenario, evidence);
  const signedMint = await signSelected(runtime, mint);
  const mintTransaction = prepareTransaction("05-mint", signedMint.toCBOR());
  const mintCore = CML.Transaction.from_cbor_hex(signedMint.toCBOR());
  const mintBody = mintCore.body();
  try {
    assert.deepEqual(inputReferences(mintBody.collateral_inputs()), [outRef(mintCollateral)]);
    assert.equal(mintBody.total_collateral(), minimumCollateral(mintBody.fee(), parameters.collateralPercentage));
  } finally { mintBody.free(); mintCore.free(); }
  const unit = toUnit(policyId, evidence.failedHash);
  const nft = mintTransaction.created.find((output) => output.assets[unit] === 1n);
  assert(nft, "Prepared proof has no NFT output.");
  scenario.preparation.push(mintTransaction);
  projectSnapshot(runtime, mintTransaction);
  transactions["05-mint"] = signedMint.toCBOR();
  const report = { ...commonReport, resourcesReleased: argumentReferences.map(outRef),
    effectsObservedOn: runtime.network === "Custom" ? "emulator" : "chain", outcome: testCase.outcome,
    transactions: { deployment: deploymentHash, setup: setupHash, arguments: argumentsHash, funding: scenario.fundingHash, failed: evidence.failedHash, mint: signedMint.toHash(),
      setupBatches: runtime.artifacts?.records.filter((record) => record.scope === "setup" && /^\d+-setup-\d+$/.test(record.name)).map((record) => record.hash) },
    validation: evidence.validation, collateral: { ...evidence.collateral, returnSpentBy: signedMint.toHash(), proofBundle: outRef(nft) },
    nft: { policyId, assetName: evidence.failedHash, unit, quantity: 1n, output: outRef(nft) } };
  const chain = makeChain(runtime.scope, parameters, scenario.preparation, scenario.initialSnapshot, protectedReferences);
  runtime.artifacts?.batch(() => {
    if (runtime.artifacts!.manifest) runtime.artifacts!.case(runtime.scope, { ...checkpoint, failureReturn: outRef(evidence.returnUtxo), result: report });
    runtime.artifacts!.report(runtime.scope, { ...commonReport, status: "prepared",
      localEvaluation: { success: false, ...evidence.validation.localEvaluation } });
    runtime.artifacts!.journalChain(chain);
  });
  progress("Broadcasting the prepared case, then confirming its net ledger effects.");
  const current = await executeChain(runtime, chain);
  assertOutput(current.get(referenceKey(nft))!, nft);
  assert(!current.has(referenceKey(evidence.returnUtxo)), "Proof did not consume collateral return.");
  completeCase(runtime);
  const cleanup = runtime.network === "Custom" ? await cleanupRun(runtime) : undefined;
  Object.assign(transactions, cleanup?.transactions);
  return { report: { ...report, cleanup: cleanup?.checkpoint }, transactions };
}

export async function resumeCaseChain(runtime: Runtime, scope: string) {
  const chain = savedChain(runtime, scope);
  if (!chain) return undefined;
  const report = runtime.artifacts!.manifest!.cases[scope]!.result;
  assert(report?.invocation && report.validators && report.collateral && report.validation, `Missing complete case checkpoint for ${scope}.`);
  await executeChain(runtime, chain);
  completeCase(runtime, scope);
  runtime.artifacts!.report(scope, { ...report, status: "passed" });
  return { report: { ...report, status: "passed" } as unknown as Awaited<ReturnType<typeof runFreshScenario>>["report"],
    transactions: Object.fromEntries(chain.transactions.map((transaction) => [transaction.name, transaction.cbor])) };
}

export async function runScenario(scripts: Validators, testCase: BuiltinCase, mode: ArgumentMode, progress: (message: string) => void = () => {}, sharedSetup?: BuiltinSetup) {
  const scope = `${scripts.builtin.name}/${testCase.name}/${mode}`;
  if (sharedSetup && savedChain(sharedSetup.runtime, scope)) return (await resumeCaseChain(sharedSetup.runtime, scope))!;
  return runFreshScenario(scripts, testCase, mode, progress, sharedSetup);
}
