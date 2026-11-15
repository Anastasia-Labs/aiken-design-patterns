import assert from "node:assert/strict";
import { Cbor, CborArray, CborMap, CborUInt } from "@harmoniclabs/cbor";
import {
  CML, Constr, Data, Lucid, ScriptContextData, applyParamsToScript, coreToTxOutput,
  fromHex, fromText, isEqualUTxO, makeScriptContext, sortUTxOs, toHex, toUnit,
  validatorToAddress, validatorToRewardAddress, validatorToScriptHash,
  type EvaluatorAdapter, type OutRef, type Script, type TxSigned, type UTxO,
} from "@lucid-evolution/lucid";
import { PlutusScriptEvaluationError, evaluator } from "scalus";
import { restoreProtocol } from "./artifacts.ts";
import type { Validators } from "./blueprint.ts";
import { ARGUMENT_MODES, WITHDRAWAL_RESULTS, type ArgumentMode, type BuiltinCase } from "./builtins.ts";
import { completeCase, createRuntime, localEvaluator, ordinaryFunding, recordResources, referenceKey, refreshProtocol, releaseResources, resourceInventory, restoreResources, submitTransaction, type Effects, type Runtime } from "./runtime.ts";
import {
  completeWithMinimumCollateral, conservativeScriptFee, finalizeWithdrawal, inputReferences, minimumCollateral, minimumOutputAda,
  minimumFee, outRef, outRefData, type Budget,
} from "./transactions.ts";

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

function transactionCollateral(signed: SignedView): OutRef[] {
  const transaction = CML.Transaction.from_cbor_hex(signed.toCBOR());
  const body = transaction.body();
  try { return inputReferences(body.collateral_inputs()); }
  finally { body.free(); transaction.free(); }
}

export async function buildWithReclamation(
  runtime: Runtime,
  build: (reclaim: UTxO[], funding: UTxO[]) => Promise<TxSigned>,
  final = false,
): Promise<TxSigned> {
  releaseResources(runtime);
  const resources = Object.values(runtime.resources).filter((resource) => resource.confirmed && !resource.consumedBy
    && resource.role !== "parameters" && resource.role !== "proof-bundle"
    && (final || resource.releasedBy !== undefined))
    .sort((a, b) => referenceKey(a.output).localeCompare(referenceKey(b.output)));
  const current = await runtime.provider.getUtxosByOutRef(resources.map(({ output }) => outRef(output)));
  const present = new Set(current.map(referenceKey));
  for (const { output } of resources)
    assert(present.has(referenceKey(output)), `Run resource ${referenceKey(output)} was unexpectedly spent outside the journal.`);
  const ordinary = final ? [] : await ordinaryFunding(runtime);
  let best: TxSigned | undefined;
  let lastError: unknown;
  for (let count = 0; count <= resources.length; count++) {
    if (final && count === 0) continue;
    const reclaim = resources.slice(0, count).map(({ output }) => output);
    const selected = new Set(reclaim.map(referenceKey));
    const funding = ordinary.filter((input) => !selected.has(referenceKey(input)));
    // Lucid reads the wallet when presetWalletInputs is empty. Keep that lookup
    // within the same eligible pool, including when reclamation supplies it all.
    runtime.wallet.overrideUTxOs([...reclaim, ...funding]);
    try {
      const candidate = await build(reclaim, funding);
      if (candidate.toCBOR().length / 2 > runtime.parameters.maxTxSize) {
        lastError = new Error("Reclamation transaction exceeds the signed transaction size limit.");
        break;
      }
      best = candidate;
    } catch (error) {
      lastError = error;
      if (best) break;
    } finally {
      runtime.wallet.clearUTxOOverride?.();
    }
  }
  assert(best, `Insufficient ADA funding or no reclamation batch fits before funding submission: ${String(lastError)}`);
  return best;
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
    const signed = await buildWithReclamation(runtime, async (reclaim) => {
      const completed = await runtime.lucid.newTx().collectFrom(reclaim)
        .complete({ coinSelection: false, canonical: true });
      return completed.sign.withWallet().complete();
    }, true);
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
    let best: { items: SetupItem[]; signed: TxSigned } | undefined;
    const packed: SetupItem[] = [];
    for (const item of candidates) {
      const tryItems = [...packed, item];
      try {
        const candidate = await buildSetupBatch({
          items: tryItems, bootstrap, nonce: nonceInput, nonceValue, parametersScript,
          parametersAddress, parametersUnit, budget, mintCollateral, runtime,
        });
        const bytes = candidate.toCBOR().length / 2;
        if (bytes > parameters.maxTxSize) continue;
        best = { items: tryItems, signed: candidate };
        packed.push(item);
      } catch (error) {
        if (best) break;
        throw error;
      }
    }
    assert(best, "No shared setup batch fits within the network's maximum transaction size.");
    const name = `${String(batchIndex + 1).padStart(2, "0")}-setup-${String(batchIndex).padStart(2, "0")}`;
    const effects: Effects = {
      present: createdOutputs(best.signed), absent: consumedInputs(best.signed), addresses: [walletAddress, parametersAddress],
    };
    const includedRegistrations = best.items.filter((item): item is SetupRegistration => item.kind === "registration");
    if (includedRegistrations.length) effects.stakeRegistered = includedRegistrations.map(({ rewardAddress }) => rewardAddress);
    const record = artifacts?.signed(setupScope, name, best.signed.toCBOR(), best.signed.toHash(), effects);
    transactions[name] = best.signed.toCBOR();
    await submitTransaction(runtime, name, best.signed.toCBOR(), effects);
    const savedView = record ? savedSigned(record.cbor) : best.signed;
    inspectSetupOutputs(savedView);
    for (const item of best.items) if (item.kind === "reference") emitted.add(item.hash);
    setupHashes.push(best.signed.toHash());
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
}): Promise<TxSigned> {
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
    const completed = await build(0n);
    return completed.sign.withWallet().complete();
  }
  const completed = await completeWithMinimumCollateral(parameters.collateralPercentage, build);
  return completed.sign.withWallet().complete();
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
  await refreshProtocol(runtime);
  const { lucid, provider, info, emulator } = runtime;
  const checkpoint = runtime.artifacts?.manifest?.cases[runtime.scope];
  const parameters = checkpoint?.protocol ? restoreProtocol(checkpoint.protocol) : runtime.parameters;
  const evaluationOptions = checkpoint?.protocol ? {
    plutusVersion: "PlutusV3" as const, protocolMajorVersion: parameters.protocolMajorVersion!,
    costModel: parameters.costModels.PlutusV3,
    maxBudget: { memory: parameters.maxTxExMem, steps: parameters.maxTxExSteps },
  } : runtime.evaluationOptions;
  const budget = readParameters(setup.parametersInput);
  assert.deepEqual(budget, { memory: parameters.maxTxExMem, steps: parameters.maxTxExSteps }, "Execution limits changed since bootstrap; stop this run.");
  const transactions: Record<string, string> = runtime.network === "Custom" || !sharedSetup ? { ...setup.transactions } : {};
  if (checkpoint?.mode) assert.equal(checkpoint.mode, mode, "Saved argument mode changed.");
  if (runtime.artifacts?.manifest) runtime.artifacts.case(runtime.scope, { mode });
  let argumentsHash: string | undefined;
  let argumentReferences: UTxO[] = [];
  const savedArguments = runtime.artifacts?.find(runtime.scope, "02-arguments");
  if (mode === "referenced") {
    const arguments_ = Data.from(testCase.arguments);
    assert(Array.isArray(arguments_), "Referenced arguments must be a Data list.");
    if (arguments_.length) {
      progress("Provisioning one inline-datum reference output per argument.");
      const signed = savedArguments ? savedSigned(savedArguments.cbor) : await buildWithReclamation(runtime, async (reclaim, funding) => {
        assert(!checkpoint?.argumentReferences, "Missing saved argument provisioning transaction.");
        let tx = lucid.newTx().collectFrom(reclaim);
        for (const argument of arguments_)
          tx = tx.pay.ToAddressWithData(runtime.referenceAddress, { kind: "inline", value: Data.to(argument) }, { lovelace: 2n * ADA });
        const completed = await tx.complete({ presetWalletInputs: funding, canonical: true });
        return completed.sign.withWallet().complete();
      });
      argumentReferences = transactionOutputs(signed).slice(0, arguments_.length);
      assert.equal(argumentReferences.length, arguments_.length, "Missing saved argument outputs.");
      for (const [index, reference] of argumentReferences.entries()) {
        assert(reference.datum && !reference.datumHash && !reference.scriptRef, "Expected an inline argument datum.");
        assert.equal(reference.address, runtime.referenceAddress, "Saved argument address changed.");
        assert.deepEqual(Data.from(reference.datum), arguments_[index], "Saved argument datum changed.");
      }
      transactions["02-arguments"] = signed.toCBOR();
      argumentsHash = await submitTransaction(runtime, "02-arguments", signed.toCBOR(), {
        present: createdOutputs(signed), absent: consumedInputs(signed), addresses: [walletAddress, runtime.referenceAddress],
      });
      assert.deepEqual(sortUTxOs(await provider.getUtxosByOutRef(argumentReferences), "Canonical"), sortUTxOs(argumentReferences, "Canonical"),
        "Original argument references are unavailable or changed.");
    } else assert(!savedArguments, "Zero arguments require no provisioning transaction.");
  } else assert(!savedArguments, "Direct arguments require no provisioning transaction.");
  for (const reference of argumentReferences) runtime.reserved.add(referenceKey(reference));
  const withdrawalReferences = sortUTxOs([withdrawalReference, ...argumentReferences], "Canonical");
  const argumentIndexes = argumentReferences.map((argument) => withdrawalReferences.findIndex((reference) => referenceKey(reference) === referenceKey(argument)));
  const resolvedArguments = Data.to(mode === "direct" ? Data.from(testCase.arguments)
    : argumentReferences.map((reference) => Data.from(reference.datum!)));
  const redeemer = Data.to(mode === "direct" ? new Constr(0, [Data.from(testCase.arguments)]) : new Constr(1, [argumentIndexes.map(BigInt)]));
  if (checkpoint?.argumentReferences) {
    assert.deepEqual(checkpoint.argumentReferences, argumentReferences.map(outRef), "Saved argument references changed.");
    assert.deepEqual(checkpoint.argumentIndexes, argumentIndexes, "Saved argument indexes changed.");
    assert.equal(checkpoint.resolvedArguments, resolvedArguments, "Saved resolved arguments changed.");
    assert.equal(checkpoint.redeemer, redeemer, "Saved builtin redeemer changed.");
  }
  if (runtime.artifacts?.manifest) runtime.artifacts.case(runtime.scope, {
    mode, argumentReferences: argumentReferences.map(outRef), argumentIndexes, resolvedArguments, redeemer,
  });
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
  const scope = runtime.scope;
  const savedFunding = runtime.artifacts?.find(scope, "03-funding");
  const withdrawalName = testCase.outcome === "success" ? "04-successful-withdrawal" : "04-failed-withdrawal";
  const savedWithdrawal = runtime.artifacts?.find(scope, withdrawalName);
  assert.equal(Boolean(savedFunding), Boolean(savedWithdrawal), "Funding and withdrawal must be saved together.");
  if (savedFunding && runtime.artifacts?.manifest) assert(checkpoint?.protocol, "Missing producing protocol snapshot for saved funding.");
  let ready: { funding: SignedView; withdrawal: SignedView; fundingInput: UTxO; failureCollateral: UTxO; feePasses: number };
  if (savedFunding && savedWithdrawal) {
    const signed = savedSigned(savedWithdrawal.cbor);
    const transaction = signed.toTransaction();
    const body = transaction.body();
    const fee = body.fee();
    const collateralRef = checkpoint?.collateralInput ?? transactionCollateral(signed)[0];
    assert(collateralRef, "Saved withdrawal is missing its collateral input.");
    body.free(); transaction.free();
    const fundingOutputs = transactionOutputs(savedSigned(savedFunding.cbor));
    const failureCollateral = fundingOutputs[1]!;
    assert.equal(referenceKey(failureCollateral), referenceKey(collateralRef), "Saved collateral output changed.");
    ready = {
      funding: savedSigned(savedFunding.cbor), withdrawal: signed,
      fundingInput: { txHash: savedFunding.hash, outputIndex: 0, address: walletAddress, assets: { lovelace: fee } },
      failureCollateral,
      feePasses: checkpoint?.feePasses ?? 0,
    };
  } else {
    const draftInput: UTxO = { txHash: "fe".repeat(32), outputIndex: 0, address: walletAddress, assets: { lovelace: 5n * ADA } };
    const templateBuilder = await lucid.newTx().collectFrom([draftInput]).readFrom(withdrawalReferences)
      .withdraw(rewardAddress, 0n, redeemer).setMinFee(draftInput.assets.lovelace!)
      .complete({ coinSelection: false, presetWalletInputs: [mintCollateral], setCollateral: 0n, evaluator: prescribedBudget, canonical: true });
    const template = CML.Transaction.from_cbor_hex(templateBuilder.toCBOR());
    let built: typeof ready | undefined;
    const minimumReturn = minimumOutputAda(walletAddress, {}, parameters);
    let futureName = 0n;
    while (runtime.proofBundle?.assets[toUnit(setup.policyId, futureName.toString(16).padStart(64, "0"))]) futureName++;
    const proofAssets = { ...(runtime.proofBundle?.assets ?? {}), lovelace: 0n,
      [toUnit(setup.policyId, futureName.toString(16).padStart(64, "0"))]: 1n };
    const bundleAda = minimumOutputAda(walletAddress, proofAssets, parameters);
    const growth = bundleAda > (runtime.proofBundle?.assets.lovelace ?? 0n)
      ? bundleAda - (runtime.proofBundle?.assets.lovelace ?? 0n) : 0n;
    assert(setup.mintReference.scriptRef);
    const returnReserve = testCase.outcome === "success" ? minimumReturn
      : conservativeScriptFee(parameters, [setup.mintReference.scriptRef]) + growth + minimumReturn;
    progress("Calculating the exact withdrawal fee and bounded collateral pair.");
    try {
      let fee = draftInput.assets.lovelace!;
      for (let attempt = 0; attempt < 8; attempt++) {
        const collateralValue = minimumCollateral(fee, parameters.collateralPercentage) + returnReserve;
        const signedFunding = await buildWithReclamation(runtime, async (reclaim, fundingSources) => {
          const tx = lucid.newTx().collectFrom(reclaim)
            .pay.ToAddress(walletAddress, { lovelace: fee })
            .pay.ToAddress(walletAddress, { lovelace: collateralValue });
          const funding = await tx.complete({ presetWalletInputs: fundingSources, canonical: true });
          return funding.sign.withWallet().complete();
        });
        const fundingInput: UTxO = { txHash: signedFunding.toHash(), outputIndex: 0, address: walletAddress, assets: { lovelace: fee } };
        const candidateCollateral: UTxO = { txHash: signedFunding.toHash(), outputIndex: 1, address: walletAddress, assets: { lovelace: collateralValue } };
        const finalized = finalizeWithdrawal(template, fundingInput, fee, candidateCollateral, parameters.collateralPercentage, walletAddress);
        let withdrawal: TxSigned;
        runtime.wallet.overrideUTxOs([fundingInput, candidateCollateral]);
        try { withdrawal = await lucid.fromTx(finalized.to_cbor_hex()).sign.withWallet().complete(); }
        finally { runtime.wallet.clearUTxOOverride?.(); finalized.free(); }
        const feeTransaction = CML.Transaction.from_cbor_hex(withdrawal.toCBOR());
        let required: bigint;
        try { required = minimumFee(feeTransaction, parameters, [scripts.withdrawal]); }
        finally { feeTransaction.free(); }
        if (fee === required) {
          built = { funding: signedFunding, withdrawal, fundingInput, failureCollateral: candidateCollateral, feePasses: attempt + 1 };
          break;
        }
        fee = required;
      }
    } finally { template.free(); }
    assert(built, "Producing fee and funding did not converge after 8 builds; no funding transaction was submitted.");
    ready = built;
    if (runtime.artifacts?.manifest) runtime.artifacts.case(scope, { protocol: parameters, feePasses: ready.feePasses,
      collateralInput: outRef(ready.failureCollateral), collateralInputLovelace: ready.failureCollateral.assets.lovelace!, stage: "prepared" });
    const withdrawalCbor = testCase.outcome === "success" ? ready.withdrawal.toCBOR() : invalidEnvelope(ready.withdrawal);
    runtime.artifacts?.signedPair(scope,
      { name: "03-funding", cbor: ready.funding.toCBOR(), hash: ready.funding.toHash(),
        effects: { present: createdOutputs(ready.funding), absent: consumedInputs(ready.funding) } },
      { name: withdrawalName, cbor: withdrawalCbor, hash: ready.withdrawal.toHash(),
        effects: testCase.outcome === "success"
          ? { present: [ready.failureCollateral], absent: [ready.fundingInput] }
          : { present: [ready.fundingInput, { txHash: ready.withdrawal.toHash(), outputIndex: 0 }], absent: [ready.failureCollateral] } },
    );
  }
  const { funding, withdrawal, fundingInput, failureCollateral, feePasses } = ready;
  const checkedWithdrawal = CML.Transaction.from_cbor_hex(withdrawal.toCBOR());
  try { assertWithdrawalBody(checkedWithdrawal, fundingInput, failureCollateral, withdrawalReferences, parameters, scripts.withdrawal, budget, redeemer, runtime.network); }
  finally { checkedWithdrawal.free(); }
  runtime.artifacts?.write(`${runtime.scope}/producing-protocol.json`, parameters);
  transactions["03-funding"] = funding.toCBOR();
  const fundingHash = await submitTransaction(runtime, "03-funding", funding.toCBOR(), { present: createdOutputs(funding), absent: consumedInputs(funding) });
  runtime.reserved.add(referenceKey(fundingInput));
  runtime.reserved.add(referenceKey(failureCollateral));
  const alreadyWithdrawn = savedWithdrawal && (await runtime.lucid.transactionStatus(savedWithdrawal.hash)).status === "confirmed";
  const actual = alreadyWithdrawn ? [fundingInput, failureCollateral]
    : await provider.getUtxosByOutRef([fundingInput, failureCollateral]);
  const actualFunding = actual.find((utxo) => referenceKey(utxo) === referenceKey(fundingInput));
  const actualCollateral = actual.find((utxo) => referenceKey(utxo) === referenceKey(failureCollateral));
  if (!alreadyWithdrawn) {
    assert(actualFunding && actualCollateral, "Funding or withdrawal collateral output is not spendable.");
    assert.deepEqual(actualFunding.assets, fundingInput.assets);
    assert.deepEqual(actualCollateral.assets, failureCollateral.assets);
  }
  return { ...setup, testCase, mode, redeemer, argumentReferences, argumentIndexes, withdrawalReferences, argumentsHash,
    info, emulator, provider, lucid, parameters, evaluationOptions, budget, transactions,
    fundingHash, fundingInput: actualFunding ?? fundingInput, failureCollateral: actualCollateral ?? failureCollateral, withdrawal, feePasses };
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

export async function submitFailure(scenario: PreparedScenario, progress: (message: string) => void = () => {}) {
  const { testCase, scripts, provider, emulator, info, evaluationOptions, budget, withdrawalHash, rewardAddress,
    fundingInput, withdrawalReferences, argumentReferences, redeemer, failureCollateral, withdrawal: signed, parameters, walletAddress, transactions, runtime } = scenario;
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
    runtime.artifacts?.report(runtime.scope, { localEvaluation: { success: false, code: expected, declared: budget, consumed: evaluation.budget } });
    const rewardBefore = await provider.getRewardAccount(rewardAddress);
    let rejectionRule: string | undefined;
    if (runtime.network === "Custom") {
      assert(emulator);
      assert.throws(() => emulator.evaluateTx(fromHex(signed.toCBOR())), (error: unknown) => {
        assert(error instanceof PlutusScriptEvaluationError);
        assert.equal(error.scriptHash, withdrawalHash);
        assert.equal(error.redeemer?.tag, "Reward");
        assert.equal(error.redeemer.index, 0);
        assert.equal(error.code, expected);
        return true;
      });
      const ledgerBefore = toHex(emulator.getUtxosCbor());
      const rejected = emulator.submitTx(fromHex(signed.toCBOR()));
      assert.equal(rejected.isSuccess, false);
      assert.equal(rejected.errorRule, "ScriptFailure", rejected.error);
      assert.equal(toHex(emulator.getUtxosCbor()), ledgerBefore);
      assert.deepEqual(await provider.getRewardAccount(rewardAddress), rewardBefore);
      assert.equal(emulator.hasTx(failedHash), false);

      rejectionRule = rejected.errorRule;
    }

    // The saved envelope contains the final isValid=false flag and exact witnesses.
    const failedCbor = runtime.artifacts?.find(runtime.scope, "04-failed-withdrawal")?.cbor ?? invalidEnvelope(signed);
    transactions["04-failed-withdrawal"] = failedCbor;
    progress("Submitting the failed withdrawal and checking its collateral-only ledger change.");
    assert.equal(await submitTransaction(runtime, "04-failed-withdrawal", failedCbor, {
      present: [fundingInput, { txHash: failedHash, outputIndex: 0 }], absent: [failureCollateral],
    }), failedHash);
    const ordinary = await provider.getUtxosByOutRef([fundingInput]);
    assert.equal(ordinary.length, 1);
    assert(isEqualUTxO(ordinary[0]!, fundingInput));
    assert.deepEqual(ordinary[0]!.assets, fundingInput.assets);
    assert.deepEqual(await provider.getUtxosByOutRef([failureCollateral]), []);
    const [returnUtxo] = await provider.getUtxosByOutRef([{ txHash: failedHash, outputIndex: 0 }]);
    assert(returnUtxo);
    const charged = minimumCollateral(body.fee(), parameters.collateralPercentage);
    assert.equal(returnUtxo.address, walletAddress);
    assert.deepEqual(returnUtxo.assets, { lovelace: failureCollateral.assets.lovelace! - charged });
    assert.equal(returnUtxo.datum, undefined);
    assert.equal(returnUtxo.scriptRef, undefined);
    assert.deepEqual(await provider.getRewardAccount(rewardAddress), rewardBefore);
    assert.deepEqual(sortUTxOs(await provider.getUtxosByOutRef(argumentReferences), "Canonical"), sortUTxOs(argumentReferences, "Canonical"));
    if (runtime.artifacts?.manifest)
      runtime.artifacts.case(runtime.scope, { stage: "withdrawal-confirmed", failureReturn: outRef(returnUtxo) });
    const costModelData = CML.PlutusData.from_cbor_hex(Data.to(parameters.costModels.PlutusV3.map(BigInt)));
    const costModel = costModelData.to_canonical_cbor_hex();
    costModelData.free();
    const witness = new Constr(0, [
      body.fee(), inputReferences(body.inputs()).map(outRefData), invocation.builtinRedeemer,
      outRefData(failureCollateral), body.total_collateral()!,
      inputReferences(body.reference_inputs()).map(outRefData), invocation.redeemerEncoding, costModel,
    ]);
    return {
      failedHash, returnUtxo, witness,
      validation: {
        withdrawal: { scriptHash: withdrawalHash, code: expected, declared: invocation.declared, consumed: evaluation.budget },
        validFlagTrueRejected: rejectionRule, invalidFlagAccepted: true,
        localEvaluation: { code: expected, consumed: evaluation.budget },
        effectsObservedOn: runtime.network === "Custom" ? "emulator" : "chain",
        ordinaryInputsUnspent: [outRef(fundingInput)], referenceScriptsUnspent: true, argumentReferencesUnspent: true,
      },
      collateral: {
        input: outRef(failureCollateral), inputLovelace: failureCollateral.assets.lovelace,
        transactionFeeLovelace: body.fee(), percentage: parameters.collateralPercentage,
        minimumLovelace: charged, chargedLovelace: charged,
        return: { ...outRef(returnUtxo), lovelace: returnUtxo.assets.lovelace! },
      },
    };
  } finally {
    body.free(); transaction.free();
  }
}

export type FailureEvidence = Awaited<ReturnType<typeof submitFailure>>;

export async function buildProofMint(
  scenario: PreparedScenario,
  evidence: FailureEvidence,
  witness = evidence.witness,
  parametersInput?: UTxO,
) {
  await refreshProtocol(scenario.runtime);
  const { lucid, parameters } = scenario.runtime;
  const { provider, parametersUnit, parametersAddress, policyId, walletAddress, mintReference, mintCollateral, argumentReferences } = scenario;
  const configuration = parametersInput ?? (await provider.getUtxosWithUnit(parametersAddress, parametersUnit))[0];
  assert(configuration, "Missing live parameters NFT.");
  assert.deepEqual(sortUTxOs(await provider.getUtxosByOutRef(argumentReferences), "Canonical"), sortUTxOs(argumentReferences, "Canonical"),
    "Original argument references are unavailable or changed.");
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

export async function recordProofBundle(runtime: Runtime, cbor: string) {
  const signed = savedSigned(cbor);
  recordResources(runtime, "05-mint", cbor, signed.toHash(), true);
  assert(runtime.proofBundle, "Missing consolidated proof bundle.");
  const [actual] = await runtime.provider.getUtxosByOutRef([runtime.proofBundle]);
  assert(actual, "Proof bundle is no longer spendable.");
  assert.deepEqual(actual.assets, runtime.proofBundle.assets, "Proof bundle tokens changed.");
  completeCase(runtime);
  return actual;
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

export async function runScenario(scripts: Validators, testCase: BuiltinCase, mode: ArgumentMode, progress: (message: string) => void = () => {}, sharedSetup?: BuiltinSetup) {
  const scenario = await prepareScenario(scripts, testCase, mode, progress, sharedSetup);
  const { runtime, emulator, provider, transactions, walletAddress, referenceAddress, rewardAddress, withdrawalHash, policyId,
    withdrawalReference, mintReference, mintCollateral, references, fundingInput, deploymentHash, setupHash, failureCollateral,
    parametersInput, parametersUnit, parametersPolicy, parametersAddress, parametersReference, signers, threshold, budget, withdrawal, parameters,
    argumentReferences, argumentIndexes, withdrawalReferences, argumentsHash, redeemer } = scenario;
  const invocationTransaction = CML.Transaction.from_cbor_hex(withdrawal.toCBOR());
  const invocation = inspectWithdrawalRedeemer(invocationTransaction, redeemer, withdrawalReferences);
  invocationTransaction.free();
  const protectedReferences = [...references, ...argumentReferences]
    .filter((reference) => !runtime.resources[referenceKey(reference)]?.consumedBy);
  const commonReport = {
    network: runtime.network, mode, evaluation: "local-scalus@1.3.0",
    protocolParameters: parameters, walletAddress, referenceAddress,
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
  runtime.artifacts?.report(runtime.scope, { ...commonReport, status: "prepared" });
  if (testCase.outcome === "success") {
    progress("Submitting the successful withdrawal and checking that no failure evidence exists.");
    const evaluations = await localEvaluator(parameters).evaluate({
      tx: withdrawal.toCBOR(), additionalUTxOs: [fundingInput, ...withdrawalReferences],
      context: { network: runtime.network, slotConfig: runtime.slotConfig,
        protocolParameters: parameters, costModels: runtime.lucid.config().costModels! },
    });
    assert.equal(evaluations.length, 1);
    const evaluation = evaluations[0]!;
    assert.equal(evaluation.redeemer_tag, "withdraw");
    assert.equal(evaluation.redeemer_index, 0);
    assert(evaluation.ex_units.mem <= budget.memory && evaluation.ex_units.steps <= budget.steps);
    runtime.artifacts?.report(runtime.scope, { localEvaluation: { success: true, declared: budget, consumed: evaluation.ex_units } });
    transactions["04-successful-withdrawal"] = withdrawal.toCBOR();
    const hash = await submitTransaction(runtime, "04-successful-withdrawal", withdrawal.toCBOR(), {
      present: [failureCollateral], absent: [fundingInput],
    });
    assert.deepEqual(await provider.getUtxosByOutRef([fundingInput]), []);
    const collateralNow = await provider.getUtxosByOutRef([failureCollateral]);
    assert.equal(collateralNow.length, 1);
    assert(isEqualUTxO(collateralNow[0]!, failureCollateral));
    assert.deepEqual(collateralNow[0]!.assets, failureCollateral.assets);
    assert.deepEqual(await provider.getUtxosByOutRef([{ txHash: hash, outputIndex: 0 }]), []);
    assert.deepEqual(await provider.getUtxosWithUnit(walletAddress, toUnit(policyId, hash)), []);
    assert.deepEqual(sortUTxOs(await provider.getUtxosByOutRef(protectedReferences), "Canonical"), sortUTxOs(protectedReferences, "Canonical"));
    assert.deepEqual(await provider.getUtxosWithUnit(parametersAddress, parametersUnit), [parametersInput]);
    assert.deepEqual(await provider.getUtxosByOutRef([mintCollateral]), [mintCollateral]);
    completeCase(runtime);
    const cleanup = runtime.network === "Custom" ? await cleanupRun(runtime) : undefined;
    Object.assign(transactions, cleanup?.transactions);
    return {
      report: { ...commonReport, cleanup: cleanup?.checkpoint, resourcesReleased: argumentReferences.map(outRef),
        effectsObservedOn: runtime.network === "Custom" ? "emulator" : "chain", outcome: "success" as const,
        transactions: { deployment: deploymentHash, setup: setupHash, arguments: argumentsHash, funding: scenario.fundingHash, withdrawal: hash },
        validation: { withdrawal: { success: true, declared: budget, consumed: { memory: BigInt(evaluation.ex_units.mem), steps: BigInt(evaluation.ex_units.steps) } },
          ordinaryInputsConsumed: true, referenceScriptsUnspent: true, argumentReferencesUnspent: true },
        collateral: { input: outRef(failureCollateral), unspent: true, returnCreated: false,
          releasedToFunding: true }, nft: null },
      transactions,
    };
  }
  const evidence = await submitFailure(scenario, progress);
  runtime.artifacts?.report(runtime.scope, { validation: evidence.validation, collateral: evidence.collateral, failedHash: evidence.failedHash, status: "withdrawal-confirmed" });
  const unit = toUnit(policyId, evidence.failedHash);
  progress("Consuming collateral return and referencing live parameters to mint the proof.");
  const savedMint = runtime.artifacts?.find(runtime.scope, "05-mint");
  const signedMint = savedMint ? savedSigned(savedMint.cbor) : await (async () => {
    const mint = await buildProofMint(scenario, evidence);
    return mint.sign.withWallet().complete();
  })();
  const mintTransaction = CML.Transaction.from_cbor_hex(signedMint.toCBOR());
  const mintBody = mintTransaction.body();
  try {
    assert.deepEqual(inputReferences(mintBody.collateral_inputs()), [outRef(mintCollateral)]);
    assert.equal(mintBody.total_collateral(), minimumCollateral(mintBody.fee(), runtime.parameters.collateralPercentage));
  } finally { mintBody.free(); mintTransaction.free(); }
  transactions["05-mint"] = signedMint.toCBOR();
  const mintHash = await submitTransaction(runtime, "05-mint", signedMint.toCBOR(), {
    present: createdOutputs(signedMint), absent: consumedInputs(signedMint),
  });
  const proofBundle = await recordProofBundle(runtime, signedMint.toCBOR());
  assert.deepEqual(await provider.getUtxosByOutRef([evidence.returnUtxo]), []);
  const [nft] = await provider.getUtxosWithUnit(walletAddress, unit);
  assert(nft);
  assert.equal(nft.address, walletAddress);
  assert.equal(nft.txHash, mintHash);
  assert.equal(nft.assets[unit], 1n);
  if (runtime.network === "Custom") {
    assert(emulator);
    const proofs = emulator.getUtxos().flatMap((u) => u.value.assets).filter((a) => a.policyId === policyId);
    assert.equal(proofs.length, 1);
    assert.equal(proofs[0]!.assetName, evidence.failedHash);
    assert.equal(proofs[0]!.quantity, 1n);
  }
  assert.deepEqual(sortUTxOs(await provider.getUtxosByOutRef(protectedReferences), "Canonical"), sortUTxOs(protectedReferences, "Canonical"));
  const ordinary = await provider.getUtxosByOutRef([fundingInput]);
  assert.equal(ordinary.length, 1);
  assert(isEqualUTxO(ordinary[0]!, fundingInput));
  assert.deepEqual(ordinary[0]!.assets, fundingInput.assets);
  assert.deepEqual(await provider.getUtxosByOutRef([mintCollateral]), [mintCollateral]);
  assert.deepEqual(await provider.getUtxosWithUnit(parametersAddress, parametersUnit), [parametersInput]);
  runtime.reserved.delete(referenceKey(fundingInput));
  const cleanup = runtime.network === "Custom" ? await cleanupRun(runtime) : undefined;
  Object.assign(transactions, cleanup?.transactions);
  return {
    report: { ...commonReport, cleanup: cleanup?.checkpoint, resourcesReleased: argumentReferences.map(outRef),
      effectsObservedOn: runtime.network === "Custom" ? "emulator" : "chain", outcome: testCase.outcome,
      transactions: { deployment: deploymentHash, setup: setupHash, arguments: argumentsHash, funding: scenario.fundingHash, failed: evidence.failedHash, mint: mintHash,
        setupBatches: runtime.artifacts?.records.filter((record) => record.scope === "setup" && /^\d+-setup-\d+$/.test(record.name)).map((record) => record.hash) },
      validation: evidence.validation, collateral: { ...evidence.collateral, returnSpentBy: mintHash,
        proofBundle: outRef(proofBundle) },
      nft: { policyId, assetName: evidence.failedHash, unit, quantity: 1n, output: outRef(nft) } },
    transactions,
  };
}
