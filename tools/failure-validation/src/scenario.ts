import assert from "node:assert/strict";
import { Cbor, CborArray, CborMap, CborUInt } from "@harmoniclabs/cbor";
import {
  CML, Constr, Data, ScriptContextData, applyParamsToScript,
  fromHex, fromText, isEqualUTxO, makeScriptContext, sortUTxOs, toHex, toUnit,
  validatorToAddress, validatorToRewardAddress, validatorToScriptHash,
  type EvaluatorAdapter, type Script, type TxSigned, type UTxO,
} from "@lucid-evolution/lucid";
import { PlutusScriptEvaluationError, evaluator } from "scalus";
import { restoreProtocol } from "./artifacts.ts";
import type { Validators } from "./blueprint.ts";
import { WITHDRAWAL_RESULTS, type BuiltinCase } from "./builtins.ts";
import { createRuntime, localEvaluator, ordinaryFunding, referenceKey, refreshProtocol, submitTransaction, type Runtime } from "./runtime.ts";
import {
  completeWithMinimumCollateral, finalizeWithdrawal, inputReferences, minimumCollateral,
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

export async function prepareBuiltin(scripts: Validators, runtime: Runtime, progress: (message: string) => void = () => {}) {
  assert.equal(scripts.networkTag, runtime.network === "Mainnet" ? 1 : 0, "Compile for the selected network before deployment.");
  await refreshProtocol(runtime);
  const { lucid, provider, walletAddress, referenceAddress, signers, threshold, network } = runtime;
  const checkpoint = runtime.artifacts?.manifest?.setup[scripts.builtin.name];
  const parameters = checkpoint?.protocol ? restoreProtocol(checkpoint.protocol) : runtime.parameters;
  const budget = { memory: parameters.maxTxExMem, steps: parameters.maxTxExSteps };
  const transactions: Record<string, string> = {};
  const savedSplit = runtime.artifacts?.find(runtime.scope, "00-prepare-wallet");
  if (savedSplit) {
    transactions[savedSplit.name] = savedSplit.cbor;
    await submitTransaction(runtime, savedSplit.name, savedSplit.cbor, savedSplit.effects);
  }
  let available = await ordinaryFunding(runtime);
  assert(available.length, "Fund the account-0 wallet with ADA before running.");
  // A wallet funded by a single output first needs a distinct bootstrap nonce.
  if (!checkpoint?.nonce && available.length === 1) {
    const split = await lucid.newTx().pay.ToAddress(walletAddress, { lovelace: 2n * ADA })
      .complete({ presetWalletInputs: available });
    const signed = await split.sign.withWallet().complete();
    transactions["00-prepare-wallet"] = signed.toCBOR();
    await submitTransaction(runtime, "00-prepare-wallet", signed.toCBOR(), { present: createdOutputs(signed), absent: consumedInputs(signed) });
    available = await ordinaryFunding(runtime);
  }
  const nonce = checkpoint?.nonce ?? outRef(available.at(-1)!);
  if (runtime.artifacts?.manifest && !checkpoint?.nonce) runtime.artifacts.setup(scripts.builtin.name, { nonce, protocol: runtime.parameters });
  const bootstrapInput = available.find((u) => referenceKey(u) === referenceKey(nonce));
  runtime.reserved.add(referenceKey(nonce));
  const deploymentFunding = available.filter((u) => referenceKey(u) !== referenceKey(nonce));
  const withdrawalHash = validatorToScriptHash(scripts.withdrawal);
  const rewardAddress = validatorToRewardAddress(network, scripts.withdrawal);
  const parametersScript: Script = {
    ...scripts.parameters,
    script: applyParamsToScript(scripts.parameters.script, [outRefData(nonce), signers.map(({ hash }) => hash), BigInt(threshold)]),
  };
  const parametersPolicy = validatorToScriptHash(parametersScript);
  const parametersAddress = validatorToAddress(network, parametersScript);
  const parametersUnit = toUnit(parametersPolicy, PARAMETERS_NAME);
  const mintScript: Script = { ...scripts.mint, script: applyParamsToScript(scripts.mint.script, [withdrawalHash, parametersPolicy]) };
  const policyId = validatorToScriptHash(mintScript);
  progress("Deploying the withdrawal, parameters, and proof reference scripts.");
  const savedDeployment = runtime.artifacts?.find(runtime.scope, "01-deployment");
  const signedDeployment = savedDeployment ? savedSigned(savedDeployment.cbor) : await (async () => {
    assert(deploymentFunding.length, "Need separate deployment funding and a bootstrap nonce.");
    const deployment = await lucid.newTx()
      .pay.ToAddressWithData(referenceAddress, undefined, { lovelace: 5n * ADA }, scripts.withdrawal)
      .pay.ToAddressWithData(referenceAddress, undefined, { lovelace: 5n * ADA }, parametersScript)
      .pay.ToAddressWithData(referenceAddress, undefined, { lovelace: 5n * ADA }, mintScript)
      .pay.ToAddress(walletAddress, { lovelace: 100n * ADA })
      .complete({ presetWalletInputs: deploymentFunding });
    return deployment.sign.withWallet().complete();
  })();
  transactions["01-deployment"] = signedDeployment.toCBOR();
  const deploymentHash = await submitTransaction(runtime, "01-deployment", signedDeployment.toCBOR(), {
    present: createdOutputs(signedDeployment), absent: consumedInputs(signedDeployment), addresses: [walletAddress, referenceAddress],
  });
  const references = (await provider.getUtxos(referenceAddress)).filter((u) => u.txHash === deploymentHash && u.scriptRef);
  assert.equal(references.length, 3);
  for (const reference of references) runtime.reserved.add(referenceKey(reference));
  const referenceFor = (hash: string) => {
    const found = references.filter((u) => u.scriptRef && validatorToScriptHash(u.scriptRef) === hash);
    assert.equal(found.length, 1); return found[0]!;
  };
  const withdrawalReference = referenceFor(withdrawalHash);
  const parametersReference = referenceFor(parametersPolicy);
  const mintReference = referenceFor(policyId);
  const [mintCollateral] = await provider.getUtxosByOutRef([{ txHash: deploymentHash, outputIndex: 3 }]);
  assert(mintCollateral);
  runtime.reserved.add(referenceKey(mintCollateral));
  const registered = checkpoint?.stakeAlreadyRegistered ?? (await provider.getRewardAccount(rewardAddress)).registered;
  if (runtime.artifacts?.manifest && checkpoint?.stakeAlreadyRegistered === undefined)
    runtime.artifacts.setup(scripts.builtin.name, { stakeAlreadyRegistered: registered });
  progress(registered ? "Bootstrapping parameters; the withdrawal credential is already registered." : "Bootstrapping parameters and registering the withdrawal credential.");
  const savedSetup = runtime.artifacts?.find(runtime.scope, "02-parameters-registration");
  const signedSetup = savedSetup ? savedSigned(savedSetup.cbor) : await (async () => {
    assert(bootstrapInput, "Bootstrap nonce is no longer spendable.");
    const setupFunding = await ordinaryFunding(runtime);
    assert(setupFunding.length, "No unreserved ADA funding remains for parameter bootstrap.");
    const setup = await completeWithMinimumCollateral(parameters.collateralPercentage, (collateral) => {
      const tx = lucid.newTx().collectFrom([bootstrapInput])
        .readFrom([withdrawalReference, parametersReference])
        .mintAssets({ [parametersUnit]: 1n }, Data.to(0n))
        .pay.ToContract(parametersAddress, { kind: "inline", value: parametersDatum(budget) }, { lovelace: 5n * ADA, [parametersUnit]: 1n });
      if (!registered) tx.register.Stake(rewardAddress, Data.void());
      return tx.complete({ presetWalletInputs: setupFunding, setCollateral: collateral });
    });
    return setup.sign.withWallet().complete();
  })();
  transactions["02-parameters-registration"] = signedSetup.toCBOR();
  const setupHash = await submitTransaction(runtime, "02-parameters-registration", signedSetup.toCBOR(), {
    present: createdOutputs(signedSetup), absent: consumedInputs(signedSetup),
    addresses: [walletAddress, parametersAddress], stakeRegistered: rewardAddress,
  });
  const [parametersInput] = await provider.getUtxosWithUnit(parametersAddress, parametersUnit);
  assert(parametersInput);
  assert.deepEqual(readParameters(parametersInput), budget);
  assert.deepEqual(parametersInput.assets, { lovelace: 5n * ADA, [parametersUnit]: 1n });
  if (runtime.artifacts?.manifest) runtime.artifacts.setup(scripts.builtin.name, { ready: true });
  const result = {
    runtime, scripts, walletAddress, referenceAddress, rewardAddress, withdrawalHash, policyId,
    parametersScript, parametersPolicy, parametersAddress, parametersUnit, parametersInput, nonce, signers, threshold,
    references, withdrawalReference, parametersReference, mintReference, mintCollateral,
    transactions, deploymentHash, setupHash, registered,
  };
  runtime.artifacts?.report(runtime.scope, {
    status: "ready", network, deploymentHash, setupHash, stakeAlreadyRegistered: registered,
    parametersUnit, parametersAddress, bootstrapNonce: nonce, budget, protocolParameters: parameters,
    authorizedSigners: signers.map(({ hash }) => hash), threshold, references: references.map(outRef),
  });
  return result;
}

export type BuiltinSetup = Awaited<ReturnType<typeof prepareBuiltin>>;

export async function prepareScenario(
  scripts: Validators,
  testCase: BuiltinCase,
  progress: (message: string) => void = () => {},
  sharedSetup?: BuiltinSetup,
) {
  const setup = sharedSetup ?? await prepareBuiltin(scripts, await createRuntime({ network: "Custom" }), progress);
  assert.equal(setup.scripts, scripts);
  const { runtime, withdrawalHash, rewardAddress, withdrawalReference, mintCollateral, walletAddress } = setup;
  if (runtime.artifacts) runtime.scope = `${scripts.builtin.name}/${testCase.name}`;
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
  const transactions: Record<string, string> = sharedSetup ? {} : { ...setup.transactions };
  const expected = WITHDRAWAL_RESULTS[testCase.outcome];
  const prescribedBudget: EvaluatorAdapter = {
    name: "configured-withdrawal-budget",
    async evaluate({ tx, additionalUTxOs, context }) {
      const transaction = CML.Transaction.from_cbor_hex(tx);
      try {
        inspectWithdrawalRedeemer(transaction, testCase.redeemer);
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
    body.free(); transaction.free();
    ready = {
      funding: savedSigned(savedFunding.cbor), withdrawal: signed,
      fundingInput: { txHash: savedFunding.hash, outputIndex: 0, address: walletAddress, assets: { lovelace: fee } },
      failureCollateral: { txHash: savedFunding.hash, outputIndex: 1, address: walletAddress, assets: { lovelace: 100n * ADA } },
      feePasses: checkpoint?.feePasses ?? 0,
    };
  } else {
    if (runtime.artifacts?.manifest) runtime.artifacts.case(scope, { protocol: parameters });
    const draftInput: UTxO = { txHash: "fe".repeat(32), outputIndex: 0, address: walletAddress, assets: { lovelace: 5n * ADA } };
    const templateBuilder = await lucid.newTx().collectFrom([draftInput]).readFrom([withdrawalReference])
      .withdraw(rewardAddress, 0n, testCase.redeemer).setMinFee(draftInput.assets.lovelace!)
      .complete({ coinSelection: false, presetWalletInputs: [mintCollateral], setCollateral: 0n, evaluator: prescribedBudget, canonical: true });
    const template = CML.Transaction.from_cbor_hex(templateBuilder.toCBOR());
    let fee = draftInput.assets.lovelace!;
    let built: typeof ready | undefined;
    const fundingSources = await ordinaryFunding(runtime);
    assert(fundingSources.length, "No unreserved ADA funding remains.");
    progress("Calculating the exact minimum fee and preparing separate invocation funding and collateral.");
    try {
      for (let attempt = 0; attempt < 8; attempt++) {
        const funding = await lucid.newTx()
          .pay.ToAddress(walletAddress, { lovelace: fee })
          .pay.ToAddress(walletAddress, { lovelace: 100n * ADA }).complete({ presetWalletInputs: fundingSources });
        const signedFunding = await funding.sign.withWallet().complete();
        const fundingInput: UTxO = { txHash: signedFunding.toHash(), outputIndex: 0, address: walletAddress, assets: { lovelace: fee } };
        const failureCollateral: UTxO = { ...fundingInput, outputIndex: 1, assets: { lovelace: 100n * ADA } };
        const finalized = finalizeWithdrawal(template, fundingInput, fee, failureCollateral, parameters.collateralPercentage, walletAddress);
        let withdrawal: TxSigned;
        runtime.wallet.overrideUTxOs([fundingInput, failureCollateral]);
        try { withdrawal = await lucid.fromTx(finalized.to_cbor_hex()).sign.withWallet().complete(); }
        finally { runtime.wallet.clearUTxOOverride?.(); finalized.free(); }
        const feeTransaction = CML.Transaction.from_cbor_hex(withdrawal.toCBOR());
        let required: bigint;
        try { required = minimumFee(feeTransaction, parameters, [scripts.withdrawal]); }
        finally { feeTransaction.free(); }
        if (fee === required) {
          built = { funding: signedFunding, withdrawal, fundingInput, failureCollateral, feePasses: attempt + 1 }; break;
        }
        fee = required;
      }
    } finally { template.free(); }
    assert(built, "Producing fee and funding did not converge after 8 builds; no funding transaction was submitted.");
    ready = built;
    if (runtime.artifacts?.manifest) runtime.artifacts.case(scope, { feePasses: ready.feePasses, stage: "prepared" });
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
  try { assertWithdrawalBody(checkedWithdrawal, fundingInput, failureCollateral, withdrawalReference, parameters, scripts.withdrawal, budget, testCase.redeemer, runtime.network); }
  finally { checkedWithdrawal.free(); }
  runtime.artifacts?.write(`${runtime.scope}/producing-protocol.json`, parameters);
  transactions["03-funding"] = funding.toCBOR();
  const fundingHash = await submitTransaction(runtime, "03-funding", funding.toCBOR(), { present: createdOutputs(funding), absent: consumedInputs(funding) });
  for (const input of [fundingInput, failureCollateral]) runtime.reserved.add(referenceKey(input));
  const alreadyWithdrawn = savedWithdrawal && (await runtime.lucid.transactionStatus(savedWithdrawal.hash)).status === "confirmed";
  const actual = alreadyWithdrawn ? [fundingInput, failureCollateral]
    : sortUTxOs(await provider.getUtxosByOutRef([fundingInput, failureCollateral]), "Canonical");
  if (!alreadyWithdrawn) {
    assert.deepEqual(actual.map(outRef), [outRef(fundingInput), outRef(failureCollateral)]);
    assert.deepEqual(actual[0]!.assets, fundingInput.assets);
    assert.deepEqual(actual[1]!.assets, failureCollateral.assets);
  }
  return { ...setup, testCase, info, emulator, provider, lucid, parameters, evaluationOptions, budget, transactions,
    fundingHash, fundingInput: actual[0]!, failureCollateral: actual[1]!, withdrawal, feePasses };
}

export type PreparedScenario = Awaited<ReturnType<typeof prepareScenario>>;

function inspectWithdrawalRedeemer(transaction: CML.Transaction, expectedArguments: string) {
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
    assert.deepEqual(Data.from(data.to_cbor_hex()), Data.from(expectedArguments));
    assert.equal(witnesses.plutus_datums(), undefined);
    return {
      declared: { memory: units.mem(), steps: units.steps() },
      builtinArguments: Data.from(data.to_cbor_hex()),
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
  reference: UTxO,
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
    assert.deepEqual(inputReferences(body.reference_inputs()), [outRef(reference)]);
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
    assert.equal(returnedAddress?.to_bech32(), funding.address);
    assert.equal(returned?.datum(), undefined);
    assert.equal(returned?.script_ref(), undefined);
    assert.deepEqual(inspectWithdrawalRedeemer(transaction, redeemer).declared, budget);
  } finally {
    returnedAddress?.free(); returnedValue?.free(); returned?.free(); account?.free(); accounts?.free(); withdrawals?.free(); body.free();
  }
}

export async function submitFailure(scenario: PreparedScenario, progress: (message: string) => void = () => {}) {
  const { testCase, scripts, provider, emulator, info, evaluationOptions, budget, withdrawalHash, rewardAddress,
    fundingInput, withdrawalReference, failureCollateral, withdrawal: signed, parameters, walletAddress, transactions, runtime } = scenario;
  assert(testCase.outcome !== "success", "Expected a failure case.");
  const expected = WITHDRAWAL_RESULTS[testCase.outcome];
  const transaction = CML.Transaction.from_cbor_hex(signed.toCBOR());
  const body = transaction.body();
  const failedHash = signed.toHash();
  try {
    const invocation = inspectWithdrawalRedeemer(transaction, testCase.redeemer);
    const context = makeScriptContext(transaction, { Rewarding: [{ ScriptCredential: [withdrawalHash] }] }, {
      resolvedInputs: [fundingInput, withdrawalReference], slotConfig: info.slotConfig,
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
    const costModelData = CML.PlutusData.from_cbor_hex(Data.to(parameters.costModels.PlutusV3.map(BigInt)));
    const costModel = costModelData.to_canonical_cbor_hex();
    costModelData.free();
    const witness = new Constr(0, [
      body.fee(), inputReferences(body.inputs()).map(outRefData), invocation.builtinArguments,
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
        ordinaryInputsUnspent: [outRef(fundingInput)], referenceScriptsUnspent: true,
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
  const { provider, parametersUnit, parametersAddress, policyId, walletAddress, mintReference, mintCollateral } = scenario;
  const configuration = parametersInput ?? (await provider.getUtxosWithUnit(parametersAddress, parametersUnit))[0];
  assert(configuration, "Missing live parameters NFT.");
  const references = sortUTxOs([mintReference, configuration], "Canonical");
  const inputs = sortUTxOs([evidence.returnUtxo], "Canonical");
  const unit = toUnit(policyId, evidence.failedHash);
  const redeemer = Data.to(new Constr(0, [BigInt(inputs.indexOf(evidence.returnUtxo)), BigInt(references.indexOf(configuration)), witness]));
  const completed = await completeWithMinimumCollateral(parameters.collateralPercentage, (collateral) =>
    lucid.newTx().collectFrom(inputs).readFrom(references)
      .mintAssets({ [unit]: 1n }, redeemer)
      .pay.ToAddress(walletAddress, { lovelace: 5n * ADA, [unit]: 1n })
      .complete({ coinSelection: false, presetWalletInputs: [mintCollateral], setCollateral: collateral }),
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

export async function runScenario(scripts: Validators, testCase: BuiltinCase, progress: (message: string) => void = () => {}, sharedSetup?: BuiltinSetup) {
  const scenario = await prepareScenario(scripts, testCase, progress, sharedSetup);
  const { runtime, emulator, provider, transactions, walletAddress, referenceAddress, rewardAddress, withdrawalHash, policyId,
    withdrawalReference, mintReference, mintCollateral, references, fundingInput, deploymentHash, setupHash, failureCollateral,
    parametersInput, parametersUnit, parametersPolicy, parametersAddress, parametersReference, signers, threshold, budget, withdrawal, parameters } = scenario;
  const invocationTransaction = CML.Transaction.from_cbor_hex(withdrawal.toCBOR());
  const invocation = inspectWithdrawalRedeemer(invocationTransaction, testCase.redeemer);
  invocationTransaction.free();
  const commonReport = {
    network: runtime.network, evaluation: "local-scalus@1.3.0",
    protocolParameters: parameters, walletAddress, referenceAddress,
    invocation: { builtin: scripts.builtin.name, case: testCase.name, arguments: invocation.builtinArguments, redeemer: invocation.redeemer, expectedOutcome: testCase.outcome },
    inputs: { ordinary: [outRef(fundingInput)] },
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
      tx: withdrawal.toCBOR(), additionalUTxOs: [fundingInput, withdrawalReference],
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
    assert.deepEqual(sortUTxOs(await provider.getUtxosByOutRef(references), "Canonical"), sortUTxOs(references, "Canonical"));
    assert.deepEqual(await provider.getUtxosWithUnit(parametersAddress, parametersUnit), [parametersInput]);
    assert.deepEqual(await provider.getUtxosByOutRef([mintCollateral]), [mintCollateral]);
    if (runtime.network === "Custom") { assert(emulator); assert.equal(emulator.getAppliedTxs().length, 4); }
    runtime.reserved.delete(referenceKey(failureCollateral));
    return {
      report: { ...commonReport, effectsObservedOn: runtime.network === "Custom" ? "emulator" : "chain", outcome: "success" as const,
        transactions: { deployment: deploymentHash, setup: setupHash, funding: scenario.fundingHash, withdrawal: hash },
        validation: { withdrawal: { success: true, declared: budget, consumed: { memory: BigInt(evaluation.ex_units.mem), steps: BigInt(evaluation.ex_units.steps) } }, ordinaryInputsConsumed: true, referenceScriptsUnspent: true },
        collateral: { input: outRef(failureCollateral), unspent: true, returnCreated: false }, nft: null },
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
    present: createdOutputs(signedMint), absent: [evidence.returnUtxo],
  });
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
  assert.deepEqual(sortUTxOs(await provider.getUtxosByOutRef(references), "Canonical"), sortUTxOs(references, "Canonical"));
  const ordinary = await provider.getUtxosByOutRef([fundingInput]);
  assert.equal(ordinary.length, 1);
  assert(isEqualUTxO(ordinary[0]!, fundingInput));
  assert.deepEqual(ordinary[0]!.assets, fundingInput.assets);
  assert.deepEqual(await provider.getUtxosByOutRef([mintCollateral]), [mintCollateral]);
  assert.deepEqual(await provider.getUtxosWithUnit(parametersAddress, parametersUnit), [parametersInput]);
  if (runtime.network === "Custom") { assert(emulator); assert.equal(emulator.getAppliedTxs().length, 5); }
  runtime.reserved.delete(referenceKey(fundingInput));
  return {
    report: { ...commonReport, effectsObservedOn: runtime.network === "Custom" ? "emulator" : "chain", outcome: testCase.outcome,
      transactions: { deployment: deploymentHash, setup: setupHash, funding: scenario.fundingHash, failed: evidence.failedHash, mint: mintHash },
      validation: evidence.validation, collateral: { ...evidence.collateral, returnSpentBy: mintHash },
      nft: { policyId, assetName: evidence.failedHash, unit, quantity: 1n, output: outRef(nft) } },
    transactions,
  };
}
