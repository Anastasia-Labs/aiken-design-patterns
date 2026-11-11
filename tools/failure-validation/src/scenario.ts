import assert from "node:assert/strict";
import { Cbor, CborArray, CborMap, CborUInt } from "@harmoniclabs/cbor";
import {
  CML, Constr, Data, Lucid, ScriptContextData, applyParamsToScript, credentialToAddress,
  fromHex, fromText, makeScriptContext, sortUTxOs, toHex, toUnit,
  validatorToAddress, validatorToRewardAddress, validatorToScriptHash,
  type EvaluatorAdapter, type Script, type TxSigned, type UTxO,
} from "@lucid-evolution/lucid";
import { CardanoInfo, Emulator, EvaluationOptions, PlutusScriptEvaluationError, Utxo, Value, evaluator } from "scalus";
import type { Validators } from "./blueprint.ts";
import { WITHDRAWAL_RESULTS, type BuiltinCase } from "./builtins.ts";
import { ScalusProvider } from "./scalus-provider.ts";
import {
  completeWithMinimumCollateral, finalizeWithdrawal, inputReferences, minimumCollateral,
  minimumFee, outRef, outRefData, type Budget,
} from "./transactions.ts";

const ADA = 1_000_000n;
const NETWORK = "Preview";
const PARAMETERS_NAME = fromText("FAILURE_PARAMETERS");

function testKey(seed: number) {
  // Public, deterministic keys for in-memory balances only.
  const privateKey = CML.PrivateKey.from_normal_bytes(new Uint8Array(32).fill(seed));
  const publicKey = privateKey.to_public();
  const hash = publicKey.hash();
  try {
    return { key: privateKey.to_bech32(), hash: hash.to_hex() };
  } finally {
    hash.free();
    publicKey.free();
    privateKey.free();
  }
}

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

export async function prepareScenario(
  scripts: Validators,
  testCase: BuiltinCase,
  progress: (message: string) => void = () => {},
) {
  const info = CardanoInfo.preview();
  const emulator = Emulator.create(info, { slot: 1_000_000 });
  const provider = new ScalusProvider(emulator);
  const lucid = await Lucid(provider, NETWORK, { slotConfig: info.slotConfig });
  const parameters = await provider.getProtocolParameters();
  const budget = { memory: parameters.maxTxExMem, steps: parameters.maxTxExSteps };
  const evaluationOptions = EvaluationOptions.fromProtocolParams("PlutusV3", info.protocolParams);
  const actor = testKey(1);
  const signers = [actor, testKey(3), testKey(4)];
  const threshold = 2;
  lucid.selectWallet.fromPrivateKey(actor.key);
  const walletAddress = await lucid.wallet().address();
  const referenceAddress = credentialToAddress(NETWORK, { type: "Key", hash: testKey(2).hash });
  const nonce = { txHash: "00".repeat(32), outputIndex: 1 };
  emulator.addUtxo(new Utxo(nonce.txHash, 0, walletAddress, Value.ada(998n)));
  emulator.addUtxo(new Utxo(nonce.txHash, 1, walletAddress, Value.ada(2n)));
  const [deploymentFunding] = await provider.getUtxosByOutRef([{ ...nonce, outputIndex: 0 }]);
  const [bootstrapInput] = await provider.getUtxosByOutRef([nonce]);
  assert(deploymentFunding && bootstrapInput);

  const withdrawalHash = validatorToScriptHash(scripts.withdrawal);
  const rewardAddress = validatorToRewardAddress(NETWORK, scripts.withdrawal);
  const parametersScript: Script = {
    ...scripts.parameters,
    script: applyParamsToScript(scripts.parameters.script, [outRefData(nonce), signers.map(({ hash }) => hash), BigInt(threshold)]),
  };
  const parametersPolicy = validatorToScriptHash(parametersScript);
  const parametersAddress = validatorToAddress(NETWORK, parametersScript);
  const parametersUnit = toUnit(parametersPolicy, PARAMETERS_NAME);
  const mintScript: Script = {
    ...scripts.mint,
    script: applyParamsToScript(scripts.mint.script, [withdrawalHash, parametersPolicy]),
  };
  const policyId = validatorToScriptHash(mintScript);
  const transactions: Record<string, string> = {};

  progress("Deploying the withdrawal, parameters, and proof reference scripts.");
  const deployment = await lucid.newTx()
    .collectFrom([deploymentFunding])
    .pay.ToAddressWithData(referenceAddress, undefined, { lovelace: 5n * ADA }, scripts.withdrawal)
    .pay.ToAddressWithData(referenceAddress, undefined, { lovelace: 5n * ADA }, parametersScript)
    .pay.ToAddressWithData(referenceAddress, undefined, { lovelace: 5n * ADA }, mintScript)
    .pay.ToAddress(walletAddress, { lovelace: 100n * ADA })
    .pay.ToAddress(walletAddress, { lovelace: 100n * ADA })
    .complete({ coinSelection: false });
  const signedDeployment = await deployment.sign.withWallet().complete();
  transactions["01-deployment"] = signedDeployment.toCBOR();
  const deploymentHash = await signedDeployment.submit();
  const references = await provider.getUtxos(referenceAddress);
  assert.equal(references.length, 3);
  const referenceFor = (hash: string) => {
    const found = references.filter((u) => u.scriptRef && validatorToScriptHash(u.scriptRef) === hash);
    assert.equal(found.length, 1);
    return found[0]!;
  };
  const withdrawalReference = referenceFor(withdrawalHash);
  const parametersReference = referenceFor(parametersPolicy);
  const mintReference = referenceFor(policyId);
  const walletUtxos = (await provider.getUtxos(walletAddress)).filter((u) => u.txHash === deploymentHash);
  const collateralUtxos = walletUtxos.filter((u) => u.assets.lovelace === 100n * ADA).sort((a, b) => a.outputIndex - b.outputIndex);
  assert.equal(collateralUtxos.length, 2);
  const [failureCollateral, mintCollateral] = collateralUtxos;
  assert(failureCollateral && mintCollateral);
  const setupFunding = walletUtxos.filter((u) => u.assets.lovelace !== 100n * ADA);
  assert.equal(setupFunding.length, 1);

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
        const result = evaluator.evaluateScript(scripts.withdrawal.script, [Data.to(scriptContext, ScriptContextData)], {
          ...evaluationOptions, maxBudget: budget,
        });
        assert.equal(result.isSuccess, expected === "success", result.error?.message);
        if (expected !== "success") assert.equal(result.error?.code, expected);
        assert(result.budget.memory <= budget.memory && result.budget.steps <= budget.steps);
        return [{ redeemer_tag: "withdraw", redeemer_index: 0, ex_units: { mem: Number(budget.memory), steps: Number(budget.steps) } }];
      } finally {
        transaction.free();
      }
    },
  };

  // This input exists only in the local draft. The submitted transaction uses
  // output zero of the real setup transaction, funded with its exact minimum fee.
  const draftInput: UTxO = { txHash: "fe".repeat(32), outputIndex: 0, address: walletAddress, assets: { lovelace: 5n * ADA } };
  const templateBuilder = await lucid.newTx()
    .collectFrom([draftInput])
    .readFrom([withdrawalReference])
    .withdraw(rewardAddress, 0n, testCase.redeemer)
    .setMinFee(draftInput.assets.lovelace!)
    .complete({ coinSelection: false, presetWalletInputs: [failureCollateral], setCollateral: 0n, evaluator: prescribedBudget, canonical: true });
  const template = CML.Transaction.from_cbor_hex(templateBuilder.toCBOR());
  let fee = draftInput.assets.lovelace!;
  let ready: { setup: TxSigned; withdrawal: TxSigned; fundingInput: UTxO; feePasses: number } | undefined;
  progress("Calculating the minimum fee before bootstrapping parameters, registering, and funding the invocation.");
  try {
    for (let attempt = 0; attempt < 8; attempt++) {
      const setup = await completeWithMinimumCollateral(parameters.collateralPercentage, (collateral) =>
        lucid.newTx()
          .collectFrom([...setupFunding, bootstrapInput])
          .readFrom([withdrawalReference, parametersReference])
          .register.Stake(rewardAddress, Data.void())
          .mintAssets({ [parametersUnit]: 1n }, Data.to(1n))
          .pay.ToAddress(walletAddress, { lovelace: fee })
          .pay.ToContract(parametersAddress, { kind: "inline", value: parametersDatum(budget) }, { lovelace: 5n * ADA, [parametersUnit]: 1n })
          .complete({ coinSelection: false, presetWalletInputs: [mintCollateral], localUPLCEval: false, setCollateral: collateral }),
      );
      const signedSetup = await setup.sign.withWallet().complete();
      const fundingInput: UTxO = { txHash: signedSetup.toHash(), outputIndex: 0, address: walletAddress, assets: { lovelace: fee } };
      const finalized = finalizeWithdrawal(template, fundingInput, fee, failureCollateral, parameters.collateralPercentage, walletAddress);
      let withdrawal: TxSigned;
      try {
        withdrawal = await lucid.fromTx(finalized.to_cbor_hex()).sign.withWallet().complete();
      } finally {
        finalized.free();
      }
      const required = minimumFee(withdrawal.toTransaction(), parameters, [scripts.withdrawal]);
      if (fee === required) {
        ready = { setup: signedSetup, withdrawal, fundingInput, feePasses: attempt + 1 };
        break;
      }
      fee = required;
    }
  } finally {
    template.free();
  }
  assert(ready, "Producing fee and funding did not converge after 8 builds; no setup transaction was submitted.");
  const { setup, withdrawal, fundingInput, feePasses } = ready;
  assertWithdrawalBody(withdrawal.toTransaction(), fundingInput, failureCollateral, withdrawalReference, parameters, scripts.withdrawal, budget, testCase.redeemer);
  const setupBody = setup.toTransaction().body();
  const setupOutputs = setupBody.outputs();
  const fundingOutput = setupOutputs.get(0);
  const fundingValue = fundingOutput.amount();
  const fundingAddress = fundingOutput.address();
  try {
    assert.equal(fundingValue.coin(), fee);
    assert.equal(fundingAddress.to_bech32(), walletAddress);
  } finally {
    fundingAddress.free(); fundingValue.free(); fundingOutput.free(); setupOutputs.free(); setupBody.free();
  }
  transactions["02-parameters-registration-and-funding"] = setup.toCBOR();
  const setupHash = await setup.submit();
  assert.equal((await provider.getRewardAccount(rewardAddress)).registered, true);
  const [actualFunding] = await provider.getUtxosByOutRef([fundingInput]);
  assert(actualFunding);
  assert.equal(actualFunding.address, fundingInput.address);
  assert.deepEqual(actualFunding.assets, fundingInput.assets);
  assert.equal(actualFunding.datum, undefined);
  assert.equal(actualFunding.scriptRef, undefined);
  assert.deepEqual(await provider.getUtxosByOutRef([nonce]), []);
  const parametersInput = await provider.getUtxoByUnit(parametersUnit);
  assert.deepEqual(readParameters(parametersInput), budget);
  assert.equal(parametersInput.address, parametersAddress);
  assert.deepEqual(parametersInput.assets, { lovelace: 5n * ADA, [parametersUnit]: 1n });

  return {
    scripts, testCase, info, emulator, provider, lucid, parameters, evaluationOptions, budget,
    walletAddress, referenceAddress, rewardAddress, withdrawalHash, policyId,
    parametersScript, parametersPolicy, parametersAddress, parametersUnit, parametersInput, nonce, signers, threshold,
    references, withdrawalReference, parametersReference, mintReference, failureCollateral, mintCollateral,
    transactions, deploymentHash, setupHash, fundingInput: actualFunding, withdrawal, feePasses,
  };
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
    try { assert.equal(reward.to_bech32(), validatorToRewardAddress(NETWORK, script)); } finally { reward.free(); }
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
    fundingInput, withdrawalReference, failureCollateral, withdrawal: signed, parameters, walletAddress, transactions } = scenario;
  assert(testCase.outcome !== "success", "Expected a failure case.");
  const expected = WITHDRAWAL_RESULTS[testCase.outcome];
  const transaction = signed.toTransaction();
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
    assert.throws(() => emulator.evaluateTx(fromHex(signed.toCBOR())), (error: unknown) => {
      assert(error instanceof PlutusScriptEvaluationError);
      assert.equal(error.scriptHash, withdrawalHash);
      assert.equal(error.redeemer?.tag, "Reward");
      assert.equal(error.redeemer.index, 0);
      assert.equal(error.code, expected);
      return true;
    });
    const ledgerBefore = toHex(emulator.getUtxosCbor());
    const rewardBefore = await provider.getRewardAccount(rewardAddress);
    const rejected = emulator.submitTx(fromHex(signed.toCBOR()));
    assert.equal(rejected.isSuccess, false);
    assert.equal(rejected.errorRule, "ScriptFailure", rejected.error);
    assert.equal(toHex(emulator.getUtxosCbor()), ledgerBefore);
    assert.deepEqual(await provider.getRewardAccount(rewardAddress), rewardBefore);
    assert.equal(emulator.hasTx(failedHash), false);

    // Lucid signs with isValid=true. Only the envelope flag changes afterwards;
    // the body and witnesses, including their signatures, stay byte-identical.
    const witnesses = transaction.witness_set();
    const invalid = CML.Transaction.new(body, witnesses, false);
    const invalidBody = invalid.body();
    const invalidWitnesses = invalid.witness_set();
    let failedCbor: string;
    try {
      assert.equal(invalidBody.to_cbor_hex(), body.to_cbor_hex());
      assert.equal(invalidWitnesses.to_cbor_hex(), witnesses.to_cbor_hex());
      failedCbor = invalid.to_cbor_hex();
    } finally {
      invalidWitnesses.free(); invalidBody.free(); invalid.free(); witnesses.free();
    }
    transactions["03-failed-withdrawal"] = failedCbor;
    progress("Submitting the failed withdrawal and checking its collateral-only ledger change.");
    assert.equal(await provider.submitTx(failedCbor), failedHash);
    assert.deepEqual(await provider.getUtxosByOutRef([fundingInput]), [fundingInput]);
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
        validFlagTrueRejected: rejected.errorRule, invalidFlagAccepted: true,
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
    body.free();
  }
}

export type FailureEvidence = Awaited<ReturnType<typeof submitFailure>>;

export async function buildProofMint(
  scenario: PreparedScenario,
  evidence: FailureEvidence,
  witness = evidence.witness,
  parametersInput?: UTxO,
) {
  const { lucid, provider, parameters, parametersUnit, policyId, walletAddress, mintReference, mintCollateral } = scenario;
  const configuration = parametersInput ?? await provider.getUtxoByUnit(parametersUnit);
  const references = sortUTxOs([mintReference, configuration], "Canonical");
  const inputs = sortUTxOs([evidence.returnUtxo], "Canonical");
  const unit = toUnit(policyId, evidence.failedHash);
  const redeemer = Data.to(new Constr(0, [BigInt(inputs.indexOf(evidence.returnUtxo)), BigInt(references.indexOf(configuration)), witness]));
  const completed = await completeWithMinimumCollateral(parameters.collateralPercentage, (collateral) =>
    lucid.newTx().collectFrom(inputs).readFrom(references)
      .mintAssets({ [unit]: 1n }, redeemer)
      .pay.ToAddress(walletAddress, { lovelace: 5n * ADA, [unit]: 1n })
      .complete({ coinSelection: false, presetWalletInputs: [mintCollateral], localUPLCEval: false, setCollateral: collateral }),
  );
  const body = completed.toTransaction().body();
  try {
    assert.deepEqual(inputReferences(body.inputs()), inputs.map(outRef));
    assert.deepEqual(inputReferences(body.reference_inputs()), references.map(outRef));
  } finally { body.free(); }
  return completed;
}

export async function updateParameters(scenario: PreparedScenario, budget: Budget, signerIndices = [0, 1]) {
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
    return tx.complete({ coinSelection: false, presetWalletInputs: [mintCollateral], localUPLCEval: false, setCollateral: collateral });
  });
  completed.sign.withWallet();
  for (const signer of selected) completed.sign.withPrivateKey(signer.key);
  const signed = await completed.complete();
  const hash = await signed.submit();
  const updated = await provider.getUtxoByUnit(parametersUnit);
  assert.equal(updated.txHash, hash);
  assert.deepEqual(readParameters(updated), budget);
  assert.deepEqual(updated.assets, current.assets);
  assert.deepEqual(await provider.getUtxosByOutRef([current]), []);
  return updated;
}

export async function runScenario(scripts: Validators, testCase: BuiltinCase, progress: (message: string) => void = () => {}) {
  const scenario = await prepareScenario(scripts, testCase, progress);
  const { emulator, provider, transactions, walletAddress, referenceAddress, rewardAddress, withdrawalHash, policyId,
    withdrawalReference, mintReference, mintCollateral, references, fundingInput, deploymentHash, setupHash, failureCollateral,
    parametersInput, parametersUnit, parametersPolicy, parametersAddress, parametersReference, signers, threshold, budget, withdrawal, parameters } = scenario;
  const invocation = inspectWithdrawalRedeemer(withdrawal.toTransaction(), testCase.redeemer);
  const commonReport = {
    network: NETWORK, emulator: "scalus@1.3.0", walletAddress, referenceAddress,
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
  if (testCase.outcome === "success") {
    progress("Submitting the successful withdrawal and checking that no failure evidence exists.");
    const evaluations = emulator.evaluateTx(fromHex(withdrawal.toCBOR()));
    assert.equal(evaluations.length, 1);
    const evaluation = evaluations[0]!;
    assert.equal(evaluation.tag, "Reward");
    assert.equal(evaluation.index, 0);
    assert(evaluation.budget.memory <= budget.memory && evaluation.budget.steps <= budget.steps);
    transactions["03-successful-withdrawal"] = withdrawal.toCBOR();
    const hash = await withdrawal.submit();
    assert.deepEqual(await provider.getUtxosByOutRef([fundingInput]), []);
    assert.deepEqual(await provider.getUtxosByOutRef([failureCollateral]), [failureCollateral]);
    assert.deepEqual(await provider.getUtxosByOutRef([{ txHash: hash, outputIndex: 0 }]), []);
    assert.equal(emulator.getUtxos().flatMap((u) => u.value.assets).filter((a) => a.policyId === policyId).length, 0);
    assert.deepEqual(await provider.getUtxos(referenceAddress), references);
    assert.deepEqual(await provider.getUtxoByUnit(parametersUnit), parametersInput);
    assert.deepEqual(await provider.getUtxosByOutRef([mintCollateral]), [mintCollateral]);
    assert.equal(emulator.getAppliedTxs().length, 3);
    return {
      report: { ...commonReport, outcome: "success" as const, transactions: { deployment: deploymentHash, setup: setupHash, withdrawal: hash },
        validation: { withdrawal: { success: true, declared: budget, consumed: evaluation.budget }, ordinaryInputsConsumed: true, referenceScriptsUnspent: true },
        collateral: { input: outRef(failureCollateral), unspent: true, returnCreated: false }, nft: null },
      transactions,
    };
  }
  const evidence = await submitFailure(scenario, progress);
  const unit = toUnit(policyId, evidence.failedHash);
  progress("Consuming collateral return and referencing live parameters to mint the proof.");
  const mint = await buildProofMint(scenario, evidence);
  const signedMint = await mint.sign.withWallet().complete();
  const mintBody = signedMint.toTransaction().body();
  try {
    assert.deepEqual(inputReferences(mintBody.collateral_inputs()), [outRef(mintCollateral)]);
    assert.equal(mintBody.total_collateral(), minimumCollateral(mintBody.fee(), parameters.collateralPercentage));
  } finally { mintBody.free(); }
  transactions["04-mint"] = signedMint.toCBOR();
  const mintHash = await signedMint.submit();
  assert.deepEqual(await provider.getUtxosByOutRef([evidence.returnUtxo]), []);
  const nft = await provider.getUtxoByUnit(unit);
  assert.equal(nft.address, walletAddress);
  assert.equal(nft.txHash, mintHash);
  assert.equal(nft.assets[unit], 1n);
  const proofs = emulator.getUtxos().flatMap((u) => u.value.assets).filter((a) => a.policyId === policyId);
  assert.equal(proofs.length, 1);
  assert.equal(proofs[0]!.assetName, evidence.failedHash);
  assert.equal(proofs[0]!.quantity, 1n);
  assert.deepEqual(await provider.getUtxos(referenceAddress), references);
  assert.deepEqual(await provider.getUtxosByOutRef([fundingInput]), [fundingInput]);
  assert.deepEqual(await provider.getUtxosByOutRef([mintCollateral]), [mintCollateral]);
  assert.deepEqual(await provider.getUtxoByUnit(parametersUnit), parametersInput);
  assert.equal(emulator.getAppliedTxs().length, 4);
  return {
    report: { ...commonReport, outcome: testCase.outcome,
      transactions: { deployment: deploymentHash, setup: setupHash, failed: evidence.failedHash, mint: mintHash },
      validation: evidence.validation, collateral: { ...evidence.collateral, returnSpentBy: mintHash },
      nft: { policyId, assetName: evidence.failedHash, unit, quantity: 1n, output: outRef(nft) } },
    transactions,
  };
}
