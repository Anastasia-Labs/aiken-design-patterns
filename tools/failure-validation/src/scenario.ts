import assert from "node:assert/strict";
import {
  CML,
  Constr,
  Data,
  Lucid,
  ScriptContextData,
  TxOutData,
  TxOutRefData,
  credentialToAddress,
  fromHex,
  makeScriptContext,
  toHex,
  toUnit,
  validatorToAddress,
  validatorToRewardAddress,
  validatorToScriptHash,
  type EvaluatorAdapter,
  type OutRef,
  type ScriptPurposeData,
  type TxSignBuilder,
  type UTxO,
} from "@lucid-evolution/lucid";
import {
  CardanoInfo,
  Emulator,
  EvaluationOptions,
  PlutusScriptEvaluationError,
  Utxo,
  Value,
  evaluator,
} from "scalus";
import type { Validators } from "./blueprint.ts";
import { ScalusProvider, toScalusUtxo } from "./scalus-provider.ts";

const ADA = 1_000_000n;
const UNIT = Data.void();
const NETWORK = "Preview";
const SPENDING_BUDGET = { memory: 50_000n, steps: 14_000_000n };
const MAXIMUM_BUDGET = { memory: 17_500_000n, steps: 10_000_000_000n };
const WITHDRAWAL_BUDGET = {
  memory: MAXIMUM_BUDGET.memory - SPENDING_BUDGET.memory,
  steps: MAXIMUM_BUDGET.steps - SPENDING_BUDGET.steps,
};

function inputReferences(inputs: CML.TransactionInputList | undefined): OutRef[] {
  if (!inputs) return [];
  try {
    return Array.from({ length: inputs.len() }, (_, index) => {
      const input = inputs.get(index);
      const hash = input.transaction_id();
      try {
        return { txHash: hash.to_hex(), outputIndex: Number(input.index()) };
      } finally {
        hash.free();
        input.free();
      }
    });
  } finally {
    inputs.free();
  }
}

function outRef({ txHash, outputIndex }: OutRef): OutRef {
  return { txHash, outputIndex };
}

async function completeWithMinimumCollateral(
  collateralPercentage: number,
  build: (collateral: bigint) => Promise<TxSignBuilder>,
): Promise<TxSignBuilder> {
  let collateral = 0n;
  // Adding collateral fields can change the final fee. Rebuild before signing
  // until the declared collateral matches the requirement of that final fee.
  for (let attempt = 0; attempt < 8; attempt++) {
    const completed = await build(collateral);
    const transaction = completed.toTransaction();
    const body = transaction.body();
    try {
      const required = (body.fee() * BigInt(collateralPercentage) + 99n) / 100n;
      assert(body.total_collateral() !== undefined, "Missing total collateral.");
      if (body.total_collateral() === required) return completed;
      collateral = required;
    } finally {
      body.free();
    }
    transaction.free();
  }
  throw new Error("Collateral and transaction fee did not converge after 8 builds.");
}

export async function runScenario(
  scripts: Validators,
  progress: (message: string) => void = () => {},
) {
  const info = CardanoInfo.preview();
  const emulator = Emulator.create(info, { slot: 1_000_000 });
  const provider = new ScalusProvider(emulator);
  const lucid = await Lucid(provider, NETWORK, { slotConfig: info.slotConfig });
  const parameters = await provider.getProtocolParameters();
  assert.equal(parameters.maxTxExMem, MAXIMUM_BUDGET.memory);
  assert.equal(parameters.maxTxExSteps, MAXIMUM_BUDGET.steps);

  // Public, deterministic test keys. Only the emulator is funded.
  const actorKey = CML.PrivateKey.from_normal_bytes(new Uint8Array(32).fill(1));
  const referenceKey = CML.PrivateKey.from_normal_bytes(new Uint8Array(32).fill(2));
  lucid.selectWallet.fromPrivateKey(actorKey.to_bech32());
  const referencePublicKey = referenceKey.to_public();
  const referenceKeyHash = referencePublicKey.hash();
  const referenceAddress = credentialToAddress(NETWORK, {
    type: "Key",
    hash: referenceKeyHash.to_hex(),
  });
  referenceKeyHash.free();
  referencePublicKey.free();
  referenceKey.free();
  actorKey.free();
  const walletAddress = await lucid.wallet().address();
  emulator.addUtxo(new Utxo("00".repeat(32), 0, walletAddress, Value.ada(1000n)));

  const spendHash = validatorToScriptHash(scripts.spend);
  const withdrawalHash = validatorToScriptHash(scripts.withdrawal);
  const policyId = validatorToScriptHash(scripts.mint);
  const spendAddress = validatorToAddress(NETWORK, scripts.spend);
  const rewardAddress = validatorToRewardAddress(NETWORK, scripts.withdrawal);
  const transactions: Record<string, string> = {};

  progress("Deploying three reference scripts to the dedicated wallet.");
  const deployment = await lucid.newTx()
    .pay.ToAddressWithData(referenceAddress, undefined, { lovelace: 5n * ADA }, scripts.spend)
    .pay.ToAddressWithData(referenceAddress, undefined, { lovelace: 5n * ADA }, scripts.withdrawal)
    .pay.ToAddressWithData(referenceAddress, undefined, { lovelace: 5n * ADA }, scripts.mint)
    .pay.ToAddress(walletAddress, { lovelace: 100n * ADA })
    .pay.ToAddress(walletAddress, { lovelace: 100n * ADA })
    .complete();
  const signedDeployment = await deployment.sign.withWallet().complete();
  transactions["01-deployment"] = signedDeployment.toCBOR();
  const deploymentHash = await signedDeployment.submit();

  const references = await provider.getUtxos(referenceAddress);
  assert.equal(references.length, 3);
  const referenceFor = (hash: string): UTxO => {
    const found = references.filter((u) => u.scriptRef && validatorToScriptHash(u.scriptRef) === hash);
    assert.equal(found.length, 1, `Expected one reference script for ${hash}.`);
    assert(found[0]);
    return found[0];
  };
  const spendReference = referenceFor(spendHash);
  const withdrawalReference = referenceFor(withdrawalHash);
  const mintReference = referenceFor(policyId);
  const walletUtxos = await provider.getUtxos(walletAddress);
  const collateralUtxos = walletUtxos
    .filter((u) => u.assets.lovelace === 100n * ADA)
    .sort((a, b) => a.outputIndex - b.outputIndex);
  assert.equal(collateralUtxos.length, 2);
  const [failureCollateral, mintCollateral] = collateralUtxos;
  assert(failureCollateral && mintCollateral);
  const setupFunding = walletUtxos.filter((u) => u.assets.lovelace !== 100n * ADA);
  assert.equal(setupFunding.length, 1);

  progress("Registering the withdrawal credential and funding the spending script.");
  const setup = await completeWithMinimumCollateral(parameters.collateralPercentage, (collateral) =>
    lucid.newTx()
      .collectFrom(setupFunding)
      .readFrom([withdrawalReference])
      .register.Stake(rewardAddress, UNIT)
      .pay.ToContract(spendAddress, { kind: "inline", value: UNIT }, { lovelace: 20n * ADA })
      .complete({ coinSelection: false, presetWalletInputs: [mintCollateral], localUPLCEval: false, setCollateral: collateral }),
  );
  const signedSetup = await setup.sign.withWallet().complete();
  transactions["02-registration-and-funding"] = signedSetup.toCBOR();
  const setupHash = await signedSetup.submit();
  assert.equal((await provider.getRewardAccount(rewardAddress)).registered, true);
  const scriptUtxos = await provider.getUtxos(spendAddress);
  assert.equal(scriptUtxos.length, 1);
  const scriptInput = scriptUtxos[0];
  assert(scriptInput);
  assert.equal(scriptInput.assets.lovelace, 20n * ADA);

  // Check each purpose within its allocation, then give Lucid the prescribed
  // budgets so fee/change balancing commits those exact values.
  const evaluationOptions = EvaluationOptions.fromProtocolParams("PlutusV3", info.protocolParams);
  const failureBudgets: EvaluatorAdapter = {
    name: "prescribed-withdrawal-failure-budgets",
    async evaluate({ tx, additionalUTxOs, context }) {
      const transaction = CML.Transaction.from_cbor_hex(tx);
      const witnesses = transaction.witness_set();
      const redeemers = witnesses.redeemers();
      const entries = redeemers?.to_flat_format();
      assert(entries, "Expected spend and withdrawal redeemers.");
      try {
        assert.equal(entries.len(), 2);
        return Array.from({ length: entries.len() }, (_, i) => {
          const key = entries.get(i);
          try {
            assert.equal(key.tag(), i === 0 ? CML.RedeemerTag.Spend : CML.RedeemerTag.Reward);
            assert.equal(key.index(), 0n);
            const budget = i === 0 ? SPENDING_BUDGET : WITHDRAWAL_BUDGET;
            const purpose: ScriptPurposeData = i === 0
              ? { Spending: [{ txOutRefId: scriptInput.txHash, txOutRefIdx: BigInt(scriptInput.outputIndex) }] }
              : { Rewarding: [{ ScriptCredential: [withdrawalHash] }] };
            const scriptContext = makeScriptContext(transaction, purpose, {
              resolvedInputs: additionalUTxOs,
              slotConfig: context.slotConfig,
            });
            const result = evaluator.evaluateScript(
              i === 0 ? scripts.spend.script : scripts.withdrawal.script,
              [Data.to(scriptContext, ScriptContextData)],
              {
                ...evaluationOptions,
                maxBudget: budget,
              },
            );
            assert.equal(result.isSuccess, i === 0, result.error?.message);
            if (i === 1) assert.equal(result.error?.code, "SCRIPT_FAILURE");
            return {
              redeemer_tag: i === 0 ? "spend" as const : "withdraw" as const,
              redeemer_index: Number(key.index()),
              ex_units: { mem: Number(budget.memory), steps: Number(budget.steps) },
            };
          } finally {
            key.free();
          }
        });
      } finally {
        entries.free();
        redeemers?.free();
        witnesses.free();
        transaction.free();
      }
    },
  };

  progress("Building the spend plus zero withdrawal and checking each validator.");
  const failing = await completeWithMinimumCollateral(parameters.collateralPercentage, (collateral) =>
    lucid.newTx()
      .collectFrom([scriptInput], Data.to(withdrawalHash))
      .readFrom([spendReference, withdrawalReference])
      .withdraw(rewardAddress, 0n, UNIT)
      .pay.ToAddress(walletAddress, { lovelace: 10n * ADA })
      .complete({
        coinSelection: false,
        presetWalletInputs: [failureCollateral],
        setCollateral: collateral,
        evaluator: failureBudgets,
      }),
  );
  const signedFailing = await failing.sign.withWallet().complete();
  const signedCore = signedFailing.toTransaction();
  const failedHash = signedFailing.toHash();
  const body = signedCore.body();
  const normalInputs = inputReferences(body.inputs());
  const collateralInputs = inputReferences(body.collateral_inputs());
  const failedReferenceInputs = inputReferences(body.reference_inputs());
  assert.deepEqual(normalInputs, [outRef(scriptInput)]);
  assert.deepEqual(collateralInputs, [outRef(failureCollateral)]);
  assert.deepEqual(
    failedReferenceInputs,
    [spendReference, withdrawalReference].map(outRef).sort((a, b) => a.outputIndex - b.outputIndex),
  );
  assert.equal(body.certs()?.len() ?? 0, 0);
  assert.equal(body.mint()?.keys().len() ?? 0, 0);
  const withdrawals = body.withdrawals();
  assert(withdrawals);
  const rewardAccounts = withdrawals.keys();
  assert.equal(rewardAccounts.len(), 1);
  const rewardAccount = rewardAccounts.get(0);
  assert.equal(rewardAccount.to_address().to_bech32(), rewardAddress);
  assert.equal(withdrawals.get(rewardAccount), 0n);
  rewardAccount.free();
  rewardAccounts.free();
  withdrawals.free();
  assert.equal(signedCore.witness_set().plutus_v3_scripts()?.len() ?? 0, 0);

  const spendContext = makeScriptContext(signedCore, {
    Spending: [{ txOutRefId: scriptInput.txHash, txOutRefIdx: BigInt(scriptInput.outputIndex) }],
  }, {
    resolvedInputs: [scriptInput, spendReference, withdrawalReference],
    slotConfig: info.slotConfig,
  });
  assert.deepEqual(
    [...spendContext.scriptContextTxInfo.txInfoRedeemers.keys()].map((p) => Object.keys(p)[0]),
    ["Spending", "Rewarding"],
  );
  const finalWitnesses = signedCore.witness_set();
  const finalRedeemers = finalWitnesses.redeemers();
  assert(finalRedeemers);
  const finalEntries = finalRedeemers.to_flat_format();
  assert.equal(finalEntries.len(), 2);
  const redeemerEncoding = new Constr(finalRedeemers.kind() === CML.RedeemersKind.ArrLegacyRedeemer ? 0 : 1, []);
  const finalWithdrawalRedeemer = finalEntries.get(1);
  const withdrawalRedeemerData = finalWithdrawalRedeemer.data();
  const withdrawalRedeemer = Data.from(withdrawalRedeemerData.to_cbor_hex());
  withdrawalRedeemerData.free();
  finalWithdrawalRedeemer.free();
  const declaredBudgets = Array.from({ length: finalEntries.len() }, (_, index) => {
    const redeemer = finalEntries.get(index);
    const units = redeemer.ex_units();
    try {
      assert.equal(redeemer.tag(), index === 0 ? CML.RedeemerTag.Spend : CML.RedeemerTag.Reward);
      assert.equal(redeemer.index(), 0n);
      return { memory: units.mem(), steps: units.steps() };
    } finally {
      units.free();
      redeemer.free();
    }
  });
  finalEntries.free();
  finalRedeemers.free();
  finalWitnesses.free();
  assert.deepEqual(declaredBudgets, [SPENDING_BUDGET, WITHDRAWAL_BUDGET]);
  const [spendBudget, withdrawalBudget] = declaredBudgets;
  assert(spendBudget && withdrawalBudget);
  const spendEvaluation = evaluator.evaluateScript(scripts.spend.script, [Data.to(spendContext, ScriptContextData)], {
    ...evaluationOptions,
    maxBudget: spendBudget,
  });
  assert(spendEvaluation.isSuccess, `Spending validator failed: ${spendEvaluation.error?.message}`);
  assert(spendEvaluation.budget.memory <= spendBudget.memory);
  assert(spendEvaluation.budget.steps <= spendBudget.steps);

  const withdrawalContext = makeScriptContext(signedCore, {
    Rewarding: [{ ScriptCredential: [withdrawalHash] }],
  }, {
    resolvedInputs: [scriptInput, spendReference, withdrawalReference],
    slotConfig: info.slotConfig,
  });
  const withdrawalEvaluation = evaluator.evaluateScript(scripts.withdrawal.script, [Data.to(withdrawalContext, ScriptContextData)], {
    ...evaluationOptions,
    maxBudget: withdrawalBudget,
  });
  assert.equal(withdrawalEvaluation.isSuccess, false);
  assert.equal(withdrawalEvaluation.error?.code, "SCRIPT_FAILURE");
  assert(withdrawalEvaluation.budget.memory <= withdrawalBudget.memory);
  assert(withdrawalEvaluation.budget.steps <= withdrawalBudget.steps);

  let withdrawalFailure: PlutusScriptEvaluationError | undefined;
  try {
    emulator.evaluateTx(fromHex(signedFailing.toCBOR()));
    assert.fail("The withdrawal unexpectedly succeeded.");
  } catch (error) {
    assert(error instanceof PlutusScriptEvaluationError, String(error));
    assert.equal(error.scriptHash, withdrawalHash);
    assert.equal(error.redeemer?.tag, "Reward");
    assert.equal(error.redeemer.index, 0);
    assert.equal(error.code, "SCRIPT_FAILURE");
    withdrawalFailure = error;
  }

  // Rejecting a phase-2 failure marked valid must leave the ledger unchanged.
  const beforeRejection = toHex(emulator.getUtxosCbor());
  const rewardBefore = await provider.getRewardAccount(rewardAddress);
  const rejected = emulator.submitTx(fromHex(signedFailing.toCBOR()));
  assert.equal(rejected.isSuccess, false);
  assert.equal(rejected.errorRule, "ScriptFailure", rejected.error);
  assert.equal(toHex(emulator.getUtxosCbor()), beforeRejection);
  assert.deepEqual(await provider.getRewardAccount(rewardAddress), rewardBefore);
  assert.equal(emulator.hasTx(failedHash), false);

  // Lucid 0.6.2 sets isValid=true when signing. Change only the envelope after
  // signing: signatures and the transaction ID cover the unchanged body.
  const invalid = CML.Transaction.new(body, signedCore.witness_set(), false, signedCore.auxiliary_data());
  const failedCbor = invalid.to_cbor_hex();
  assert.equal(invalid.is_valid(), false);
  assert.equal(invalid.body().to_cbor_hex(), body.to_cbor_hex());
  assert.equal(CML.hash_transaction(invalid.body()).to_hex(), failedHash);
  assert.equal(invalid.witness_set().to_cbor_hex(), signedCore.witness_set().to_cbor_hex());
  transactions["03-failed-spend"] = failedCbor;

  const collateralReturn = body.collateral_return();
  assert(collateralReturn);
  const ordinaryOutputCount = body.outputs().len();
  const returnedLovelace = collateralReturn.amount().coin();
  const chargedCollateral = failureCollateral.assets.lovelace! - returnedLovelace;
  const minimumCollateral = (body.fee() * BigInt(parameters.collateralPercentage) + 99n) / 100n;
  assert.equal(collateralReturn.address().to_bech32(), walletAddress);
  assert(returnedLovelace > 0n);
  assert.equal(chargedCollateral, minimumCollateral);
  assert.equal(body.total_collateral(), chargedCollateral);

  progress("Submitting isValid=false and verifying the collateral-only ledger change.");
  assert.equal(await provider.submitTx(failedCbor), failedHash);
  assert.equal(await provider.awaitTx(failedHash), true);
  assert.deepEqual(await provider.getUtxosByOutRef(normalInputs), [scriptInput]);
  assert.deepEqual(await provider.getUtxosByOutRef([outRef(failureCollateral)]), []);
  assert.deepEqual(await provider.getUtxosByOutRef(Array.from({ length: ordinaryOutputCount }, (_, outputIndex) => ({
    txHash: failedHash,
    outputIndex,
  }))), []);
  const returned = await provider.getUtxosByOutRef([{ txHash: failedHash, outputIndex: ordinaryOutputCount }]);
  assert.equal(returned.length, 1);
  const returnUtxo = returned[0];
  assert(returnUtxo);
  assert.equal(returnUtxo.address, walletAddress);
  assert.deepEqual(returnUtxo.assets, { lovelace: returnedLovelace });
  assert.deepEqual(toScalusUtxo(returnUtxo).toObject(),
    Utxo.fromCbor(CML.TransactionUnspentOutput.new(
      CML.TransactionInput.new(CML.TransactionHash.from_hex(failedHash), BigInt(ordinaryOutputCount)),
      collateralReturn,
    ).to_cbor_bytes()).toObject());
  assert.deepEqual(await provider.getRewardAccount(rewardAddress), rewardBefore);

  progress("Spending the collateral return and minting the transaction-hash NFT.");
  assert.equal(fromHex(failedHash).length, 32);
  const unit = toUnit(policyId, failedHash);
  const mintReferences = [mintReference, scriptInput].sort((a, b) =>
    a.txHash < b.txHash ? -1 : a.txHash > b.txHash ? 1 : a.outputIndex - b.outputIndex,
  );
  const spendingReferenceInputIndex = mintReferences.indexOf(scriptInput);
  const collateralInput = collateralInputs[0];
  const totalCollateral = body.total_collateral();
  assert(collateralInput && totalCollateral !== undefined);
  const costModelData = CML.PlutusData.from_cbor_hex(Data.to(parameters.costModels.PlutusV3.map(BigInt)));
  const costModel = costModelData.to_canonical_cbor_hex();
  costModelData.free();
  const witness = new Constr(0, [
    spendContext.scriptContextTxInfo.txInfoOutputs.map((output) => Data.from(Data.to(output, TxOutData))),
    body.fee(),
    Data.from(Data.to({ txOutRefId: collateralInput.txHash, txOutRefIdx: BigInt(collateralInput.outputIndex) }, TxOutRefData)),
    totalCollateral,
    failedReferenceInputs.map((input) =>
      Data.from(Data.to({ txOutRefId: input.txHash, txOutRefIdx: BigInt(input.outputIndex) }, TxOutRefData)),
    ),
    withdrawalRedeemer,
    redeemerEncoding,
    costModel,
  ]);
  const mintRedeemer = Data.to(new Constr(0, [0n, BigInt(spendingReferenceInputIndex), witness]));
  const mint = await completeWithMinimumCollateral(parameters.collateralPercentage, (collateral) =>
    lucid.newTx()
      .collectFrom([returnUtxo])
      .readFrom(mintReferences)
      .mintAssets({ [unit]: 1n }, mintRedeemer)
      .pay.ToAddress(walletAddress, { lovelace: 5n * ADA, [unit]: 1n })
      .complete({ coinSelection: false, presetWalletInputs: [mintCollateral], localUPLCEval: false, setCollateral: collateral }),
  );
  const signedMint = await mint.sign.withWallet().complete();
  const mintBody = signedMint.toTransaction().body();
  assert.deepEqual(inputReferences(mintBody.inputs()), [outRef(returnUtxo)]);
  assert.deepEqual(inputReferences(mintBody.collateral_inputs()), [outRef(mintCollateral)]);
  assert.deepEqual(inputReferences(mintBody.reference_inputs()), mintReferences.map(outRef));
  assert.equal(signedMint.toTransaction().witness_set().plutus_v3_scripts()?.len() ?? 0, 0);
  transactions["04-mint"] = signedMint.toCBOR();
  const mintHash = await signedMint.submit();
  assert.deepEqual(await provider.getUtxosByOutRef([outRef(returnUtxo)]), []);
  assert.deepEqual(await provider.getUtxosByOutRef([outRef(mintCollateral)]), [mintCollateral]);
  const nftUtxo = await provider.getUtxoByUnit(unit);
  assert.equal(nftUtxo.address, walletAddress);
  assert.equal(nftUtxo.txHash, mintHash);
  assert.equal(nftUtxo.assets[unit], 1n);
  const finalNfts = emulator.getUtxos().flatMap((u) => u.value.assets).filter((a) => a.policyId === policyId);
  assert.equal(finalNfts.length, 1);
  assert.equal(finalNfts[0]?.assetName, failedHash);
  assert.equal(finalNfts[0]?.quantity, 1n);
  assert.deepEqual(await provider.getUtxos(referenceAddress), references);
  assert.deepEqual(await provider.getUtxos(spendAddress), [scriptInput]);
  assert.equal(emulator.getAppliedTxs().length, 4);

  const report = {
    network: NETWORK,
    emulator: "scalus@1.3.0",
    walletAddress,
    referenceAddress,
    validators: {
      spend: { hash: spendHash, address: spendAddress, reference: outRef(spendReference) },
      withdrawal: { hash: withdrawalHash, rewardAddress, reference: outRef(withdrawalReference) },
      mint: { policyId, reference: outRef(mintReference) },
    },
    transactions: { deployment: deploymentHash, setup: setupHash, failed: failedHash, mint: mintHash },
    validation: {
      spend: { success: spendEvaluation.isSuccess, declared: spendBudget, consumed: spendEvaluation.budget },
      withdrawal: {
        scriptHash: withdrawalFailure.scriptHash,
        code: withdrawalFailure.code,
        declared: withdrawalBudget,
        consumed: withdrawalEvaluation.budget,
      },
      validFlagTrueRejected: rejected.errorRule,
      invalidFlagAccepted: true,
      originalScriptInputUnspent: outRef(scriptInput),
      referenceScriptsUnspent: true,
    },
    collateral: {
      input: outRef(failureCollateral),
      inputLovelace: failureCollateral.assets.lovelace,
      transactionFeeLovelace: body.fee(),
      percentage: parameters.collateralPercentage,
      minimumLovelace: minimumCollateral,
      chargedLovelace: chargedCollateral,
      return: { ...outRef(returnUtxo), lovelace: returnedLovelace },
      returnSpentBy: mintHash,
    },
    nft: { policyId, assetName: failedHash, unit, quantity: 1n, output: outRef(nftUtxo) },
  };
  mintBody.free();
  collateralReturn.free();
  invalid.free();
  body.free();
  return { report, transactions };
}
