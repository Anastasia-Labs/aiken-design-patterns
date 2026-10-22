import assert from "node:assert/strict";
import { before, test } from "node:test";
import { CML, Constr, Data, TxOutRefData, fromHex, toHex } from "@lucid-evolution/lucid";
import { CardanoInfo, PlutusScriptEvaluationError } from "scalus";
import { buildValidators, type Validators } from "./blueprint.ts";
import { buildProofMint, buildSpend, extractOutputsCbor, prepareScenario, runScenario, submitFailure } from "./scenario.ts";

// RFC 8032 section 7.1, test 1: a valid signature of the empty message.
const PUBLIC_KEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const SIGNATURE = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

let scripts: Validators;
before(() => { scripts = buildValidators(); });

const OUTPUT_ADDRESS = `60${"04".repeat(28)}`;
for (const { name, outputs } of [
  { name: "non-minimal array and integer encodings", outputs: `98019f581d${OUTPUT_ADDRESS}1b0000000001406f40ff` },
  { name: "an indefinite outputs array", outputs: `9f82581d${OUTPUT_ADDRESS}1a01406f40ff` },
]) {
  test(`output extraction preserves ${name}`, () => {
    // Locate key 1 even when it follows another body field.
    const body = fromHex(`a3021a000f424001${outputs}0f00`);
    assert.equal(extractOutputsCbor(body), outputs);
  });
}

const inputOutputCases = [true, false].flatMap((scriptInputFirst) =>
  (["plain", "inline datum", "reference script"] as const).map((outputKind) => ({ scriptInputFirst, outputKind })),
);
for (const { scriptInputFirst, outputKind } of inputOutputCases) {
  test(`builtin failure, collateral return, and proof NFT with spending input ${scriptInputFirst ? 0 : 1} and ${outputKind} output`, async () => {
    const spendOutput = outputKind === "inline datum"
      ? { datum: Data.void() }
      : outputKind === "reference script" ? { referenceScript: scripts.spendWithdraw } : {};
    const { report, transactions } = await runScenario(scripts, undefined, { scriptInputFirst, spendOutput });
    assert.equal(report.inputs.spendingInputIndex, scriptInputFirst ? 0 : 1);
    assert.equal(report.inputs.ownInputIsFirst, scriptInputFirst);
    assert.deepEqual(report.invocation.arguments, [PUBLIC_KEY, "01", SIGNATURE]);
    assert.equal(report.validation.withdrawal.scriptHash, report.validators.spendWithdraw.hash);
    assert.equal(report.validation.withdrawal.code, "SCRIPT_FAILURE");
    assert.equal(report.validation.validFlagTrueRejected, "ScriptFailure");
    assert.equal(report.validation.ordinaryInputsUnspent.length, 2);
    assert.equal(report.nft.assetName, report.transactions.failed);
    assert.equal(report.nft.quantity, 1n);
    const cbor = transactions["03-failed-spend"];
    assert(cbor);
    const transaction = CML.Transaction.from_cbor_hex(cbor);
    const witnesses = transaction.witness_set();
    const redeemers = witnesses.redeemers();
    assert(redeemers);
    const entries = redeemers.to_flat_format();
    try {
      assert.equal(transaction.is_valid(), false);
      assert.equal(entries.len(), 2);
      const validations = [report.validation.spend, report.validation.withdrawal];
      assert.deepEqual(validations.map(({ declared }) => declared), [
        { memory: 50_000n, steps: 14_000_000n },
        { memory: 17_450_000n, steps: 9_986_000_000n },
      ]);
      for (const [index, { declared, consumed }] of validations.entries()) {
        const redeemer = entries.get(index);
        const units = redeemer.ex_units();
        const data = redeemer.data();
        try {
          assert.equal(redeemer.tag(), index === 0 ? CML.RedeemerTag.Spend : CML.RedeemerTag.Reward);
          assert.equal(redeemer.index(), index === 0 ? BigInt(report.inputs.spendingInputIndex) : 0n);
          assert.deepEqual(Data.from(data.to_cbor_hex()), new Constr(index === 0 && scriptInputFirst ? 1 : 0, []));
          assert.equal(units.mem(), declared.memory);
          assert.equal(units.steps(), declared.steps);
          assert(consumed.memory <= declared.memory);
          assert(consumed.steps <= declared.steps);
        } finally {
          units.free();
          data.free();
          redeemer.free();
        }
      }
      const parameters = CardanoInfo.preview().protocolParams;
      assert.equal(report.validation.spend.declared.memory + report.validation.withdrawal.declared.memory, parameters.maxTxExecutionMemory);
      assert.equal(report.validation.spend.declared.steps + report.validation.withdrawal.declared.steps, parameters.maxTxExecutionSteps);
      for (const name of ["02-registration-and-funding", "03-failed-spend", "04-mint"]) {
        const scriptCbor = transactions[name];
        assert(scriptCbor);
        const scriptTransaction = CML.Transaction.from_cbor_hex(scriptCbor);
        const body = scriptTransaction.body();
        try {
          const minimum = (body.fee() * BigInt(parameters.collateralPercentage) + 99n) / 100n;
          assert.equal(body.total_collateral(), minimum, `${name}: collateral must match the final fee`);
          if (name === "03-failed-spend") {
            const inputs = body.inputs();
            const references = body.reference_inputs();
            assert.equal(inputs.len(), 2);
            assert.equal(references?.len(), 1);
            inputs.free();
            references?.free();
            assert.equal(report.collateral.chargedLovelace, minimum);
            assert.equal(report.collateral.transactionFeeLovelace, body.fee());
            assert.equal(report.collateral.return.lovelace + minimum, report.collateral.inputLovelace);
            const outputs = body.outputs();
            const first = outputs.get(0);
            const datum = first.datum();
            const inline = datum?.as_datum();
            const reference = first.script_ref();
            const referenceHash = reference?.hash();
            try {
              assert.equal(inline?.to_cbor_hex(), outputKind === "inline datum" ? Data.void() : undefined);
              assert.equal(referenceHash?.to_hex(), outputKind === "reference script" ? report.validators.spendWithdraw.hash : undefined);
            } finally {
              referenceHash?.free();
              reference?.free();
              inline?.free();
              datum?.free();
              first.free();
              outputs.free();
            }
          }
        } finally {
          body.free();
          scriptTransaction.free();
        }
      }
    } finally {
      entries.free();
      redeemers.free();
      witnesses.free();
      transaction.free();
    }
  });
}

test("valid builtin arguments succeed and consume both ordinary inputs without creating failure evidence", async () => {
  const scenario = await prepareScenario(scripts, {
    datum: Data.to([PUBLIC_KEY, "", SIGNATURE]),
    scriptInputFirst: false,
  });
  const signed = await buildSpend(scenario, "success");
  const { emulator, provider, normalInputUtxos, failureCollateral, references, referenceAddress } = scenario;
  const evaluations = emulator.evaluateTx(fromHex(signed.toCBOR()));
  assert.deepEqual(evaluations.map(({ tag, index }) => [tag, index]), [["Spend", 1], ["Reward", 0]]);
  const transaction = signed.toTransaction();
  const body = transaction.body();
  const outputs = body.outputs();
  try {
    assert.equal(transaction.is_valid(), true);
    const hash = await signed.submit();
    assert.deepEqual(await provider.getUtxosByOutRef(normalInputUtxos), []);
    assert.deepEqual(await provider.getUtxosByOutRef([failureCollateral]), [failureCollateral]);
    assert.deepEqual(await provider.getUtxosByOutRef([{ txHash: hash, outputIndex: outputs.len() }]), []);
    assert.equal((await provider.getUtxosByOutRef(Array.from({ length: outputs.len() }, (_, outputIndex) => ({
      txHash: hash, outputIndex,
    })))).length, outputs.len());
    assert.deepEqual(await provider.getUtxos(referenceAddress), references);
    assert.equal(emulator.getAppliedTxs().length, 3);
  } finally {
    outputs.free();
    body.free();
  }
});

async function assertProofRejected(
  expectedCode: "SCRIPT_FAILURE" | "BUILTIN_FAILURE",
  ...args: Parameters<typeof buildProofMint>
) {
  const [scenario, evidence] = args;
  const { emulator, provider, policyId } = scenario;
  const ledgerBefore = toHex(emulator.getUtxosCbor());
  const evaluate = provider.evaluateTx.bind(provider);
  let failure: unknown;
  // Record the real evaluator error before Lucid wraps it, so an unrelated
  // builder failure cannot satisfy this negative test.
  provider.evaluateTx = async (...evaluationArgs) => {
    try {
      return await evaluate(...evaluationArgs);
    } catch (error) {
      failure = error;
      throw error;
    }
  };
  try {
    await assert.rejects(buildProofMint(...args));
  } finally {
    provider.evaluateTx = evaluate;
  }
  assert(failure instanceof PlutusScriptEvaluationError, String(failure));
  assert.equal(failure.scriptHash, policyId);
  assert.equal(failure.redeemer?.tag, "Mint");
  assert.equal(failure.code, expectedCode);
  assert.equal(toHex(emulator.getUtxosCbor()), ledgerBefore);
  assert.deepEqual(await provider.getUtxosByOutRef([evidence.returnUtxo]), [evidence.returnUtxo]);
  assert.equal(emulator.getAppliedTxs().length, 3);
  assert.equal(emulator.getUtxos().flatMap((u) => u.value.assets).filter((a) => a.policyId === policyId).length, 0);
}

// Failed Data/list extraction also produces BUILTIN_FAILURE in Scalus. The
// proof policy must reject preparation failures even after collateral is charged.
for (const { name, datum } of [
  { name: "non-list datum", datum: Data.void() },
  { name: "missing argument", datum: Data.to([PUBLIC_KEY, "01"]) },
  { name: "wrong argument type", datum: Data.to([1n, "01", SIGNATURE]) },
]) {
  test(`${name} fails withdrawal but cannot mint proof of a builtin failure`, async () => {
    const scenario = await prepareScenario(scripts, { datum });
    const evidence = await submitFailure(scenario, undefined, "BUILTIN_FAILURE");
    assert.equal(evidence.validation.spend.success, true);
    assert.equal(evidence.validation.withdrawal.code, "BUILTIN_FAILURE");
    assert.equal(evidence.validation.invalidFlagAccepted, true);
    await assertProofRejected("BUILTIN_FAILURE", scenario, evidence);
  });
}

test("proof mint rejects a witness naming the wrong other ordinary input", async () => {
  const scenario = await prepareScenario(scripts);
  const evidence = await submitFailure(scenario);
  const fields = [...evidence.witness.fields];
  fields[2] = Data.from(Data.to({
    txOutRefId: scenario.otherInput.txHash,
    txOutRefIdx: 99n,
  }, TxOutRefData));
  await assertProofRejected("SCRIPT_FAILURE", scenario, evidence, new Constr(0, fields));
});

for (const mutation of ["changed", "truncated", "appended"] as const) {
  test(`proof mint rejects ${mutation} output CBOR bytes`, async () => {
    const scenario = await prepareScenario(scripts);
    const evidence = await submitFailure(scenario);
    const fields = [...evidence.witness.fields];
    const outputs = fields[0];
    assert.equal(typeof outputs, "string");
    const failed = CML.Transaction.from_cbor_hex(scenario.transactions["03-failed-spend"]!);
    const body = failed.body();
    try {
      assert.equal(outputs, extractOutputsCbor(body.to_cbor_bytes()));
    } finally {
      body.free();
      failed.free();
    }
    fields[0] = mutation === "changed" ? "80" : mutation === "truncated" ? outputs.slice(0, -2) : `${outputs}00`;
    await assertProofRejected("SCRIPT_FAILURE", scenario, evidence, new Constr(0, fields));
  });
}
