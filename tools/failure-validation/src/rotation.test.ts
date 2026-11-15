import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { before, describe, test } from "node:test";
import { CML, Constr, Data } from "@lucid-evolution/lucid";
import { buildValidators, type Validators } from "./blueprint.ts";
import { ARGUMENT_MODES, BUILTINS, CASES, parseBuiltins, WITHDRAWAL_RESULTS, type BuiltinCase } from "./builtins.ts";
import { ENVIRONMENT_PATH } from "./environment.ts";
import { prepareScenario, runScenario, submitFailure } from "./scenario.ts";
import { assertProofRejected } from "./test-support.ts";
import { inputReferences } from "./transactions.ts";

const configured = parseBuiltins(
  [...BUILTINS, "equals_bytearray(ByteArray, ByteArray) -> Bool", "new_list() -> List<Data>"],
  [...CASES,
    `equals_bytearray/equal|success|${Data.to(["aabb", "aabb"])}`,
    `equals_bytearray/different|false|${Data.to(["aa", "bb"])}`,
    `new_list/empty|success|${Data.to([])}`,
  ],
);

for (const builtin of configured) {
  describe(builtin.name, () => {
    let scripts: Validators;
    before(async () => {
      const original = readFileSync(ENVIRONMENT_PATH);
      scripts = await buildValidators(builtin);
      assert.deepEqual(readFileSync(ENVIRONMENT_PATH), original);
    });
    for (const testCase of builtin.cases) for (const mode of ARGUMENT_MODES) {
      test(`${testCase.name}/${mode}`, async () => {
        const { report, transactions } = await runScenario(scripts, testCase, mode);
        const provisioned = mode === "referenced" && builtin.arity > 0;
        assert.equal(report.invocation.builtin, builtin.name);
        assert.equal(report.invocation.case, testCase.name);
        assert.equal(report.invocation.expectedOutcome, testCase.outcome);
        assert.equal(report.invocation.mode, mode);
        assert.deepEqual(report.invocation.arguments, Data.from(testCase.arguments));
        assert.equal(report.invocation.argumentReferences.length, mode === "referenced" ? builtin.arity : 0);
        assert.equal(new Set(report.invocation.argumentReferences.map((ref) => `${ref.txHash}#${ref.outputIndex}`)).size,
          report.invocation.argumentReferences.length);
        const indexes = report.invocation.argumentReferences.map((argument) => report.inputs.references.findIndex((reference) =>
          reference.txHash === argument.txHash && reference.outputIndex === argument.outputIndex));
        assert(indexes.every((index) => index >= 0));
        assert.deepEqual(report.invocation.argumentIndexes, indexes);
        const expectedRedeemer = new Constr(mode === "direct" ? 0 : 1,
          [mode === "direct" ? Data.from(testCase.arguments) : indexes.map(BigInt)]);
        assert.deepEqual(Data.from(report.invocation.redeemer), expectedRedeemer);
        assert.equal("02-arguments" in transactions, provisioned);
        assert.equal(report.outcome, testCase.outcome);
        assert.equal(report.inputs.ordinary.length, 1);
        assert.equal(report.fee.minimum, true);
        assert(report.fee.calculationPasses <= 8);
        assert.deepEqual(report.validation.withdrawal.declared, report.validators.parameters.budget);
        const transaction = CML.Transaction.from_cbor_hex(transactions[testCase.outcome === "success" ? "04-successful-withdrawal" : "04-failed-withdrawal"]!);
        const body = transaction.body();
        const outputs = body.outputs();
        try {
          assert.equal(outputs.len(), 0);
          assert.deepEqual(inputReferences(body.reference_inputs()), report.inputs.references);
        } finally { outputs.free(); body.free(); transaction.free(); }
        assert.equal(report.validation.argumentReferencesUnspent, true);
        if (report.outcome === "success") {
          assert.equal(Object.keys(transactions).length, provisioned ? 5 : 4);
          assert.equal(report.nft, null);
          assert.equal(report.validation.ordinaryInputsConsumed, true);
          assert.equal(report.collateral.returnCreated, false);
        } else {
          assert.equal(Object.keys(transactions).length, provisioned ? 6 : 5);
          assert.equal(report.validation.withdrawal.code, WITHDRAWAL_RESULTS[testCase.outcome]);
          assert.equal(report.validation.validFlagTrueRejected, "ScriptFailure");
          assert.equal(report.validation.ordinaryInputsUnspent.length, 1);
          assert.equal(report.collateral.return.outputIndex, 0);
          assert.equal(report.nft.assetName, report.transactions.failed);
          assert.equal(report.nft.quantity, 1n);
          const mint = CML.Transaction.from_cbor_hex(transactions["05-mint"]!);
          const witnesses = mint.witness_set();
          const redeemers = witnesses.redeemers()!;
          const entries = redeemers.to_flat_format();
          const entry = entries.get(0);
          const data = entry.data();
          try {
            const proof = Data.from(data.to_cbor_hex());
            assert(proof instanceof Constr);
            const witness = proof.fields[2];
            assert(witness instanceof Constr);
            assert.deepEqual(witness.fields[2], expectedRedeemer);
          } finally { data.free(); entry.free(); entries.free(); redeemers.free(); witnesses.free(); mint.free(); }
        }
      });
    }
    const arguments_ = Data.from(builtin.cases[0]!.arguments);
    assert(Array.isArray(arguments_));
    const malformed: BuiltinCase[] = [
      { name: "non-list", arguments: Data.void(), outcome: "builtin-error" },
      ...(builtin.arity === 0 ? [] : [{ name: "missing", arguments: Data.to(arguments_.slice(0, -1)), outcome: "builtin-error" as const }]),
      { name: "extra", arguments: Data.to([...arguments_, ""]), outcome: "false" },
      ...arguments_.map((_, index): BuiltinCase => ({
        name: `wrong-type-${index}`, outcome: "builtin-error",
        arguments: Data.to(arguments_.map((value, i) => i === index ? 1n : value)),
      })),
    ];
    for (const testCase of malformed) for (const mode of ARGUMENT_MODES) {
      if (mode === "referenced" && testCase.name === "non-list") continue;
      test(`preparation failure ${testCase.name}/${mode} cannot mint proof`, async () => {
        const scenario = await prepareScenario(scripts, testCase, mode);
        const evidence = await submitFailure(scenario);
        const expected = WITHDRAWAL_RESULTS[testCase.outcome];
        assert(expected !== "success");
        await assertProofRejected(expected, scenario, evidence);
      });
    }
  });
}
