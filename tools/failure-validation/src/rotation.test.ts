import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { before, describe, test } from "node:test";
import { CML, Data } from "@lucid-evolution/lucid";
import { buildValidators, type Validators } from "./blueprint.ts";
import { BUILTINS, CASES, parseBuiltins, WITHDRAWAL_RESULTS, type BuiltinCase } from "./builtins.ts";
import { ENVIRONMENT_PATH } from "./environment.ts";
import { prepareScenario, runScenario, submitFailure } from "./scenario.ts";
import { assertProofRejected } from "./test-support.ts";

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
    for (const testCase of builtin.cases) {
      test(testCase.name, async () => {
        const { report, transactions } = await runScenario(scripts, testCase);
        assert.equal(report.invocation.builtin, builtin.name);
        assert.equal(report.invocation.case, testCase.name);
        assert.equal(report.invocation.expectedOutcome, testCase.outcome);
        assert.deepEqual(report.invocation.arguments, Data.from(testCase.redeemer));
        assert.equal(report.outcome, testCase.outcome);
        assert.equal(report.inputs.ordinary.length, 1);
        assert.equal(report.fee.minimum, true);
        assert(report.fee.calculationPasses <= 8);
        assert.deepEqual(report.validation.withdrawal.declared, report.validators.parameters.budget);
        const transaction = CML.Transaction.from_cbor_hex(transactions[testCase.outcome === "success" ? "03-successful-withdrawal" : "03-failed-withdrawal"]!);
        const body = transaction.body();
        const outputs = body.outputs();
        try { assert.equal(outputs.len(), 0); } finally { outputs.free(); body.free(); transaction.free(); }
        if (report.outcome === "success") {
          assert.equal(Object.keys(transactions).length, 3);
          assert.equal(report.nft, null);
          assert.equal(report.validation.ordinaryInputsConsumed, true);
          assert.equal(report.collateral.returnCreated, false);
        } else {
          assert.equal(Object.keys(transactions).length, 4);
          assert.equal(report.validation.withdrawal.code, WITHDRAWAL_RESULTS[testCase.outcome]);
          assert.equal(report.validation.validFlagTrueRejected, "ScriptFailure");
          assert.equal(report.validation.ordinaryInputsUnspent.length, 1);
          assert.equal(report.collateral.return.outputIndex, 0);
          assert.equal(report.nft.assetName, report.transactions.failed);
          assert.equal(report.nft.quantity, 1n);
        }
      });
    }
    const arguments_ = Data.from(builtin.cases[0]!.redeemer);
    assert(Array.isArray(arguments_));
    const malformed: BuiltinCase[] = [
      { name: "non-list", redeemer: Data.void(), outcome: "builtin-error" },
      ...(builtin.arity === 0 ? [] : [{ name: "missing", redeemer: Data.to(arguments_.slice(0, -1)), outcome: "builtin-error" as const }]),
      { name: "extra", redeemer: Data.to([...arguments_, ""]), outcome: "false" },
      ...arguments_.map((_, index): BuiltinCase => ({
        name: `wrong-type-${index}`, outcome: "builtin-error",
        redeemer: Data.to(arguments_.map((value, i) => i === index ? 1n : value)),
      })),
    ];
    for (const testCase of malformed) {
      test(`preparation failure ${testCase.name} cannot mint proof`, async () => {
        const scenario = await prepareScenario(scripts, testCase);
        const evidence = await submitFailure(scenario);
        const expected = WITHDRAWAL_RESULTS[testCase.outcome];
        assert(expected !== "success");
        await assertProofRejected(expected, scenario, evidence);
      });
    }
  });
}
