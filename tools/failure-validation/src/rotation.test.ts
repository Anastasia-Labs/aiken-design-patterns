import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { before, describe, test } from "node:test";
import { Data } from "@lucid-evolution/lucid";
import { buildValidators, type Validators } from "./blueprint.ts";
import { BUILTINS, CASES, parseBuiltins, WITHDRAWAL_RESULTS, type BuiltinCase } from "./builtins.ts";
import { ENVIRONMENT_PATH } from "./environment.ts";
import { prepareScenario, runScenario, submitFailure } from "./scenario.ts";
import { assertProofRejected } from "./test-support.ts";

// A new name and arity exercise the same generator and runner with array entries only.
const configured = parseBuiltins(
  [...BUILTINS, "equals_bytearray(ByteArray, ByteArray) -> Bool", "new_list() -> List<Data>"],
  [...CASES,
    `equals_bytearray/equal|success|${Data.to(["aabb", "aabb"])}`,
    `equals_bytearray/different|false|${Data.to(["aa", "bb"])}`,
    `new_list/empty|success|${Data.to([])}`,
  ],
);

const spendingCosts: {
  label: string;
  inputIndex: number;
  consumed: { memory: bigint; steps: bigint };
}[] = [];

for (const builtin of configured) {
  describe(builtin.name, () => {
    let scripts: Validators;
    before(async () => {
      const original = readFileSync(ENVIRONMENT_PATH);
      scripts = await buildValidators(builtin);
      assert.deepEqual(readFileSync(ENVIRONMENT_PATH), original);
    });

    for (const testCase of builtin.cases) {
      for (const scriptInputFirst of [true, false]) {
        test(`${testCase.name} with script input ${scriptInputFirst ? 0 : 1}`, async () => {
          const { report, transactions } = await runScenario(scripts, testCase, undefined, { scriptInputFirst });
          assert.equal(report.invocation.builtin, builtin.name);
          assert.equal(report.invocation.case, testCase.name);
          assert.equal(report.invocation.expectedOutcome, testCase.outcome);
          assert.deepEqual(report.invocation.arguments, Data.from(testCase.datum));
          assert.equal(report.inputs.spendingInputIndex, scriptInputFirst ? 0 : 1);
          assert.equal(report.outcome, testCase.outcome);
          if (report.outcome === "success") {
            assert.equal(Object.keys(transactions).length, 3);
            assert(transactions["03-successful-spend"]);
            assert.equal(report.nft, null);
            assert.equal(report.validation.ordinaryInputsConsumed, true);
            assert.equal(report.collateral.returnCreated, false);
          } else {
            assert.equal(Object.keys(transactions).length, 4);
            assert.equal(report.validation.withdrawal.code, WITHDRAWAL_RESULTS[testCase.outcome]);
            assert.equal(report.validation.spend.success, true);
            assert.equal(report.validation.validFlagTrueRejected, "ScriptFailure");
            assert.equal(report.validation.ordinaryInputsUnspent.length, 2);
            assert.equal(report.nft.assetName, report.transactions.failed);
            assert.equal(report.nft.quantity, 1n);
          }
          spendingCosts.push({
            label: `${builtin.name}/${testCase.name}`,
            inputIndex: report.inputs.spendingInputIndex,
            consumed: report.validation.spend.consumed,
          });
        });
      }
    }

    const arguments_ = Data.from(builtin.cases[0]!.datum);
    assert(Array.isArray(arguments_));
    const malformed: BuiltinCase[] = [
      { name: "non-list", datum: Data.void(), outcome: "builtin-error" },
      ...(builtin.arity === 0 ? [] : [{ name: "missing", datum: Data.to(arguments_.slice(0, -1)), outcome: "builtin-error" as const }]),
      { name: "extra", datum: Data.to([...arguments_, ""]), outcome: "false" },
      ...arguments_.map((_, index): BuiltinCase => ({
        name: `wrong-type-${index}`, outcome: "builtin-error",
        datum: Data.to(arguments_.map((value, i) => i === index ? 1n : value)),
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

for (const inputIndex of [0, 1]) {
  test(`spending cost is independent of builtin with script input ${inputIndex}`, () => {
    const measurements = spendingCosts.filter((measurement) => measurement.inputIndex === inputIndex);
    const expectedCases = configured.flatMap((builtin) =>
      builtin.cases.map((testCase) => `${builtin.name}/${testCase.name}`),
    );
    assert.deepEqual(measurements.map(({ label }) => label).sort(), expectedCases.sort(),
      `Expected spending measurements for every builtin/case with script input ${inputIndex}`);
    const baseline = measurements[0];
    assert(baseline, `Missing spending baseline for script input ${inputIndex}`);
    const { label: baselineLabel, consumed: expected } = baseline;
    for (const { label, consumed } of measurements) {
      assert.deepEqual(consumed, expected,
        `${label} with script input ${inputIndex}: spending cost must match ${baselineLabel}`);
    }
  });
}
