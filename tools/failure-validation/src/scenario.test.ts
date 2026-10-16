import assert from "node:assert/strict";
import { test } from "node:test";
import { CML } from "@lucid-evolution/lucid";
import { CardanoInfo } from "scalus";
import { buildValidators } from "./blueprint.ts";
import { runScenario } from "./scenario.ts";

test("reference scripts, prescribed budgets, minimum collateral, and failure-proof NFT mint", async () => {
  const { report, transactions } = await runScenario(buildValidators());
  const cbor = transactions["03-failed-spend"];
  assert(cbor);
  const transaction = CML.Transaction.from_cbor_hex(cbor);
  const witnesses = transaction.witness_set();
  const redeemers = witnesses.redeemers();
  assert(redeemers);
  const entries = redeemers.to_flat_format();
  try {
    assert.equal(entries.len(), 2);
    const validations = [report.validation.spend, report.validation.withdrawal];
    assert.deepEqual(validations.map(({ declared }) => declared), [
      { memory: 50_000n, steps: 14_000_000n },
      { memory: 17_450_000n, steps: 9_986_000_000n },
    ]);
    for (const [index, { declared, consumed }] of validations.entries()) {
      const redeemer = entries.get(index);
      const units = redeemer.ex_units();
      try {
        assert.equal(units.mem(), declared.memory);
        assert.equal(units.steps(), declared.steps);
        assert(consumed.memory <= declared.memory);
        assert(consumed.steps <= declared.steps);
      } finally {
        units.free();
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
          assert.equal(report.collateral.chargedLovelace, minimum);
          assert.equal(report.collateral.transactionFeeLovelace, body.fee());
          assert.equal(report.collateral.return.lovelace + minimum, report.collateral.inputLovelace);
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
