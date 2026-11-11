import assert from "node:assert/strict";
import { toHex } from "@lucid-evolution/lucid";
import { PlutusScriptEvaluationError } from "scalus";
import { buildProofMint, type PreparedScenario } from "./scenario.ts";

export async function assertScriptRejected(
  scenario: PreparedScenario,
  scriptHash: string,
  purpose: "Mint" | "Spend",
  expectedCode: "SCRIPT_FAILURE" | "BUILTIN_FAILURE",
  build: () => Promise<unknown>,
) {
  const { emulator, provider } = scenario;
  const ledgerBefore = toHex(emulator.getUtxosCbor());
  const transactionCount = emulator.getAppliedTxs().length;
  const evaluate = provider.evaluateTx.bind(provider);
  let failure: unknown;
  // A builder error must not satisfy a negative test of the validator.
  provider.evaluateTx = async (...args) => {
    try { return await evaluate(...args); }
    catch (error) { failure = error; throw error; }
  };
  try { await assert.rejects(build); }
  finally { provider.evaluateTx = evaluate; }
  assert(failure instanceof PlutusScriptEvaluationError, String(failure));
  assert.equal(failure.scriptHash, scriptHash);
  assert.equal(failure.redeemer?.tag, purpose);
  assert.equal(failure.code, expectedCode);
  assert.equal(toHex(emulator.getUtxosCbor()), ledgerBefore);
  assert.equal(emulator.getAppliedTxs().length, transactionCount);
}

export async function assertProofRejected(
  expectedCode: "SCRIPT_FAILURE" | "BUILTIN_FAILURE",
  ...args: Parameters<typeof buildProofMint>
) {
  const [scenario, evidence] = args;
  await assertScriptRejected(scenario, scenario.policyId, "Mint", expectedCode, () => buildProofMint(...args));
  assert.deepEqual(await scenario.provider.getUtxosByOutRef([evidence.returnUtxo]), [evidence.returnUtxo]);
  assert.equal(scenario.emulator.getUtxos().flatMap((u) => u.value.assets).filter((a) => a.policyId === scenario.policyId).length, 0);
}
