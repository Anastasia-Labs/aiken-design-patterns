import assert from "node:assert/strict";
import { toHex } from "@lucid-evolution/lucid";
import { PlutusScriptEvaluationError } from "scalus";
import { buildProofMint, prepareFailureEvidence, prepareScenario, type PreparedScenario } from "./scenario.ts";
import { executeChain, makeChain } from "./case-chain.ts";

// Validator mutation tests explicitly confirm funding before submitting custom bodies.
export async function prepareFundedScenario(...args: Parameters<typeof prepareScenario>) {
  const scenario = await prepareScenario(...args);
  const prefix = scenario.preparation.slice(0, -1);
  await executeChain(scenario.runtime, makeChain(scenario.runtime.scope, scenario.parameters, prefix, scenario.initialSnapshot), false);
  return scenario;
}

export async function confirmFailure(scenario: PreparedScenario) {
  const evidence = prepareFailureEvidence(scenario);
  const withdrawal = scenario.preparation.at(-1)!;
  await executeChain(scenario.runtime, makeChain(scenario.runtime.scope, scenario.parameters, [withdrawal]), false);
  return evidence;
}

export async function assertScriptRejected(
  scenario: PreparedScenario,
  scriptHash: string,
  purpose: "Mint" | "Spend",
  expectedCode: "SCRIPT_FAILURE" | "BUILTIN_FAILURE",
  build: () => Promise<unknown>,
) {
  const { emulator } = scenario;
  assert(emulator);
  const ledgerBefore = toHex(emulator.getUtxosCbor());
  const transactionCount = emulator.getAppliedTxs().length;
  const adapter = scenario.runtime.localEvaluator;
  const evaluate = adapter.evaluate.bind(adapter);
  let failure: unknown;
  // A builder error must not satisfy a negative test of the validator.
  adapter.evaluate = async (...args) => {
    try { return await evaluate(...args); }
    catch (error) { failure = error; throw error; }
  };
  try { await assert.rejects(build); }
  finally { adapter.evaluate = evaluate; }
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
  assert(scenario.emulator);
  assert.equal(scenario.emulator.getUtxos().flatMap((u) => u.value.assets).filter((a) => a.policyId === scenario.policyId).length, 0);
}
