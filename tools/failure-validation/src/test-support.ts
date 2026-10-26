import assert from "node:assert/strict";
import { toHex } from "@lucid-evolution/lucid";
import { PlutusScriptEvaluationError } from "scalus";
import { buildProofMint } from "./scenario.ts";

export async function assertProofRejected(
  expectedCode: "SCRIPT_FAILURE" | "BUILTIN_FAILURE",
  ...args: Parameters<typeof buildProofMint>
) {
  const [scenario, evidence] = args;
  const { emulator, provider, policyId } = scenario;
  const ledgerBefore = toHex(emulator.getUtxosCbor());
  const evaluate = provider.evaluateTx.bind(provider);
  let failure: unknown;
  // Record the evaluator error before Lucid wraps it. A builder error must not
  // satisfy a negative test of the proof policy.
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
