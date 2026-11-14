import assert from "node:assert/strict";
import { CML, coreToTxOutput, toUnit } from "@lucid-evolution/lucid";
import { type Artifacts } from "./artifacts.ts";
import { checkValidity, submitTransaction, type Runtime } from "./runtime.ts";
import { recordProofCollateralChange } from "./scenario.ts";

export async function checkRecorded(runtime: Runtime, journal: Artifacts) {
  for (const record of journal.records) {
    const status = await runtime.lucid.transactionStatus(record.hash);
    assert.equal(status.status, "confirmed", `Recorded transaction ${record.hash} is not confirmed.`);
    const tx = CML.Transaction.from_cbor_hex(record.cbor);
    try { await checkValidity(runtime, record.hash, tx.is_valid()); }
    finally { tx.free(); }
    record.status = "confirmed";
    record.confirmation = status.confirmation;
    record.confirmedAt ??= new Date().toISOString();
    delete record.error;
    journal.flush(record);
  }
}

export async function recoverMint(runtime: Runtime, journal: Artifacts, scope: string, outcome: string) {
  const mint = journal.find(scope, "05-mint");
  if (!mint) return false;
  const failed = journal.find(scope, "04-failed-withdrawal");
  assert(failed, `Missing failed withdrawal for ${scope}.`);
  if ((await runtime.lucid.transactionStatus(failed.hash)).status !== "confirmed") return false;
  runtime.scope = scope;
  const mintStatus = await runtime.lucid.transactionStatus(mint.hash);
  if (mintStatus.status === "confirmed") {
    const saved = CML.Transaction.from_cbor_hex(mint.cbor);
    try { await checkValidity(runtime, mint.hash, saved.is_valid()); }
    finally { saved.free(); }
    mint.status = "confirmed";
    mint.confirmation = mintStatus.confirmation;
    mint.includedAt ??= new Date().toISOString();
    mint.confirmedAt ??= new Date().toISOString();
    delete mint.error;
    journal.flush(mint);
  } else await submitTransaction(runtime, mint.name, mint.cbor, mint.effects);
  const previous = journal.manifest?.reports[scope];
  assert(previous && previous.validators && previous.collateral && previous.validation && previous.failedHash,
    `Missing case checkpoint for ${scope}.`);
  const validators = previous.validators as { mint: { policyId: string } };
  const failedHash = previous.failedHash as string;
  const unit = toUnit(validators.mint.policyId, failedHash);
  const tx = CML.Transaction.from_cbor_hex(mint.cbor);
  const body = tx.body();
  const outputs = body.outputs();
  let outputIndex = -1;
  try {
    for (let index = 0; index < outputs.len(); index++) {
      const output = outputs.get(index);
      try { if (coreToTxOutput(output).assets[unit] === 1n) outputIndex = index; }
      finally { output.free(); }
    }
  } finally { outputs.free(); body.free(); tx.free(); }
  assert(outputIndex >= 0, "Saved mint transaction has no proof output.");
  const setupBatches = journal.records.filter((record) => record.scope === "setup" && /^\d+-setup-\d+$/.test(record.name))
    .map((record) => record.hash);
  const deployment = setupBatches.at(-1);
  const setup = setupBatches[0];
  const funding = journal.find(scope, "03-funding")?.hash;
  assert(deployment && setup && funding);
  const rollingCollateral = await recordProofCollateralChange(runtime, mint.cbor);
  journal.report(scope, {
    ...previous, status: "passed", outcome, effectsObservedOn: "chain",
    transactions: { deployment, setup, setupBatches, funding, failed: failed.hash, mint: mint.hash },
    collateral: { ...(previous.collateral as object), returnSpentBy: mint.hash,
      rollingCollateral: { outRef: { txHash: rollingCollateral.txHash, outputIndex: rollingCollateral.outputIndex }, lovelace: rollingCollateral.assets.lovelace } },
    nft: { policyId: validators.mint.policyId, assetName: failedHash, unit, quantity: 1n,
      output: { txHash: mint.hash, outputIndex } },
  });
  return true;
}

