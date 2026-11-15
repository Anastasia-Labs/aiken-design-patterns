import assert from "node:assert/strict";
import { CML, Data, coreToTxOutput, sortUTxOs, toUnit, validatorToScriptHash, type UTxO } from "@lucid-evolution/lucid";
import { type Artifacts } from "./artifacts.ts";
import { checkValidity, referenceKey, restoreResources, submitTransaction, type Runtime } from "./runtime.ts";
import { recordProofBundle } from "./scenario.ts";
import { outRef } from "./transactions.ts";

async function checkArguments(runtime: Runtime, journal: Artifacts, scope: string) {
  const checkpoint = journal.manifest?.cases[scope];
  assert(checkpoint?.mode && checkpoint.argumentReferences, `Missing argument checkpoint for ${scope}.`);
  const [builtinName, caseName] = scope.split("/");
  const testCase = journal.manifest!.selection.find((builtin) => builtin.name === builtinName)?.cases.find((testCase) => testCase.name === caseName);
  assert(testCase);
  const arguments_ = Data.from(testCase.arguments);
  assert(Array.isArray(arguments_));
  assert.equal(checkpoint.argumentReferences.length, checkpoint.mode === "referenced" ? arguments_.length : 0,
    "Saved argument reference count changed.");
  const record = journal.find(scope, "02-arguments");
  if (!checkpoint.argumentReferences.length) {
    assert(!record, `Unexpected argument provisioning for ${scope}.`);
    return;
  }
  assert(checkpoint.mode === "referenced" && record, `Missing argument provisioning for ${scope}.`);
  const transaction = CML.Transaction.from_cbor_hex(record.cbor);
  const body = transaction.body();
  const outputs = body.outputs();
  const expected: UTxO[] = [];
  try {
    for (const [outputIndex, reference] of checkpoint.argumentReferences.entries()) {
      assert.deepEqual(reference, { txHash: record.hash, outputIndex }, "Saved argument output reference changed.");
      const output = outputs.get(outputIndex);
      try { expected.push({ ...reference, ...coreToTxOutput(output) }); }
      finally { output.free(); }
    }
  } finally { outputs.free(); body.free(); transaction.free(); }
  assert.deepEqual(expected.map((output) => { assert(output.datum && !output.datumHash); return Data.from(output.datum); }), arguments_,
    "Saved argument datums do not match configured arguments.");
  const required = expected.filter((output) => !runtime.resources[referenceKey(output)]?.consumedBy);
  assert.deepEqual(sortUTxOs(await runtime.provider.getUtxosByOutRef(required.map(outRef)), "Canonical"), sortUTxOs(required, "Canonical"),
    "Original argument references are unavailable or changed.");
}

export async function checkRecorded(runtime: Runtime, journal: Artifacts) {
  await restoreResources(runtime);
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
  for (const resource of Object.values(runtime.resources)) {
    if (!resource.confirmed) continue;
    if (resource.consumedBy) {
      assert(journal.records.some((record) => record.hash === resource.consumedBy && record.status === "confirmed"
        && record.consumedInputs.some((input) => referenceKey(input) === referenceKey(resource.output))),
      "Resource consumer is missing from the confirmed journal.");
    } else {
      const [current] = await runtime.provider.getUtxosByOutRef([resource.output]);
      assert(current, "Original argument references or run resources are unavailable outside the journal.");
      const expected = resource.output;
      assert.equal(current.address, expected.address, "Run resource address changed.");
      assert.deepEqual(current.assets, expected.assets, "Run resource assets changed.");
      assert.equal(current.datumHash, expected.datumHash, "Run resource datum hash changed.");
      assert.deepEqual(current.datum ? Data.from(current.datum) : undefined,
        expected.datum ? Data.from(expected.datum) : undefined, "Run resource datum changed.");
      assert.equal(current.scriptRef ? validatorToScriptHash(current.scriptRef) : undefined,
        expected.scriptRef ? validatorToScriptHash(expected.scriptRef) : undefined, "Run resource reference script changed.");
    }
  }
  for (const scope of Object.keys(journal.manifest?.cases ?? {})) await checkArguments(runtime, journal, scope);
}

export async function recoverMint(runtime: Runtime, journal: Artifacts, scope: string, outcome: string) {
  await restoreResources(runtime);
  const mint = journal.find(scope, "05-mint");
  if (!mint) return false;
  const failed = journal.find(scope, "04-failed-withdrawal");
  assert(failed, `Missing failed withdrawal for ${scope}.`);
  await checkArguments(runtime, journal, scope);
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
  await checkArguments(runtime, journal, scope);
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
  const proofBundle = await recordProofBundle(runtime, mint.cbor);
  journal.report(scope, {
    ...previous, status: "passed", outcome, effectsObservedOn: "chain",
    transactions: { deployment, setup, setupBatches, arguments: journal.find(scope, "02-arguments")?.hash, funding, failed: failed.hash, mint: mint.hash },
    collateral: { ...(previous.collateral as object), returnSpentBy: mint.hash,
      proofBundle: outRef(proofBundle) },
    nft: { policyId: validators.mint.policyId, assetName: failedHash, unit, quantity: 1n,
      output: { txHash: mint.hash, outputIndex } },
  });
  return true;
}

