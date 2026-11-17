import assert from "node:assert/strict";
import { CML, Data, coreToTxOutput, type UTxO } from "@lucid-evolution/lucid";
import { type Artifacts } from "./artifacts.ts";
import { assertValidity, observeTransaction, recordResources, referenceKey, restoreResources, takeSnapshot, type Runtime } from "./runtime.ts";
import { assertOutput, prepareTransaction } from "./case-chain.ts";

function checkArguments(runtime: Runtime, journal: Artifacts, scope: string, current: Map<string, UTxO>) {
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
  for (const output of required) {
    const actual = current.get(referenceKey(output));
    assert(actual, "Original argument references are unavailable or changed.");
    assertOutput(actual, output);
  }
}

export async function checkRecorded(runtime: Runtime, journal: Artifacts) {
  await restoreResources(runtime);
  for (const record of journal.records) {
    const observed = runtime.observations.get(record.hash) ?? await observeTransaction(runtime, record.hash);
    runtime.observations.delete(record.hash);
    assert.equal(observed.status, "confirmed", `Recorded transaction ${record.hash} is not confirmed.`);
    const transaction = prepareTransaction(record.name, record.cbor, record.effects);
    assertValidity(observed, transaction.valid);
    const scope = runtime.scope;
    runtime.scope = record.scope;
    recordResources(runtime, record.name, record.cbor, record.hash, true);
    runtime.scope = scope;
    if (record.status !== "confirmed") {
      record.status = "confirmed";
      if (observed.status === "confirmed") record.confirmation = observed.confirmation;
      record.confirmedAt ??= new Date().toISOString();
      delete record.error;
    }
  }
  const resources = Object.values(runtime.resources).filter((resource) => resource.confirmed);
  const current = await takeSnapshot(runtime, resources.filter((resource) => !resource.consumedBy).map((resource) => resource.output.address));
  for (const resource of resources) {
    if (resource.consumedBy) {
      assert(journal.records.some((record) => record.hash === resource.consumedBy && record.status === "confirmed"
        && record.consumedInputs.some((input) => referenceKey(input) === referenceKey(resource.output))),
      "Resource consumer is missing from the confirmed journal.");
      assert(!current.has(referenceKey(resource.output)), "Consumed run resource is still spendable.");
    } else {
      const actual = current.get(referenceKey(resource.output));
      assert(actual, "Original argument references or run resources are unavailable outside the journal.");
      assertOutput(actual, resource.output);
    }
  }
  for (const scope of Object.keys(journal.manifest?.cases ?? {})) checkArguments(runtime, journal, scope, current);
  journal.saveManifest();
  journal.renderTransactions();
}
