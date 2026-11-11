import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { before, describe, test, type TestContext } from "node:test";
import { CML, Data, toHex } from "@lucid-evolution/lucid";
import { Artifacts } from "./artifacts.ts";
import { buildValidators, type Validators } from "./blueprint.ts";
import { parseBuiltins } from "./builtins.ts";
import { BlockfrostProvider } from "./blockfrost-provider.ts";
import { MOCK_KEY, MOCK_SEED, mockBlockfrost } from "./mock-blockfrost.ts";
import { redactSecrets } from "./network.ts";
import { createRuntime, ordinaryFunding, referenceKey, submitTransaction, type Runtime } from "./runtime.ts";
import { buildProofMint, prepareBuiltin, prepareScenario, runScenario, submitFailure } from "./scenario.ts";
import { inputReferences, minimumCollateral, minimumFee } from "./transactions.ts";

const builtin = parseBuiltins(["equals_bytearray(ByteArray, ByteArray) -> Bool"], [
  `equals_bytearray/unequal|false|${Data.to(["aa", "bb"])}`,
  `equals_bytearray/other-unequal|false|${Data.to(["ab", "bc"])}`,
  `equals_bytearray/equal|success|${Data.to(["aa", "aa"])}`,
])[0]!;

async function fixture(t: TestContext, funding?: readonly bigint[]) {
  const mock = mockBlockfrost("Preprod", funding);
  const controller = new AbortController();
  const runtime = await createRuntime({ network: "Preprod", apiKey: MOCK_KEY, seed: MOCK_SEED }, controller.signal, mock.fetcher);
  const root = mkdtempSync(join(tmpdir(), "failure-artifacts-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const artifacts = new Artifacts(root, runtime.network, redactSecrets({ BLOCKFROST_API_KEY: MOCK_KEY, WALLET_SEED: MOCK_SEED }));
  runtime.artifacts = artifacts;
  let now = 0;
  const sleeps: number[] = [];
  runtime.now = () => now;
  runtime.sleep = async (ms) => { sleeps.push(ms); now += ms; };
  return { mock, controller, runtime, artifacts, root, sleeps };
}

function readJson(artifacts: Artifacts, file: string) { return JSON.parse(readFileSync(join(artifacts.directory, file), "utf8")); }
function assertNoSecrets(artifacts: Artifacts) {
  for (const path of readdirSync(artifacts.directory, { recursive: true, withFileTypes: true })) {
    if (path.isFile()) {
      const text = readFileSync(join(path.parentPath, path.name), "utf8");
      assert(!text.includes(MOCK_KEY)); assert(!text.includes(MOCK_SEED));
    }
  }
}

async function payment(runtime: Runtime) {
  const inputs = await ordinaryFunding(runtime);
  const tx = await runtime.lucid.newTx().collectFrom(inputs).pay.ToAddress(runtime.walletAddress, { lovelace: 10_000_000n })
    .complete({ coinSelection: false });
  return tx.sign.withWallet().complete();
}

describe("live orchestration through mocked Blockfrost responses", () => {
  let scripts: Validators;
  before(async () => { scripts = await buildValidators(builtin, undefined, "Preprod"); });

  for (const [label, funding, maximumInputs] of [
    ["557 UTxOs", [1000n, ...Array<bigint>(556).fill(2n)], 2],
    ["multiple small UTxOs", Array<bigint>(31).fill(10n), 15],
  ] as const) {
    test(`Lucid selects bounded funding from ${label} through the full proof lifecycle`, async (t) => {
      const { runtime, mock } = await fixture(t, funding);
      assert.equal((await ordinaryFunding(runtime)).length, funding.length);
      const setup = await prepareBuiltin(scripts, runtime);
      for (const testCase of builtin.cases) await runScenario(scripts, testCase, () => {}, setup);
      assert.equal(mock.submissions.filter((tx) => !tx.valid).length, 2);
      for (const { cbor } of mock.submissions) {
        assert(cbor.length / 2 <= runtime.parameters.maxTxSize);
        const tx = CML.Transaction.from_cbor_hex(cbor);
        const body = tx.body();
        try { assert(inputReferences(body.inputs()).length <= maximumInputs); }
        finally { body.free(); tx.free(); }
      }
      if (funding.length === 557) {
        assert.equal((await runtime.provider.getUtxos(runtime.walletAddress)).filter((u) => u.txHash === "01".repeat(32)).length, 555);
      }
      assert.equal((await runtime.provider.getUtxosByOutRef([setup.mintCollateral])).length, 1);
      assert.equal((await runtime.provider.getUtxosByOutRef(setup.references)).length, 3);
    });
  }

  test("shared setup, sequential cases, delayed indexing, raw invalid envelopes, and existing stake registration", async (t) => {
    const { runtime, mock, artifacts, sleeps } = await fixture(t);
    runtime.scope = "equals_bytearray/setup";
    mock.controls.confirmationDelay = 1;
    mock.controls.indexingDelay = 2;
    const setup = await prepareBuiltin(scripts, runtime);
    assert.equal(setup.threshold, 1);
    assert.equal(setup.signers.length, 1);
    assert.equal(setup.registered, false);
    assert.equal(mock.submissions.length, 3); // wallet split, deployment, bootstrap
    const funding = await ordinaryFunding(runtime);
    assert(!funding.some((u) => u.scriptRef || runtime.reserved.has(referenceKey(u))));
    const reports = [];
    for (const testCase of builtin.cases) {
      runtime.scope = `equals_bytearray/${testCase.name}`;
      const { report } = await runScenario(scripts, testCase, () => {}, setup);
      artifacts.report(runtime.scope, { ...report, status: "passed" });
      reports.push(report);
    }
    assert.equal(mock.submissions.length, 11);
    assert.equal(mock.submissions.filter((s) => !s.valid).length, 2);
    assert.equal(reports[0]!.validators.parameters.policyId, reports[2]!.validators.parameters.policyId);
    assert.equal(reports[0]!.validators.parameters.threshold, 1);
    assert.equal(reports[2]!.nft, null);
    assert(sleeps.length > 3 && sleeps.every((ms) => ms === 3_000));
    for (const report of reports) {
      if (report.outcome !== "success") {
        assert.equal(report.validation.validFlagTrueRejected, undefined);
        const signed = mock.submissions.find((s) => s.hash === report.transactions.failed)!;
        const transaction = CML.Transaction.from_cbor_hex(signed.cbor);
        const body = transaction.body(); const outputs = body.outputs();
        assert.equal(transaction.is_valid(), false);
        assert.equal(outputs.len(), 0);
        assert.equal(body.fee(), minimumFee(transaction, runtime.parameters, [scripts.withdrawal]));
        assert.equal(body.total_collateral(), minimumCollateral(body.fee(), runtime.parameters.collateralPercentage));
        outputs.free(); body.free(); transaction.free();
        assert.equal(report.effectsObservedOn, "chain");
      }
    }
    assert.deepEqual(readJson(artifacts, "transactions.json"), mock.submissions.map(({ cbor }) => ({ cbor })));
    assert(readJson(artifacts, "transaction-status.json").every((r: { status: string }) => r.status === "confirmed"));
    assert.equal(readJson(artifacts, "equals_bytearray/setup/transactions.json").length, 3);
    assert.equal(readJson(artifacts, "equals_bytearray/unequal/transactions.json").length, 3);
    assertNoSecrets(artifacts);

    // A new invocation deploys a new setup; the unchanged withdrawal credential is already registered.
    runtime.reserved.delete(referenceKey(setup.mintCollateral));
    runtime.scope = "new-invocation/setup";
    const next = await prepareBuiltin(scripts, runtime);
    assert(next.registered);
    assert.notEqual(next.parametersPolicy, setup.parametersPolicy);
    const tx = CML.Transaction.from_cbor_hex(next.transactions["02-parameters-registration"]!);
    const body = tx.body(); const certs = body.certs();
    assert(!certs || certs.len() === 0);
    certs?.free(); body.free(); tx.free();
    assertNoSecrets(artifacts);
  });

  test("spent collateral with historical consumed_by_tx=null is absent from current UTxOs", async (t) => {
    const { runtime, mock } = await fixture(t);
    const setup = await prepareBuiltin(scripts, runtime);
    const scenario = await prepareScenario(scripts, builtin.cases[0]!, () => {}, setup);
    const evidence = await submitFailure(scenario);
    const historical = mock.history.get(referenceKey(scenario.failureCollateral));
    assert(historical);
    // Use a new provider with an empty address cache so the historical lookup is exercised.
    const provider = new BlockfrostProvider("Preprod", MOCK_KEY, runtime.signal, mock.fetcher);
    assert.deepEqual(await provider.getUtxosByOutRef([scenario.failureCollateral]), []);
    assert.equal((await provider.getUtxosByOutRef([evidence.returnUtxo])).length, 1);
    const mint = await buildProofMint(scenario, evidence);
    const signed = await mint.sign.withWallet().complete();
    await submitTransaction(runtime, "proof", signed.toCBOR(), { absent: [evidence.returnUtxo] });
    assert.deepEqual(await provider.getUtxosByOutRef([evidence.returnUtxo]), []);
  });

  test("proof witness retains the producing cost model when current parameters change", async (t) => {
    const { runtime, mock } = await fixture(t);
    const setup = await prepareBuiltin(scripts, runtime);
    const scenario = await prepareScenario(scripts, builtin.cases[0]!, () => {}, setup);
    const original = [...scenario.parameters.costModels.PlutusV3];
    const evidence = await submitFailure(scenario);
    const changed = mock.rawParameters();
    // New construction uses the refreshed model; the witness still commits the producing one.
    changed.min_fee_a = 45;
    changed.cost_models_raw.PlutusV3[0] += 1;
    mock.setParameters(changed);
    await buildProofMint(scenario, evidence);
    assert.equal(runtime.parameters.minFeeA, 45);
    assert.notDeepEqual(runtime.parameters.costModels.PlutusV3, original);
    assert.deepEqual(scenario.parameters.costModels.PlutusV3, original);
    assert.notEqual(scenario.parameters.minFeeA, runtime.parameters.minFeeA);
    const canonical = CML.PlutusData.from_cbor_hex(Data.to(original.map(BigInt)));
    assert.equal(evidence.witness.fields[7], canonical.to_canonical_cbor_hex());
    canonical.free();
  });
});

for (const failure of ["rejection", "timeout", "indexing-timeout", "interruption"] as const) {
  test(`${failure} preserves signed artifacts and never resubmits`, async (t) => {
    const { runtime, mock, artifacts, controller, root } = await fixture(t);
    runtime.scope = "case";
    const signed = await payment(runtime);
    const before = toHex(mock.emulator.getUtxosCbor());
    if (failure === "rejection") mock.controls.rejectSubmission = true;
    if (failure === "timeout") { mock.controls.hideConfirmations = true; runtime.confirmationTimeout = 6_000; }
    if (failure === "indexing-timeout") { mock.controls.indexingDelay = 100; runtime.confirmationTimeout = 6_000; }
    if (failure === "interruption") mock.controls.afterSubmit = () => controller.abort(new Error(`interrupted ${MOCK_KEY} ${MOCK_SEED}`));
    await assert.rejects(() => submitTransaction(runtime, "payment", signed.toCBOR(), { present: [{ txHash: signed.toHash(), outputIndex: 0 }] }), failure.endsWith("timeout") ? /Confirmation timed out/ : /Blockfrost|interrupted/);
    assert.equal(mock.requests.filter((p) => p === "/tx/submit").length, 1);
    assert.equal(readFileSync(join(artifacts.directory, "case/payment.cbor"), "utf8").trim(), signed.toCBOR());
    assert.equal(readFileSync(join(artifacts.directory, "case/payment.hash"), "utf8").trim(), signed.toHash());
    const record = readJson(artifacts, "case/transaction-status.json")[0];
    assert.equal(record.status, "stopped");
    if (failure === "indexing-timeout") { assert(record.includedAt); assert(record.confirmation.block); }
    assert.deepEqual(readJson(artifacts, "transactions.json"), [{ cbor: signed.toCBOR() }]);
    if (failure === "rejection") assert.equal(toHex(mock.emulator.getUtxosCbor()), before);
    else assert(mock.emulator.hasTx(signed.toHash()));
    const another = new Artifacts(root, runtime.network);
    assert.notEqual(another.directory, artifacts.directory);
    assertNoSecrets(artifacts);
  });
}

test("current protocol parameters configure local Scalus evaluation and construction", async (t) => {
  const { runtime, mock } = await fixture(t);
  assert.equal(runtime.parameters.protocolMajorVersion, mock.info.protocolParams.protocolMajorVersion);
  assert.deepEqual(runtime.parameters.costModels, mock.info.protocolParams.costModels);
  assert.equal(runtime.evaluationOptions.protocolMajorVersion, runtime.parameters.protocolMajorVersion);
  assert.equal(runtime.parameters.keyDeposit, mock.info.protocolParams.stakeAddressDeposit);
  const signed = await payment(runtime);
  const tx = CML.Transaction.from_cbor_hex(signed.toCBOR());
  const body = tx.body();
  assert(inputReferences(body.inputs()).length);
  body.free(); tx.free();
  assert.deepEqual(await runtime.provider.evaluateTx(signed.toCBOR()), []);
});

test("oversized signed transactions are preserved and stopped before submission", async (t) => {
  const { runtime, mock, artifacts } = await fixture(t);
  runtime.scope = "size-check";
  const signed = await payment(runtime);
  runtime.parameters = { ...runtime.parameters, maxTxSize: signed.toCBOR().length / 2 - 1 };
  await assert.rejects(() => submitTransaction(runtime, "payment", signed.toCBOR()), /signed transaction is .*maximum is/);
  assert.equal(mock.requests.filter((path) => path === "/tx/submit").length, 0);
  assert.equal(readJson(artifacts, "size-check/transaction-status.json")[0].status, "stopped");
  assert.equal(readFileSync(join(artifacts.directory, "size-check/payment.cbor"), "utf8").trim(), signed.toCBOR());
});
