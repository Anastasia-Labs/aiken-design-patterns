import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { before, describe, test, type TestContext } from "node:test";
import { CML, Data, toHex } from "@lucid-evolution/lucid";
import { Utxo, Value } from "scalus";
import { Artifacts } from "./artifacts.ts";
import { buildValidators, type Validators } from "./blueprint.ts";
import { ARGUMENT_MODES, BUILTINS, CASES, parseBuiltins } from "./builtins.ts";
import { LiveProvider } from "./live-provider.ts";
import { MOCK_KEY, MOCK_SEED, mockBlockfrost } from "./mock-blockfrost.ts";
import { BLOCKFROST_URLS, redactSecrets } from "./network.ts";
import { createRuntime, ordinaryFunding, referenceKey, submitTransaction, type Runtime } from "./runtime.ts";
import { buildProofMint, prepareBuiltin, prepareLiveRun, prepareScenario, runScenario, submitFailure } from "./scenario.ts";
import { inputReferences, minimumCollateral, minimumFee } from "./transactions.ts";

const builtin = parseBuiltins(["equals_bytearray(ByteArray, ByteArray) -> Bool"], [
  `equals_bytearray/unequal|false|${Data.to(["aa", "bb"])}`,
  `equals_bytearray/other-unequal|false|${Data.to(["ab", "bc"])}`,
  `equals_bytearray/equal|success|${Data.to(["aa", "aa"])}`,
])[0]!;
const secondBuiltin = parseBuiltins(["bls12_381_g1_uncompress(ByteArray) -> G1Element"], [
  `bls12_381_g1_uncompress/generator|success|${Data.to(["97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"])}`,
])[0]!;

async function fixture(t: TestContext, funding?: readonly bigint[]) {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let driving = true;
  const driver = (async () => {
    while (driving) {
      t.mock.timers.tick(500);
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
  })();
  t.after(async () => { driving = false; await driver; });
  const mock = mockBlockfrost("Preprod", funding);
  const controller = new AbortController();
  t.mock.method(globalThis, "fetch", mock.fetcher);
  const runtime = await createRuntime({ network: "Preprod", apiKey: MOCK_KEY, seed: MOCK_SEED }, controller.signal);
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
  let secondScripts: Validators;
  let productionScripts: Validators[];
  before(async () => {
    scripts = await buildValidators(builtin, undefined, "Preprod");
    secondScripts = await buildValidators(secondBuiltin, undefined, "Preprod");
    productionScripts = [];
    for (const item of parseBuiltins(BUILTINS, CASES)) {
      productionScripts.push(item.name === secondBuiltin.name
        ? secondScripts : await buildValidators(item, undefined, "Preprod"));
    }
  });

  test("selected builtins share one parameters NFT and register each stake credential once", async (t) => {
    const { runtime, mock, artifacts } = await fixture(t);
    const prepared = await prepareLiveRun([scripts, secondScripts], runtime);
    const first = prepared.builtins[builtin.name]!;
    const second = prepared.builtins[secondBuiltin.name]!;
    assert.equal(first.parametersPolicy, second.parametersPolicy);
    assert.deepEqual(first.parametersInput, second.parametersInput);
    assert.deepEqual(first.parametersReference, second.parametersReference);
    assert.equal((await runtime.provider.getUtxosWithUnit(first.parametersAddress, first.parametersUnit)).length, 1);
    for (const item of [first, second]) assert((await runtime.provider.getRewardAccount(item.rewardAddress)).registered);
    const setupRecords = artifacts.records.filter((record) => record.scope === "setup" && /^\d+-setup-\d+$/.test(record.name));
    assert(setupRecords.length > 0);
    let certificates = 0;
    for (const record of setupRecords) {
      const transaction = CML.Transaction.from_cbor_hex(record.cbor);
      const body = transaction.body();
      const outputs = body.outputs();
      const certs = body.certs();
      try {
        assert(record.cbor.length / 2 <= runtime.parameters.maxTxSize);
        certificates += certs?.len() ?? 0;
        assert(outputs.len() <= 8);
      } finally { certs?.free(); outputs.free(); body.free(); transaction.free(); }
    }
    assert.equal(certificates, 2);
    const firstReport = (await runScenario(scripts, builtin.cases[0]!, "direct", () => {}, first)).report;
    const secondReport = (await runScenario(secondScripts, secondBuiltin.cases[0]!, "referenced", () => {}, second)).report;
    assert.deepEqual(firstReport.validators.parameters.input, secondReport.validators.parameters.input);
    assert.equal(mock.submissions.filter((tx) => !tx.valid).length, 1);
  });

  test("four builtin reference sets pack into signed setup batches within maxTxSize", async (t) => {
    const { runtime, artifacts } = await fixture(t);
    const prepared = await prepareLiveRun(productionScripts, runtime);
    const batches = artifacts.records.filter((record) => record.scope === "setup" && /^\d+-setup-\d+$/.test(record.name));
    assert.equal(batches.length, 2);
    let referenceOutputs = 0;
    let registrations = 0;
    for (const batch of batches) {
      assert(batch.cbor.length / 2 <= runtime.parameters.maxTxSize);
      const transaction = CML.Transaction.from_cbor_hex(batch.cbor);
      const body = transaction.body();
      const outputs = body.outputs();
      const certs = body.certs();
      try {
        for (let index = 0; index < outputs.len(); index++) {
          const output = outputs.get(index);
          try {
            const reference = output.script_ref();
            if (reference) { referenceOutputs++; reference.free(); }
          } finally { output.free(); }
        }
        registrations += certs?.len() ?? 0;
      } finally { certs?.free(); outputs.free(); body.free(); transaction.free(); }
    }
    assert.equal(referenceOutputs, 9);
    assert.equal(registrations, 4);
    const first = prepared.builtins[productionScripts[0]!.builtin.name]!;
    assert.equal((await runtime.provider.getUtxosWithUnit(first.parametersAddress, first.parametersUnit)).length, 1);
  });

  test("insufficient rolling collateral stops before creating case funding", async (t) => {
    const { runtime, mock } = await fixture(t);
    const setup = await prepareBuiltin(scripts, runtime);
    const tinyRef = { txHash: "fe".repeat(32), outputIndex: 0 };
    mock.emulator.addUtxo(new Utxo(tinyRef.txHash, tinyRef.outputIndex, runtime.walletAddress, Value.ada(2n)));
    const tiny = (await runtime.provider.getUtxos(runtime.walletAddress)).find((utxo) => referenceKey(utxo) === referenceKey(tinyRef));
    assert(tiny);
    mock.history.set(referenceKey(tiny), tiny);
    runtime.rollingCollateral = tiny;
    runtime.reserved.add(referenceKey(tiny));
    for (const utxo of await ordinaryFunding(runtime)) runtime.reserved.add(referenceKey(utxo));
    const before = mock.submissions.length;
    await assert.rejects(() => prepareScenario(scripts, builtin.cases[0]!, "direct", () => {}, setup), /stopping before funding/);
    assert.equal(mock.submissions.length, before);
  });

  for (const [label, funding, maximumInputs] of [
    ["557 UTxOs", [1000n, ...Array<bigint>(556).fill(2n)], 2],
    ["multiple small UTxOs", Array<bigint>(31).fill(10n), 15],
  ] as const) {
    test(`Lucid selects bounded funding from ${label} through the full proof lifecycle`, async (t) => {
      const { runtime, mock } = await fixture(t, funding);
      assert.equal((await ordinaryFunding(runtime)).length, funding.length);
      const setup = await prepareBuiltin(scripts, runtime);
      for (const testCase of builtin.cases) for (const mode of ARGUMENT_MODES) await runScenario(scripts, testCase, mode, () => {}, setup);
      assert.equal(mock.submissions.filter((tx) => !tx.valid).length, 4);
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
    assert.equal(mock.submissions.length, 2); // wallet split and shared bootstrap
    const funding = await ordinaryFunding(runtime);
    assert(!funding.some((u) => u.scriptRef || runtime.reserved.has(referenceKey(u))));
    const reports = [];
    for (const testCase of builtin.cases) for (const mode of ARGUMENT_MODES) {
      runtime.scope = `equals_bytearray/${testCase.name}/${mode}`;
      const { report } = await runScenario(scripts, testCase, mode, () => {}, setup);
      artifacts.report(runtime.scope, { ...report, status: "passed" });
      reports.push(report);
    }
    assert.equal(mock.submissions.length, 21);
    assert.equal(mock.submissions.filter((s) => !s.valid).length, 4);
    assert.equal(reports[0]!.validators.parameters.policyId, reports[2]!.validators.parameters.policyId);
    assert.deepEqual(reports[0]!.validators.parameters.input, reports[1]!.validators.parameters.input);
    assert.deepEqual(reports[1]!.validators.parameters.input, reports[2]!.validators.parameters.input);
    const firstRolling = reports[0]!.collateral.rollingCollateral;
    const secondRolling = reports[1]!.collateral.rollingCollateral;
    assert(firstRolling && secondRolling);
    assert("inputLovelace" in reports[0]!.collateral && "inputLovelace" in reports[1]!.collateral);
    assert.deepEqual(reports[1]!.collateral.input, firstRolling.outRef);
    assert.deepEqual(reports[2]!.collateral.input, secondRolling.outRef);
    assert(reports[0]!.collateral.inputLovelace > reports[1]!.collateral.inputLovelace);
    assert.equal(firstRolling.lovelace, reports[1]!.collateral.inputLovelace);
    assert.equal((await runtime.provider.getUtxosByOutRef([reports[5]!.collateral.input])).length, 1);
    assert.equal((await runtime.provider.getUtxosWithUnit(setup.parametersAddress, setup.parametersUnit)).length, 1);
    assert.equal(reports[0]!.validators.parameters.threshold, 1);
    assert.equal(reports[4]!.nft, null);
    assert.equal(reports[5]!.nft, null);
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
    assert.equal(readJson(artifacts, "setup/transactions.json").length, 2);
    assert.equal(readJson(artifacts, "equals_bytearray/unequal/direct/transactions.json").length, 3);
    assert.equal(readJson(artifacts, "equals_bytearray/unequal/referenced/transactions.json").length, 4);
    assertNoSecrets(artifacts);

    // A new invocation deploys a new setup; the unchanged withdrawal credential is already registered.
    runtime.scope = "new-invocation/setup";
    runtime.artifacts = new Artifacts(join(artifacts.directory, "new-invocation"), runtime.network);
    const next = await prepareBuiltin(scripts, runtime);
    assert(next.registered);
    assert.notEqual(next.parametersPolicy, setup.parametersPolicy);
    const savedSetup = runtime.artifacts.find("setup", "01-setup-00");
    assert(savedSetup);
    const tx = CML.Transaction.from_cbor_hex(savedSetup.cbor);
    const body = tx.body(); const certs = body.certs();
    assert(!certs || certs.len() === 0);
    certs?.free(); body.free(); tx.free();
    assertNoSecrets(artifacts);
  });

  test("spent collateral with historical consumed_by_tx=null is absent from current UTxOs", async (t) => {
    const { runtime, mock } = await fixture(t);
    const setup = await prepareBuiltin(scripts, runtime);
    const scenario = await prepareScenario(scripts, builtin.cases[0]!, "referenced", () => {}, setup);
    const evidence = await submitFailure(scenario);
    const historical = mock.history.get(referenceKey(scenario.failureCollateral));
    assert(historical);
    // Use a new provider with an empty address cache so the historical lookup is exercised.
    const provider = new LiveProvider(BLOCKFROST_URLS.Preprod, MOCK_KEY);
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
    const scenario = await prepareScenario(scripts, builtin.cases[0]!, "referenced", () => {}, setup);
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
    await assert.rejects(() => submitTransaction(runtime, "payment", signed.toCBOR(), { present: [{ txHash: signed.toHash(), outputIndex: 0 }] }), failure.endsWith("timeout") ? /Confirmation timed out/ : /Could not submit transaction|interrupted/);
    assert.equal(mock.requests.filter((p) => p === "/tx/submit").length, 1);
    assert.equal(readFileSync(join(artifacts.directory, "case/payment.cbor"), "utf8").trim(), signed.toCBOR());
    assert.equal(readFileSync(join(artifacts.directory, "case/payment.hash"), "utf8").trim(), signed.toHash());
    const record = readJson(artifacts, "case/transaction-status.json")[0];
    assert.equal(record.status, "stopped");
    if (failure === "indexing-timeout") { assert(record.includedAt); assert(record.confirmation.blockHash); }
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
  assert.deepEqual(await runtime.localEvaluator.evaluate({ tx: signed.toCBOR(), additionalUTxOs: await ordinaryFunding(runtime),
    context: { network: runtime.network, slotConfig: runtime.slotConfig,
      protocolParameters: runtime.parameters, costModels: runtime.lucid.config().costModels! } }), []);
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
