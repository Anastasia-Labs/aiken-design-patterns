import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { before, describe, test, type TestContext } from "node:test";
import { CML, Constr, Data, getAddressDetails, toHex, type UTxO } from "@lucid-evolution/lucid";
import { Artifacts } from "./artifacts.ts";
import { buildValidators, type Validators } from "./blueprint.ts";
import { ARGUMENT_MODES, BUILTINS, CASES, parseBuiltins } from "./builtins.ts";
import { LiveProvider } from "./live-provider.ts";
import { MOCK_KEY, MOCK_SEED, mockBlockfrost } from "./mock-blockfrost.ts";
import { BLOCKFROST_URLS, redactSecrets } from "./network.ts";
import { checkRecorded } from "./resume.ts";
import { completeCase, createRuntime, ordinaryFunding, referenceKey, submitTransaction, type Runtime } from "./runtime.ts";
import { buildProofMint, buildWithReclamation, cleanupRun, prepareBuiltin, prepareRun, prepareScenario, runScenario, submitFailure } from "./scenario.ts";
import { inputReferences, minimumCollateral, minimumFee, minimumOutputAda, outRef } from "./transactions.ts";

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
        ? { ...secondScripts, builtin: item } : await buildValidators(item, undefined, "Preprod"));
    }
  });

  test("selected builtins share one parameters NFT and register each stake credential once", async (t) => {
    const { runtime, mock, artifacts } = await fixture(t);
    const prepared = await prepareRun([scripts, secondScripts], runtime);
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
    const prepared = await prepareRun(productionScripts, runtime);
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

  test("a large wallet output remains usable funding with bounded dedicated collateral", async (t) => {
    const { runtime, mock } = await fixture(t, [1000n, 2n, 2n]);
    const setup = await prepareBuiltin(scripts, runtime);
    assert.equal(setup.mintCollateral.assets.lovelace, 20_000_000n);
    assert((await ordinaryFunding(runtime)).some((output) => output.assets.lovelace! > 900_000_000n));
    const scenario = await prepareScenario(scripts, builtin.cases[0]!, "direct", () => {}, setup);
    assert.equal(scenario.failureCollateral.txHash, scenario.fundingHash);
    assert.equal(scenario.failureCollateral.outputIndex, 1);
    assert(scenario.failureCollateral.assets.lovelace! < 20_000_000n);
    assert((await ordinaryFunding(runtime)).some((output) => output.assets.lovelace! > 900_000_000n));
    assert(mock.submissions.every(({ cbor }) => cbor.length / 2 <= runtime.parameters.maxTxSize));
  });

  test("all 24 executions share a ledger and finish with sixteen proof NFTs and three run outputs", async (t) => {
    const { runtime, mock, artifacts } = await fixture(t);
    artifacts.initialize(runtime.network, runtime.walletAddress, getAddressDetails(runtime.walletAddress).paymentCredential!.hash,
      productionScripts.map((item) => item.builtin), productionScripts);
    const setup = await prepareRun(productionScripts, runtime);
    let successes = 0;
    const units: string[] = [];
    const returnIndexes = new Set<bigint>();
    for (const compiled of productionScripts) for (const testCase of compiled.builtin.cases) for (const mode of ARGUMENT_MODES) {
      const { report } = await runScenario(compiled, testCase, mode, () => {}, setup.builtins[compiled.builtin.name]);
      artifacts.report(runtime.scope, { ...report, status: "passed" });
      for (const reference of report.invocation.argumentReferences) {
        const resource = runtime.resources[referenceKey(reference)]!;
        assert(resource.releasedBy);
        assert(!resource.consumedBy, "Arguments must survive their own withdrawal and proof.");
      }
      const funding = await ordinaryFunding(runtime);
      if (report.outcome === "success") {
        successes++;
        assert(funding.some((output) => referenceKey(output) === referenceKey(report.collateral.input)),
          "Successful-withdrawal collateral must become available for funding.");
      }
      else {
        assert(funding.some((output) => output.txHash === report.transactions.mint), "Proof change must become ordinary funding.");
        assert(funding.some((output) => referenceKey(output) === referenceKey(report.inputs.ordinary[0]!)),
          "A failed withdrawal's surviving fee input must become available for funding.");
        units.push(report.nft.unit);
        const saved = artifacts.find(runtime.scope, "05-mint")!;
        const transaction = CML.Transaction.from_cbor_hex(saved.cbor);
        const body = transaction.body();
        const witnesses = transaction.witness_set();
        const redeemers = witnesses.redeemers()!;
        const entries = redeemers.to_flat_format();
        const entry = entries.get(0);
        const data = entry.data();
        try {
          const redeemer = Data.from(data.to_cbor_hex());
          assert(redeemer instanceof Constr && typeof redeemer.fields[0] === "bigint");
          returnIndexes.add(redeemer.fields[0]);
          assert.deepEqual(inputReferences(body.inputs())[Number(redeemer.fields[0])], outRef(report.collateral.return));
        } finally { data.free(); entry.free(); entries.free(); redeemers.free(); witnesses.free(); body.free(); transaction.free(); }
        assert(runtime.proofBundle);
        assert.equal(runtime.proofBundle.assets.lovelace,
          minimumOutputAda(runtime.walletAddress, { ...runtime.proofBundle.assets, lovelace: 0n }, runtime.parameters));
        assert(units.every((unit) => runtime.proofBundle!.assets[unit] === 1n));
      }
    }
    assert.equal(successes, 8);
    assert.equal(units.length, 16);
    assert.deepEqual(returnIndexes, new Set([0n, 1n]));
    const cleanup = await cleanupRun(runtime);
    assert(cleanup.checkpoint.complete);
    assert.equal(mock.emulator.getUtxos().length, 3);
    assert.equal(Object.keys(runtime.proofBundle!.assets).length, 17);
    assert.equal(Object.values(runtime.resources).filter((resource) => resource.confirmed && !resource.consumedBy).length, 3);
    assert(Object.values(runtime.resources).filter((resource) => resource.role === "argument" || resource.role === "reference")
      .every((resource) => resource.consumedBy));
    assert(mock.submissions.every(({ cbor }) => cbor.length / 2 <= runtime.parameters.maxTxSize));
    for (const item of Object.values(setup.builtins)) assert((await runtime.provider.getRewardAccount(item.rewardAddress)).registered);
    const submissions = mock.submissions.length;
    await checkRecorded(runtime, artifacts);
    assert.equal(mock.submissions.length, submissions);
  });

  test("references shared by script hash stay protected through the last scheduled user", async (t) => {
    const { runtime } = await fixture(t);
    const sharedScripts = { ...scripts, builtin: { ...builtin, name: "equals_bytearray_shared", cases: [builtin.cases[0]!] } };
    const prepared = await prepareRun([scripts, sharedScripts], runtime);
    const first = prepared.builtins[builtin.name]!;
    const second = prepared.builtins[sharedScripts.builtin.name]!;
    assert.deepEqual(first.withdrawalReference, second.withdrawalReference);
    assert.deepEqual(first.mintReference, second.mintReference);
    assert.equal(runtime.referenceUses.get(first.withdrawalHash)!.length, 8);
    for (const testCase of builtin.cases) for (const mode of ARGUMENT_MODES)
      await runScenario(scripts, testCase, mode, () => {}, first);
    assert.equal((await runtime.provider.getUtxosByOutRef(first.references)).length, 3);
    assert(!runtime.resources[referenceKey(first.withdrawalReference)]!.releasedBy);
    assert(!runtime.resources[referenceKey(first.mintReference)]!.releasedBy);
    for (const mode of ARGUMENT_MODES) await runScenario(sharedScripts, builtin.cases[0]!, mode, () => {}, second);
    assert(runtime.resources[referenceKey(first.withdrawalReference)]!.releasedBy);
    assert(runtime.resources[referenceKey(first.mintReference)]!.releasedBy);
    assert(!runtime.resources[referenceKey(first.parametersReference)]!.releasedBy);
    await cleanupRun(runtime);
    assert.equal((await runtime.provider.getUtxosByOutRef(first.references)).length, 0);
  });

  for (const [label, funding, maximumInputs] of [
    ["557 UTxOs", [1000n, ...Array<bigint>(556).fill(2n)], 10],
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
        assert((await runtime.provider.getUtxos(runtime.walletAddress)).filter((u) => u.txHash === "01".repeat(32)).length >= 550);
      }
      assert.equal((await runtime.provider.getUtxosByOutRef([setup.mintCollateral])).length, 1);
      await cleanupRun(runtime);
      assert.equal((await runtime.provider.getUtxosByOutRef(setup.references)).length, 0);
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
    assert(mock.submissions.length >= 21);
    assert.equal(mock.submissions.filter((s) => !s.valid).length, 4);
    assert.equal(reports[0]!.validators.parameters.policyId, reports[2]!.validators.parameters.policyId);
    assert.deepEqual(reports[0]!.validators.parameters.input, reports[1]!.validators.parameters.input);
    assert.deepEqual(reports[1]!.validators.parameters.input, reports[2]!.validators.parameters.input);
    assert(reports[0]!.outcome !== "success");
    const firstBundle = reports[0]!.collateral.proofBundle;
    assert(firstBundle);
    assert.notDeepEqual(reports[1]!.collateral.input, reports[0]!.collateral.input);
    assert.equal((await runtime.provider.getUtxosByOutRef([firstBundle])).length, 0);
    assert.equal(Object.keys(runtime.proofBundle!.assets).length, 5);
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

test("reclamation selects deterministic signed-size batches and cleanup consolidates every batch", async (t) => {
  const { runtime, mock } = await fixture(t);
  runtime.scope = "arguments";
  let tx = runtime.lucid.newTx();
  for (let index = 0; index < 30; index++)
    tx = tx.pay.ToAddressWithData(runtime.walletAddress, { kind: "inline", value: Data.to(BigInt(index)) }, { lovelace: 2_000_000n });
  const completed = await tx.complete({ presetWalletInputs: await ordinaryFunding(runtime), canonical: true });
  const signed = await completed.sign.withWallet().complete();
  await submitTransaction(runtime, "02-arguments", signed.toCBOR());
  assert.equal(Object.values(runtime.resources).filter((resource) => resource.role === "argument" && !resource.releasedBy).length, 30);
  completeCase(runtime);
  runtime.parameters.maxTxSize = 900;
  const build = async (reclaim: UTxO[], funding: UTxO[]) => {
    const completed = await runtime.lucid.newTx().collectFrom(reclaim)
      .pay.ToAddress(runtime.walletAddress, { lovelace: 3_000_000n })
      .complete({ presetWalletInputs: funding, canonical: true });
    return completed.sign.withWallet().complete();
  };
  const first = await buildWithReclamation(runtime, build);
  const second = await buildWithReclamation(runtime, build);
  assert.equal(first.toCBOR(), second.toCBOR());
  assert(first.toCBOR().length / 2 <= 900);
  const transaction = first.toTransaction();
  const body = transaction.body();
  try { assert(inputReferences(body.inputs()).length < 30); }
  finally { body.free(); transaction.free(); }
  await cleanupRun(runtime);
  assert(runtime.cleanup.transactions.length > 1);
  assert.equal(mock.emulator.getUtxos().length, 1);
  assert(mock.submissions.slice(1).every(({ cbor }) => cbor.length / 2 <= 900));
});

test("insufficient reclaimed ADA reports the funding failure before submitting", async (t) => {
  const { runtime, mock } = await fixture(t, [2n]);
  await assert.rejects(() => buildWithReclamation(runtime, async (reclaim, funding) => {
    const completed = await runtime.lucid.newTx().collectFrom(reclaim)
      .pay.ToAddress(runtime.walletAddress, { lovelace: 10_000_000n }).complete({ presetWalletInputs: funding });
    return completed.sign.withWallet().complete();
  }), /Insufficient ADA funding.*before funding submission/);
  assert.equal(mock.submissions.length, 0);
});

test("an empty funding pool cannot select reserved wallet collateral", async (t) => {
  const { runtime, mock } = await fixture(t);
  const [collateral] = await ordinaryFunding(runtime);
  assert(collateral);
  runtime.reserved.add(referenceKey(collateral));
  await assert.rejects(() => buildWithReclamation(runtime, async (reclaim, funding) => {
    assert.equal(reclaim.length + funding.length, 0);
    const completed = await runtime.lucid.newTx().collectFrom(reclaim)
      .pay.ToAddress(runtime.walletAddress, { lovelace: 10_000_000n }).complete({ presetWalletInputs: funding });
    return completed.sign.withWallet().complete();
  }), /Insufficient ADA funding.*before funding submission/);
  assert.equal(mock.submissions.length, 0);
  assert.equal((await runtime.provider.getUtxosByOutRef([collateral])).length, 1);
  assert.equal((await runtime.wallet.getUtxos()).length, 1, "Clear the wallet override after a failed build.");
});

test("reference-script minimum ADA includes the serialized script", async (t) => {
  const { runtime } = await fixture(t);
  const raw = CML.PlutusV3Script.from_raw_bytes(new Uint8Array(6000).fill(1));
  try {
    const script = { type: "PlutusV3" as const, script: raw.to_cbor_hex() };
    const lovelace = minimumOutputAda(runtime.walletAddress, { lovelace: 5_000_000n }, runtime.parameters, script);
    assert(lovelace > 25_000_000n);
    assert.equal(minimumOutputAda(runtime.walletAddress, { lovelace }, runtime.parameters, script), lovelace);
  } finally { raw.free(); }
});

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
