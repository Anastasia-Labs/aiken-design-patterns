import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { before, test, type TestContext } from "node:test";
import { Data, credentialToAddress, getAddressDetails } from "@lucid-evolution/lucid";
import { Artifacts, validateResumeIdentity } from "./artifacts.ts";
import { buildValidators, type Validators } from "./blueprint.ts";
import { ARGUMENT_MODES, parseBuiltins } from "./builtins.ts";
import { MOCK_KEY, MOCK_SEED, mockBlockfrost } from "./mock-blockfrost.ts";
import { createRuntime, ordinaryFunding, referenceKey, submitTransaction, type Runtime } from "./runtime.ts";
import { checkRecorded, recoverMint } from "./resume.ts";
import { cleanupRun, prepareBuiltin, prepareScenario, runScenario, submitFailure } from "./scenario.ts";

const builtin = parseBuiltins(["equals_bytearray(ByteArray, ByteArray) -> Bool"], [
  `equals_bytearray/unequal|false|${Data.to(["aa", "bb"])}`,
])[0]!;
let scripts: Validators;
before(async () => { scripts = await buildValidators(builtin, undefined, "Preprod"); });

async function fixture(t: TestContext) {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let driving = true;
  const driver = (async () => {
    while (driving) {
      t.mock.timers.tick(500);
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
  })();
  t.after(async () => { driving = false; await driver; });
  const mock = mockBlockfrost("Preprod");
  t.mock.method(globalThis, "fetch", mock.fetcher);
  const root = mkdtempSync(join(tmpdir(), "failure-resume-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const runtime = await createRuntime({ network: "Preprod", apiKey: MOCK_KEY, seed: MOCK_SEED });
  const artifacts = new Artifacts(root, "Preprod");
  artifacts.initialize("Preprod", runtime.walletAddress, getAddressDetails(runtime.walletAddress).paymentCredential!.hash,
    [builtin], [scripts]);
  runtime.artifacts = artifacts;
  runtime.scope = "equals_bytearray/setup";
  return { mock, runtime, artifacts };
}

async function reopen(directory: string): Promise<{ runtime: Runtime; artifacts: Artifacts }> {
  const artifacts = Artifacts.resume(directory);
  const runtime = await createRuntime({ network: "Preprod", apiKey: MOCK_KEY, seed: MOCK_SEED });
  validateResumeIdentity(artifacts.manifest!, runtime.walletAddress, "Preprod");
  runtime.artifacts = artifacts;
  runtime.scope = "equals_bytearray/setup";
  return { artifacts, runtime };
}

async function payment(runtime: Runtime) {
  const funding = await ordinaryFunding(runtime);
  const tx = await runtime.lucid.newTx().collectFrom([funding[0]!])
    .pay.ToAddress(runtime.walletAddress, { lovelace: 10_000_000n })
    .complete({ coinSelection: false });
  return tx.sign.withWallet().complete();
}

test("saved transaction resumes with exact bytes and one bundle entry", async (t) => {
  const { mock, runtime, artifacts } = await fixture(t);
  runtime.scope = "payment";
  const signed = await payment(runtime);
  const cbor = signed.toCBOR();
  artifacts.signed("payment", "pay", cbor, signed.toHash());
  const next = await reopen(artifacts.directory);
  next.runtime.scope = "payment";
  await submitTransaction(next.runtime, "pay", cbor);
  assert.deepEqual(mock.submissions.map((tx) => tx.cbor), [cbor]);
  assert.deepEqual(JSON.parse(readFileSync(join(artifacts.directory, "transactions.json"), "utf8")), [{ cbor }]);
  assert.equal(next.artifacts.find("payment", "pay")?.status, "confirmed");
});

test("accepted transaction survives a lost submission response", async (t) => {
  const { mock, runtime, artifacts } = await fixture(t);
  runtime.scope = "payment";
  const signed = await payment(runtime);
  mock.controls.afterSubmit = () => { throw new Error("lost response"); };
  await assert.rejects(() => submitTransaction(runtime, "pay", signed.toCBOR()), /lost response/);
  mock.controls.afterSubmit = undefined;
  const next = await reopen(artifacts.directory);
  next.runtime.scope = "payment";
  await submitTransaction(next.runtime, "pay", signed.toCBOR());
  assert.equal(mock.submissions.length, 1);
  assert.equal(next.artifacts.find("payment", "pay")?.hash, signed.toHash());
});

test("confirmed saved transaction waits for delayed output indexing", async (t) => {
  const { mock, runtime, artifacts } = await fixture(t);
  runtime.scope = "payment";
  const signed = await payment(runtime);
  const effects = { present: [{ txHash: signed.toHash(), outputIndex: 0 }] };
  mock.controls.afterSubmit = () => { throw new Error("lost response"); };
  await assert.rejects(() => submitTransaction(runtime, "pay", signed.toCBOR(), effects), /lost response/);
  mock.controls.afterSubmit = undefined;
  mock.controls.indexingDelay = 2;
  const next = await reopen(artifacts.directory);
  next.runtime.scope = "payment";
  let now = 0;
  let sleeps = 0;
  next.runtime.now = () => now;
  next.runtime.sleep = async (ms) => { now += ms; sleeps++; };
  await submitTransaction(next.runtime, "pay", signed.toCBOR(), effects);
  assert(sleeps >= 1);
  assert.equal(mock.submissions.length, 1);
});

test("unavailable inputs with no confirmed hash stop without replacement funding", async (t) => {
  const { mock, runtime, artifacts } = await fixture(t);
  runtime.scope = "payment";
  const signed = await payment(runtime);
  artifacts.signed("payment", "pay", signed.toCBOR(), signed.toHash());
  const funding = (await ordinaryFunding(runtime))[0]!;
  const competing = await runtime.lucid.newTx().collectFrom([funding])
    .pay.ToAddress(runtime.walletAddress, { lovelace: 20_000_000n })
    .complete({ coinSelection: false });
  await runtime.provider.submitTx((await competing.sign.withWallet().complete()).toCBOR());
  const next = await reopen(artifacts.directory);
  next.runtime.scope = "payment";
  next.runtime.confirmationTimeout = 1_000;
  await assert.rejects(() => submitTransaction(next.runtime, "pay", signed.toCBOR()), /Confirmation timed out/);
  assert.equal(mock.submissions.some((tx) => tx.hash === signed.toHash()), false);
  assert.equal(next.artifacts.find("payment", "pay")?.cbor, signed.toCBOR());
});

for (const stage of ["signed", "accepted"] as const) test(`argument provisioning resumes its ${stage} bytes without replacement outputs`, async (t) => {
  const { mock, runtime, artifacts } = await fixture(t);
  const setup = await prepareBuiltin(scripts, runtime);
  const scope = "equals_bytearray/unequal/referenced";
  const signed = artifacts.signed.bind(artifacts);
  const journal = t.mock.method(artifacts, "signed", (...args: Parameters<Artifacts["signed"]>) => {
    const record = signed(...args);
    if (stage === "signed" && record.name === "02-arguments") throw new Error("interrupted arguments");
    return record;
  });
  mock.controls.afterSubmit = () => {
    if (stage === "accepted") throw new Error("interrupted arguments");
  };
  await assert.rejects(() => prepareScenario(scripts, builtin.cases[0]!, "referenced", () => {}, setup), /interrupted arguments/);
  journal.mock.restore();
  mock.controls.afterSubmit = undefined;
  const argumentsTx = artifacts.find(scope, "02-arguments")!;
  assert(argumentsTx);
  assert.equal(artifacts.find(scope, "03-funding"), undefined);
  const bytes = argumentsTx.cbor;
  const next = await reopen(artifacts.directory);
  const reused = await prepareBuiltin(scripts, next.runtime);
  await runScenario(scripts, builtin.cases[0]!, "referenced", () => {}, reused);
  assert.equal(next.artifacts.find(scope, "02-arguments")?.cbor, bytes);
  assert.deepEqual(next.artifacts.manifest!.cases[scope]!.argumentReferences,
    [0, 1].map((outputIndex) => ({ txHash: argumentsTx.hash, outputIndex })));
  assert.equal(mock.submissions.filter((tx) => tx.hash === argumentsTx.hash).length, 1);
  assert.equal(mock.submissions.filter((tx) => tx.cbor === bytes).length, 1);
  await checkRecorded(next.runtime, next.artifacts);
});

for (const mode of ARGUMENT_MODES) test(`funding checkpoint restores setup and producing snapshot without rebuilding (${mode})`, async (t) => {
  const scope = `equals_bytearray/unequal/${mode}`;
  const { mock, runtime, artifacts } = await fixture(t);
  const setup = await prepareBuiltin(scripts, runtime);
  runtime.scope = scope;
  mock.controls.afterSubmit = () => {
    if (artifacts.find(scope, "03-funding")?.hash === mock.submissions.at(-1)?.hash) throw new Error("lost funding response");
  };
  await assert.rejects(() => prepareScenario(scripts, builtin.cases[0]!, mode, () => {}, setup), /lost funding response/);
  mock.controls.afterSubmit = undefined;
  const funding = artifacts.find(scope, "03-funding")!;
  const withdrawal = artifacts.find(scope, "04-failed-withdrawal")!;
  assert(funding && withdrawal);
  const original = artifacts.manifest!.cases[scope]!.protocol!;
  const changed = mock.rawParameters();
  changed.min_fee_a = Number(changed.min_fee_a) + 1;
  mock.setParameters(changed);
  const next = await reopen(artifacts.directory);
  const reused = await prepareBuiltin(scripts, next.runtime);
  next.runtime.scope = scope;
  const resumed = await prepareScenario(scripts, builtin.cases[0]!, mode, () => {}, reused);
  assert.equal(resumed.parameters.minFeeA, original.minFeeA);
  assert.equal(resumed.withdrawal.toCBOR(), withdrawal.cbor);
  assert.equal(resumed.fundingHash, funding.hash);
  mock.setParameters(JSON.parse(mock.info.protocolParams.toBlockfrostJson()));
  await runScenario(scripts, builtin.cases[0]!, mode, () => {}, reused);
  assert.equal(mock.submissions.filter((tx) => tx.hash === funding.hash).length, 1);
  assert.equal(mock.submissions.filter((tx) => tx.hash === withdrawal.hash).length, 1);
  assert.equal(mock.submissions.filter((tx) => !tx.valid).length, 1);
  const twice = Artifacts.resume(artifacts.directory);
  assert(twice.find(scope, "05-mint"));
  assert.equal(twice.records.length, mock.submissions.length);
});

for (const mode of ARGUMENT_MODES) test(`confirmed failed withdrawal resumes at proof mint (${mode})`, async (t) => {
  const scope = `equals_bytearray/unequal/${mode}`;
  const { mock, runtime, artifacts } = await fixture(t);
  const setup = await prepareBuiltin(scripts, runtime);
  runtime.scope = scope;
  const scenario = await prepareScenario(scripts, builtin.cases[0]!, mode, () => {}, setup);
  mock.controls.afterSubmit = () => { throw new Error("lost withdrawal response"); };
  await assert.rejects(() => submitFailure(scenario), /lost withdrawal response/);
  mock.controls.afterSubmit = undefined;
  const failed = artifacts.find(scope, "04-failed-withdrawal")!;
  const next = await reopen(artifacts.directory);
  const reused = await prepareBuiltin(scripts, next.runtime);
  next.runtime.scope = scope;
  const result = await runScenario(scripts, builtin.cases[0]!, mode, () => {}, reused);
  assert.equal(result.report.transactions.failed, failed.hash);
  assert.equal(mock.submissions.filter((tx) => tx.hash === failed.hash).length, 1);
  assert.equal(mock.submissions.filter((tx) => tx.hash === result.report.transactions.mint).length, 1);
  // A later proof consumed collateral return, but the earlier hash is still confirmed.
  await submitTransaction(next.runtime, "04-failed-withdrawal", failed.cbor, failed.effects);
  assert.equal(mock.submissions.filter((tx) => tx.hash === failed.hash).length, 1);
});

test("shared bootstrap resumes from its accepted transaction bytes", async (t) => {
  const { mock, runtime, artifacts } = await fixture(t);
  let submitted = 0;
  mock.controls.afterSubmit = () => {
    submitted++;
    if (submitted === 2) throw new Error("lost bootstrap response");
  };
  await assert.rejects(() => prepareBuiltin(scripts, runtime), /lost bootstrap response/);
  const bootstrap = artifacts.find("setup", "01-setup-00");
  assert(bootstrap);
  assert.equal(mock.submissions.length, 2); // wallet split and accepted bootstrap
  mock.controls.afterSubmit = undefined;
  const next = await reopen(artifacts.directory);
  const resumed = await prepareBuiltin(scripts, next.runtime);
  assert.equal(mock.submissions.length, 2);
  assert.equal(resumed.parametersInput.txHash, bootstrap.hash);
  assert.equal(next.artifacts.manifest?.shared.ready, true);
  assert.equal((await next.runtime.provider.getUtxosWithUnit(resumed.parametersAddress, resumed.parametersUnit)).length, 1);
});

for (const mode of ARGUMENT_MODES) test(`accepted proof mint is not minted twice after restart (${mode})`, async (t) => {
  const scope = `equals_bytearray/unequal/${mode}`;
  const { mock, runtime, artifacts } = await fixture(t);
  const setup = await prepareBuiltin(scripts, runtime);
  runtime.scope = scope;
  mock.controls.afterSubmit = () => {
    if (mock.submissions.at(-1)?.valid && mock.submissions.some((tx) => !tx.valid)) throw new Error("lost mint response");
  };
  await assert.rejects(() => runScenario(scripts, builtin.cases[0]!, mode, () => {}, setup), /lost mint response/);
  mock.controls.afterSubmit = undefined;
  const mint = artifacts.find(scope, "05-mint")!;
  const next = await reopen(artifacts.directory);
  next.runtime.scope = scope;
  assert.equal(await recoverMint(next.runtime, next.artifacts, scope, "false"), true);
  assert.equal(mock.submissions.filter((tx) => tx.hash === mint.hash).length, 1);
  assert.equal(next.artifacts.find(scope, "05-mint")?.status, "confirmed");
  assert.equal(next.artifacts.manifest!.reports[scope]?.status, "passed");
  const before = mock.submissions.length;
  await checkRecorded(next.runtime, next.artifacts);
  assert.equal(mock.submissions.length, before);
});

test("completion and proof recovery require the original argument UTxOs to remain unspent", async (t) => {
  const { mock, runtime, artifacts } = await fixture(t);
  const setup = await prepareBuiltin(scripts, runtime);
  const scope = "equals_bytearray/unequal/referenced";
  const { report } = await runScenario(scripts, builtin.cases[0]!, "referenced", () => {}, setup);
  artifacts.report(scope, { ...report, status: "passed" });
  await checkRecorded(runtime, artifacts);
  const [argument] = await runtime.provider.getUtxosByOutRef(report.invocation.argumentReferences.slice(0, 1));
  assert(argument);
  const spent = await runtime.lucid.newTx().collectFrom([argument]).complete({ coinSelection: false });
  await (await spent.sign.withWallet().complete()).submit();
  const before = mock.submissions.length;
  await assert.rejects(() => checkRecorded(runtime, artifacts), /unavailable/);
  await assert.rejects(() => recoverMint(runtime, artifacts, scope, "false"), /Original argument references are unavailable/);
  assert.equal(mock.submissions.length, before);
});

test("resume rejects changed argument modes, indexes, references, and typed redeemers", async (t) => {
  const { runtime, artifacts } = await fixture(t);
  const setup = await prepareBuiltin(scripts, runtime);
  await prepareScenario(scripts, builtin.cases[0]!, "referenced", () => {}, setup);
  const scope = "equals_bytearray/unequal/referenced";
  const path = join(artifacts.directory, "manifest.json");
  const original = readFileSync(path, "utf8");
  for (const mutate of [
    (checkpoint: any) => { checkpoint.mode = "direct"; },
    (checkpoint: any) => { checkpoint.argumentReferences.pop(); },
    (checkpoint: any) => { checkpoint.argumentReferences[1] = checkpoint.argumentReferences[0]; },
    (checkpoint: any) => { checkpoint.argumentIndexes[1] = checkpoint.argumentIndexes[0]; },
    (checkpoint: any) => { checkpoint.argumentIndexes[0] = 10; },
    (checkpoint: any) => { checkpoint.resolvedArguments = Data.to(["cc", "dd"]); },
    (checkpoint: any) => { checkpoint.redeemer = Data.void(); },
  ]) {
    const value = JSON.parse(original);
    mutate(value.cases[scope]);
    writeFileSync(path, JSON.stringify(value));
    assert.throws(() => Artifacts.resume(artifacts.directory));
  }
  writeFileSync(path, original);
});

test("resume rejects missing, corrupt, incompatible, and tampered manifests", async (t) => {
  const { runtime, artifacts } = await fixture(t);
  const signed = await payment(runtime);
  artifacts.signed("payment", "pay", signed.toCBOR(), signed.toHash());
  const path = join(artifacts.directory, "manifest.json");
  const original = readFileSync(path, "utf8");
  const bad = (mutate: (value: any) => void) => {
    const value = JSON.parse(original);
    mutate(value);
    writeFileSync(path, JSON.stringify(value));
    assert.throws(() => Artifacts.resume(artifacts.directory));
  };
  bad((value) => { value.version = 1; });
  bad((value) => { value.version = 2; });
  bad((value) => { value.version = 3; });
  bad((value) => { value.scripts[builtin.name].hashes.mint = "ff".repeat(28); });
  bad((value) => { value.transactions[0].hash = "ff".repeat(32); });
  bad((value) => { value.transactions[0].requiredInputs = []; });
  writeFileSync(path, "{");
  assert.throws(() => Artifacts.resume(artifacts.directory), /Missing or corrupt manifest/);
  rmSync(path);
  assert.equal(existsSync(path), false);
  assert.throws(() => Artifacts.resume(artifacts.directory), /Missing or corrupt manifest/);
  writeFileSync(path, original);
  const resumed = Artifacts.resume(artifacts.directory);
  assert.throws(() => validateResumeIdentity(resumed.manifest!, runtime.walletAddress, "Mainnet"), /NETWORK conflicts/);
  const other = credentialToAddress("Preprod", { type: "Key", hash: "aa".repeat(28) });
  assert.throws(() => validateResumeIdentity(resumed.manifest!, other, "Preprod"), /Wallet does not match/);
  assert.deepEqual(resumed.manifest!.selection, [builtin]);
});

test("an interruption after atomically saving funding preserves both unsubmitted transactions", async (t) => {
  const { mock, runtime, artifacts } = await fixture(t);
  const setup = await prepareBuiltin(scripts, runtime);
  const save = artifacts.signedPair.bind(artifacts);
  const hook = t.mock.method(artifacts, "signedPair", (...args: Parameters<Artifacts["signedPair"]>) => {
    save(...args);
    throw new Error("interrupted saved funding pair");
  });
  await assert.rejects(() => prepareScenario(scripts, builtin.cases[0]!, "direct", () => {}, setup), /saved funding pair/);
  hook.mock.restore();
  const scope = "equals_bytearray/unequal/direct";
  const funding = artifacts.find(scope, "03-funding")!;
  const withdrawal = artifacts.find(scope, "04-failed-withdrawal")!;
  assert(!mock.submissions.some((tx) => tx.hash === funding.hash || tx.hash === withdrawal.hash));
  const next = await reopen(artifacts.directory);
  const resumed = await prepareBuiltin(scripts, next.runtime);
  await runScenario(scripts, builtin.cases[0]!, "direct", () => {}, resumed);
  for (const record of [funding, withdrawal]) {
    assert.equal(next.artifacts.find(scope, record.name)?.cbor, record.cbor);
    assert.equal(mock.submissions.filter((tx) => tx.cbor === record.cbor).length, 1);
  }
});

for (const step of ["03-funding", "05-mint", "06-cleanup-00"] as const)
  for (const stage of ["signed", "accepted"] as const)
    test(`${stage} ${step} resumes reclamation and consolidation with identical bytes`, async (t) => {
      const { mock, runtime, artifacts } = await fixture(t);
      const setup = await prepareBuiltin(scripts, runtime);
      const first = await runScenario(scripts, builtin.cases[0]!, "referenced", () => {}, setup);
      artifacts.report(runtime.scope, { ...first.report, status: "passed" });
      const beforeCleanup = mock.submissions.length;
      await assert.rejects(() => cleanupRun(runtime), /every scheduled execution/);
      assert.equal(runtime.cleanup.started, false);
      assert.equal(mock.submissions.length, beforeCleanup);
      const arguments_ = first.report.invocation.argumentReferences;
      assert(arguments_.every((ref) => runtime.resources[referenceKey(ref)]?.releasedBy));
      assert.equal((await runtime.provider.getUtxosByOutRef(arguments_)).length, 2);
      const caseScope = "equals_bytearray/unequal/direct";
      const targetScope = step.startsWith("06-") ? "cleanup" : caseScope;
      let interrupted = false;
      const save = artifacts.signed.bind(artifacts);
      const pair = artifacts.signedPair.bind(artifacts);
      const signedHook = t.mock.method(artifacts, "signed", (...args: Parameters<Artifacts["signed"]>) => {
        const record = save(...args);
        if (!interrupted && stage === "signed" && record.name === step && record.scope === targetScope) {
          interrupted = true;
          throw new Error("interrupted lifecycle step");
        }
        return record;
      });
      const pairHook = t.mock.method(artifacts, "signedPair", (...args: Parameters<Artifacts["signedPair"]>) => {
        pair(...args);
        if (stage === "signed" && step === "03-funding") {
          interrupted = true;
          throw new Error("interrupted lifecycle step");
        }
      });
      mock.controls.afterSubmit = () => {
        if (!interrupted && stage === "accepted" && artifacts.find(targetScope, step)?.hash === mock.submissions.at(-1)?.hash) {
          interrupted = true;
          throw new Error("interrupted lifecycle step");
        }
      };
      const execute = async () => {
        const second = await runScenario(scripts, builtin.cases[0]!, "direct", () => {}, setup);
        artifacts.report(runtime.scope, { ...second.report, status: "passed" });
        if (step.startsWith("06-")) await cleanupRun(runtime);
      };
      await assert.rejects(execute, /interrupted lifecycle step/);
      signedHook.mock.restore(); pairHook.mock.restore(); mock.controls.afterSubmit = undefined;
      const saved = artifacts.find(targetScope, step)!;
      assert(saved);
      const next = await reopen(artifacts.directory);
      const resumed = await prepareBuiltin(scripts, next.runtime);
      if (step === "05-mint") assert(await recoverMint(next.runtime, next.artifacts, caseScope, "false"));
      else if (step === "03-funding") {
        const second = await runScenario(scripts, builtin.cases[0]!, "direct", () => {}, resumed);
        next.artifacts.report(caseScope, { ...second.report, status: "passed" });
      }
      await cleanupRun(next.runtime);
      await checkRecorded(next.runtime, next.artifacts);
      assert.equal(next.artifacts.find(targetScope, step)?.cbor, saved.cbor);
      assert.equal(mock.submissions.filter((tx) => tx.hash === saved.hash).length, 1);
      assert.equal(new Set(mock.submissions.map((tx) => tx.hash)).size, mock.submissions.length);
      assert.equal(mock.emulator.getUtxos().length, 3);
      assert.equal(Object.keys(next.runtime.proofBundle!.assets).length, 3);
      assert(arguments_.every((ref) => next.runtime.resources[referenceKey(ref)]?.consumedBy));
      const before = mock.submissions.length;
      next.artifacts.manifest!.status = "passed";
      next.artifacts.saveManifest();
      const completed = await reopen(next.artifacts.directory);
      await checkRecorded(completed.runtime, completed.artifacts);
      await cleanupRun(completed.runtime);
      assert.equal(mock.submissions.length, before);
    });
