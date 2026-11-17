import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { before, test, type TestContext } from "node:test";
import { Data, credentialToAddress, getAddressDetails } from "@lucid-evolution/lucid";
import { Artifacts, validateResumeIdentity } from "./artifacts.ts";
import { buildValidators, type Validators } from "./blueprint.ts";
import { ARGUMENT_MODES, parseBuiltins } from "./builtins.ts";
import { LiveProvider } from "./live-provider.ts";
import { savedChain } from "./case-chain.ts";
import { MOCK_KEY, MOCK_SEED, mockBlockfrost } from "./mock-blockfrost.ts";
import { createRuntime, ordinaryFunding, referenceKey, submitTransaction, type Runtime } from "./runtime.ts";
import { checkRecorded } from "./resume.ts";
import { cleanupRun, prepareBuiltin, resumeCaseChain, runScenario } from "./scenario.ts";

const builtin = parseBuiltins(["equals_bytearray(ByteArray, ByteArray) -> Bool"], [
  `equals_bytearray/unequal|false|${Data.to(["aa", "bb"])}`,
])[0]!;
let scripts: Validators;
before(async () => { scripts = await buildValidators(builtin, undefined, "Preprod"); });

async function fixture(t: TestContext, selection = builtin) {
  const mock = mockBlockfrost("Preprod");
  t.mock.method(globalThis, "fetch", mock.fetcher);
  const root = mkdtempSync(join(tmpdir(), "failure-resume-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const controller = new AbortController();
  const runtime = await createRuntime({ network: "Preprod", apiKey: MOCK_KEY, seed: MOCK_SEED }, controller.signal);
  assert(runtime.provider instanceof LiveProvider);
  let requestTime = Date.now();
  t.mock.method(runtime.provider.requests, "now", () => requestTime);
  t.mock.method(runtime.provider.requests, "sleep", async (ms: number, signal?: AbortSignal) => { signal?.throwIfAborted(); requestTime += ms; });
  const artifacts = new Artifacts(root, "Preprod");
  const compiled = selection === builtin ? scripts : { ...scripts, builtin: selection };
  artifacts.initialize("Preprod", runtime.walletAddress, getAddressDetails(runtime.walletAddress).paymentCredential!.hash, [selection], [compiled]);
  runtime.artifacts = artifacts;
  runtime.scope = "setup";
  return { mock, runtime, artifacts, controller, compiled };
}
async function reopen(directory: string) {
  const artifacts = Artifacts.resume(directory);
  const runtime = await createRuntime({ network: "Preprod", apiKey: MOCK_KEY, seed: MOCK_SEED });
  validateResumeIdentity(artifacts.manifest!, runtime.walletAddress, "Preprod");
  runtime.artifacts = artifacts;
  runtime.scope = "setup";
  let now = 0;
  runtime.now = () => now;
  runtime.sleep = async (ms) => { now += ms; };
  return { artifacts, runtime };
}
async function payment(runtime: Runtime) {
  const funding = await ordinaryFunding(runtime);
  const completed = await runtime.lucid.newTx().collectFrom([funding[0]!]).pay.ToAddress(runtime.walletAddress, { lovelace: 10_000_000n })
    .complete({ coinSelection: false });
  return completed.sign.withWallet().complete();
}

for (const accepted of [false, true]) test(`one saved transaction resumes exact bytes (accepted=${accepted})`, async (t) => {
  const { mock, runtime, artifacts } = await fixture(t);
  runtime.scope = "payment";
  const signed = await payment(runtime);
  if (accepted) {
    mock.controls.afterSubmit = () => { throw new Error("lost response"); };
    await assert.rejects(() => submitTransaction(runtime, "pay", signed.toCBOR()), /lost response/);
    mock.controls.afterSubmit = undefined;
  } else artifacts.signed("payment", "pay", signed.toCBOR(), signed.toHash());
  const next = await reopen(artifacts.directory);
  next.runtime.scope = "payment";
  await submitTransaction(next.runtime, "pay", signed.toCBOR());
  assert.deepEqual(mock.submissions.map((tx) => tx.cbor), [signed.toCBOR()]);
  assert.equal(next.artifacts.find("payment", "pay")!.status, "confirmed");
  assert.deepEqual(JSON.parse(readFileSync(join(artifacts.directory, "transactions.json"), "utf8")), [{ cbor: signed.toCBOR() }]);
});

test("connection failures during reads recover and a lost submission response resumes without replay", async (t) => {
  const { mock, runtime, artifacts } = await fixture(t);
  runtime.scope = "payment";
  const signed = await payment(runtime);
  mock.controls.autoConfirm = false;
  mock.controls.afterSubmit = () => { throw new TypeError("fetch failed"); };
  await assert.rejects(() => submitTransaction(runtime, "pay", signed.toCBOR()), /fetch failed/);
  assert.equal(mock.submissions.length, 1);
  assert.equal(artifacts.find("payment", "pay")!.cbor, signed.toCBOR());
  mock.controls.afterSubmit = undefined;
  let statusFailures = 2;
  let addressFailures = 1;
  let mempoolSeen = false;
  t.mock.method(globalThis, "fetch", async (...args: Parameters<typeof fetch>) => {
    const path = new URL(String(args[0])).pathname.replace("/api/v0", "");
    if (path === `/txs/${signed.toHash()}` && statusFailures > 0) { statusFailures--; throw new TypeError("fetch failed"); }
    if (path.startsWith("/addresses/") && addressFailures > 0) { addressFailures--; throw new TypeError("fetch failed"); }
    const response = await mock.fetcher(...args);
    if (path === `/mempool/${signed.toHash()}` && response.ok) { mempoolSeen = true; mock.controls.autoConfirm = true; }
    return response;
  });
  const next = await reopen(artifacts.directory);
  assert(next.runtime.provider instanceof LiveProvider);
  const sleeps: number[] = [];
  t.mock.method(next.runtime.provider.requests, "sleep", async (ms: number) => { sleeps.push(ms); });
  next.runtime.scope = "payment";
  await submitTransaction(next.runtime, "pay", signed.toCBOR());
  assert(mempoolSeen);
  assert.equal(sleeps.length, 3);
  assert.equal(mock.submissions.length, 1);
  assert.equal(next.artifacts.find("payment", "pay")!.status, "confirmed");
  assert.equal(next.artifacts.find("payment", "pay")!.cbor, signed.toCBOR());
});

test("case preparation and confirmation tolerate transient reads without duplicate submissions", async (t) => {
  const { mock, runtime, artifacts } = await fixture(t);
  const setup = await prepareBuiltin(scripts, runtime);
  let protocolFailure = true;
  let addressFailure = true;
  let statusFailure = true;
  t.mock.method(globalThis, "fetch", async (...args: Parameters<typeof fetch>) => {
    const path = new URL(String(args[0])).pathname.replace("/api/v0", "");
    if (path === "/epochs/latest/parameters" && protocolFailure) { protocolFailure = false; return new Response(null, { status: 503 }); }
    if (path.startsWith("/addresses/") && addressFailure) { addressFailure = false; throw new TypeError("fetch failed"); }
    if (/^\/txs\/[0-9a-f]+$/.test(path) && statusFailure) { statusFailure = false; return new Response(null, { status: 502 }); }
    return mock.fetcher(...args);
  });
  const result = await runScenario(scripts, builtin.cases[0]!, "referenced", () => {}, setup);
  assert(result.report.outcome !== "success");
  assert.equal(result.report.nft.quantity, 1n);
  assert(!protocolFailure && !addressFailure && !statusFailure);
  const records = artifacts.records.filter((record) => record.scope === runtime.scope);
  assert.equal(records.length, 4);
  assert(records.every((record) => record.status === "confirmed"));
  assert(records.every((record) => mock.submissions.filter((submission) => submission.cbor === record.cbor).length === 1));
});

for (const mode of ARGUMENT_MODES) {
  const names = [...(mode === "referenced" ? ["02-arguments"] : []), "03-funding", "04-failed-withdrawal", "05-mint"];
  const scope = `equals_bytearray/unequal/${mode}`;
  for (const position of names) for (const failure of ["interruption", "lost-response", "rejection"] as const) {
    test(`${mode}: ${failure} at ${position} preserves the complete chain and resumes exact bytes`, async (t) => {
      const { mock, runtime, artifacts, controller } = await fixture(t);
      const setup = await prepareBuiltin(scripts, runtime);
      const setupCount = mock.submissions.length;
      const submit = runtime.provider.submitTx.bind(runtime.provider);
      const hook = t.mock.method(runtime.provider, "submitTx", async (cbor: string) => {
        const target = artifacts.find(scope, position);
        if (cbor === target?.cbor && failure === "rejection") throw new Error("submission rejected");
        const hash = await submit(cbor);
        if (cbor === target?.cbor) {
          if (failure === "interruption") controller.abort(new Error("interrupted case"));
          if (failure === "lost-response") throw new Error("lost response");
        }
        return hash;
      });
      await assert.rejects(() => runScenario(scripts, builtin.cases[0]!, mode, () => {}, setup), /interrupted case|lost response|submission rejected/);
      hook.mock.restore();
      const checkpoint = artifacts.manifest!.cases[scope]!;
      assert(checkpoint.chain);
      assert.deepEqual(checkpoint.chain.transactions.map((entry) => entry.name), names);
      const saved = names.map((name) => artifacts.find(scope, name)!);
      assert(saved.every((record) => record.cbor));
      const index = names.indexOf(position);
      assert.equal(mock.submissions.length - setupCount, index + (failure === "rejection" ? 0 : 1));
      const next = await reopen(artifacts.directory);
      const reused = await prepareBuiltin(scripts, next.runtime);
      const result = await runScenario(scripts, builtin.cases[0]!, mode, () => {}, reused);
      assert(result.report.outcome !== "success");
      assert.equal(result.report.transactions.mint, saved.at(-1)!.hash);
      for (const record of saved) {
        assert.equal(next.artifacts.find(scope, record.name)!.cbor, record.cbor);
        assert.equal(mock.submissions.filter((tx) => tx.cbor === record.cbor).length, 1);
      }
      assert.equal(next.runtime.recoveryScans, 1);
      assert.equal(next.artifacts.manifest!.cases[scope]!.stage, "completed");
      assert.equal(next.artifacts.manifest!.reports[scope]!.status, "passed");
      await checkRecorded(next.runtime, next.artifacts);
    });
  }
}

for (const mode of ARGUMENT_MODES) for (const position of [...(mode === "referenced" ? ["02-arguments"] : []), "03-funding", "04-successful-withdrawal"])
  test(`${mode}: a successful case resumes a lost response at ${position}`, async (t) => {
    const selection = parseBuiltins(["equals_bytearray(ByteArray, ByteArray) -> Bool"], [`equals_bytearray/equal|success|${Data.to(["aa", "aa"])}`])[0]!;
    const { mock, runtime, artifacts, compiled } = await fixture(t, selection);
    const setup = await prepareBuiltin(compiled, runtime);
    const scope = `equals_bytearray/equal/${mode}`;
    mock.controls.afterSubmit = () => {
      if (artifacts.find(scope, position)?.hash === mock.submissions.at(-1)?.hash) throw new Error("lost success response");
    };
    await assert.rejects(() => runScenario(compiled, selection.cases[0]!, mode, () => {}, setup), /lost success response/);
    mock.controls.afterSubmit = undefined;
    const records = artifacts.records.filter((record) => record.scope === scope);
    const next = await reopen(artifacts.directory);
    const reused = await prepareBuiltin(compiled, next.runtime);
    const result = await runScenario(compiled, selection.cases[0]!, mode, () => {}, reused);
    assert.equal(result.report.outcome, "success");
    assert.equal(result.report.nft, null);
    assert.equal(result.transactions["05-mint"], undefined);
    for (const record of records) assert.equal(mock.submissions.filter((transaction) => transaction.cbor === record.cbor).length, 1);
    await checkRecorded(next.runtime, next.artifacts);
  });

test("atomically journaled case includes proof bytes before any case broadcast", async (t) => {
  const { mock, runtime, artifacts } = await fixture(t);
  const setup = await prepareBuiltin(scripts, runtime);
  const before = mock.submissions.length;
  const journal = artifacts.journalChain.bind(artifacts);
  const hook = t.mock.method(artifacts, "journalChain", (...args: Parameters<Artifacts["journalChain"]>) => {
    journal(...args);
    throw new Error("interrupted saved case");
  });
  await assert.rejects(() => runScenario(scripts, builtin.cases[0]!, "referenced", () => {}, setup), /interrupted saved case/);
  hook.mock.restore();
  assert.equal(mock.submissions.length, before);
  const next = await reopen(artifacts.directory);
  const scope = "equals_bytearray/unequal/referenced";
  assert.equal(savedChain(next.runtime, scope)!.transactions.length, 4);
  assert(await resumeCaseChain(next.runtime, scope));
  assert.equal(mock.submissions.length, before + 4);
});

for (const confirmedParents of [0, 1, 2]) test(`resume projects pending parents with ${confirmedParents} already confirmed`, async (t) => {
  const { mock, runtime, artifacts } = await fixture(t);
  const setup = await prepareBuiltin(scripts, runtime);
  const setupCount = mock.submissions.length;
  const scope = "equals_bytearray/unequal/referenced";
  mock.controls.autoConfirm = false;
  mock.controls.afterSubmit = () => {
    if (mock.submissions.length === setupCount + 3) throw new Error("lost withdrawal response");
  };
  await assert.rejects(() => runScenario(scripts, builtin.cases[0]!, "referenced", () => {}, setup), /lost withdrawal response/);
  mock.controls.afterSubmit = undefined;
  mock.confirm(confirmedParents);
  const next = await reopen(artifacts.directory);
  mock.controls.afterSubmit = () => { if (mock.submissions.length === setupCount + 4) mock.controls.autoConfirm = true; };
  assert(await resumeCaseChain(next.runtime, scope));
  assert.equal(mock.submissions.length, setupCount + 4);
  assert.equal(new Set(mock.submissions.map((tx) => tx.hash)).size, mock.submissions.length);
  assert(next.runtime.proofBundle);
});

test("an unknown transaction with unavailable inputs waits without broadcasting descendants", async (t) => {
  const { mock, runtime, artifacts } = await fixture(t);
  const setup = await prepareBuiltin(scripts, runtime);
  const count = mock.submissions.length;
  const scope = "equals_bytearray/unequal/referenced";
  mock.controls.afterSubmit = () => { throw new Error("lost argument response"); };
  await assert.rejects(() => runScenario(scripts, builtin.cases[0]!, "referenced", () => {}, setup), /lost argument response/);
  mock.controls.afterSubmit = undefined;
  mock.confirm();
  mock.controls.hideConfirmations = true;
  const next = await reopen(artifacts.directory);
  next.runtime.confirmationTimeout = 6_000;
  await assert.rejects(() => resumeCaseChain(next.runtime, scope), /Confirmation timed out/);
  assert.equal(mock.submissions.length, count + 1);
});

test("saved case uses its producing snapshot when protocol fees change", async (t) => {
  const { mock, runtime, artifacts } = await fixture(t);
  const setup = await prepareBuiltin(scripts, runtime);
  mock.controls.afterSubmit = () => { throw new Error("lost funding response"); };
  await assert.rejects(() => runScenario(scripts, builtin.cases[0]!, "direct", () => {}, setup), /lost funding response/);
  mock.controls.afterSubmit = undefined;
  const changed = mock.rawParameters(); changed.min_fee_a = Number(changed.min_fee_a) + 1; mock.setParameters(changed);
  const next = await reopen(artifacts.directory);
  const scope = "equals_bytearray/unequal/direct";
  const before = savedChain(next.runtime, scope)!;
  assert.notEqual(before.protocol.minFeeA, next.runtime.parameters.minFeeA);
  await resumeCaseChain(next.runtime, scope);
  assert.deepEqual(next.artifacts.manifest!.cases[scope]!.chain!.transactions, artifacts.manifest!.cases[scope]!.chain!.transactions);
});

test("resume refreshes delayed confirmed parent outputs before broadcasting an unknown child", async (t) => {
  const { mock, runtime, artifacts } = await fixture(t);
  const setup = await prepareBuiltin(scripts, runtime);
  const scope = "equals_bytearray/unequal/referenced";
  mock.controls.afterSubmit = () => { throw new Error("lost argument response"); };
  await assert.rejects(() => runScenario(scripts, builtin.cases[0]!, "referenced", () => {}, setup), /lost argument response/);
  mock.controls.afterSubmit = undefined;
  mock.confirm();
  mock.controls.indexingDelay = 4;
  const next = await reopen(artifacts.directory);
  let sleeps = 0;
  const sleep = next.runtime.sleep;
  next.runtime.sleep = async (ms) => { sleeps++; await sleep(ms); };
  assert(await resumeCaseChain(next.runtime, scope));
  assert(sleeps >= 1);
  for (const record of next.artifacts.records) assert.equal(mock.submissions.filter((transaction) => transaction.hash === record.hash).length, 1);
});

test("shared bootstrap resumes accepted bytes", async (t) => {
  const { mock, runtime, artifacts } = await fixture(t);
  mock.controls.afterSubmit = () => { if (mock.submissions.length === 2) throw new Error("lost bootstrap response"); };
  await assert.rejects(() => prepareBuiltin(scripts, runtime), /lost bootstrap response/);
  mock.controls.afterSubmit = undefined;
  const next = await reopen(artifacts.directory);
  const setup = await prepareBuiltin(scripts, next.runtime);
  assert.equal(setup.parametersInput.txHash, artifacts.find("setup", "01-setup-00")!.hash);
  assert.equal(mock.submissions.length, 2);
});

test("verification detects external spends and fetches each transaction observation once", async (t) => {
  const { mock, runtime, artifacts } = await fixture(t);
  const setup = await prepareBuiltin(scripts, runtime);
  const result = await runScenario(scripts, builtin.cases[0]!, "referenced", () => {}, setup);
  const start = mock.requests.length;
  await checkRecorded(runtime, artifacts);
  const observations = mock.requests.slice(start).filter((path) => /^\/txs\/[0-9a-f]+$/.test(path));
  assert.equal(observations.length, artifacts.records.length);
  assert.equal(new Set(observations).size, observations.length);
  const [argument] = await runtime.provider.getUtxosByOutRef(result.report.invocation.argumentReferences.slice(0, 1));
  assert(argument);
  const completed = await runtime.lucid.newTx().collectFrom([argument]).complete({ coinSelection: false });
  await (await completed.sign.withWallet().complete()).submit(); mock.confirm();
  const count = mock.submissions.length;
  await assert.rejects(() => checkRecorded(runtime, artifacts), /unavailable/);
  const next = await reopen(artifacts.directory);
  next.runtime.confirmationTimeout = 6_000;
  await assert.rejects(() => resumeCaseChain(next.runtime, "equals_bytearray/unequal/referenced"), /Confirmation timed out/);
  assert.equal(mock.submissions.length, count);
});

for (const stage of ["signed", "accepted"]) test(`cleanup ${stage} resumes once and completed runs make no submissions`, async (t) => {
  const { mock, runtime, artifacts } = await fixture(t);
  const setup = await prepareBuiltin(scripts, runtime);
  for (const mode of ARGUMENT_MODES) await runScenario(scripts, builtin.cases[0]!, mode, () => {}, setup);
  const save = artifacts.signed.bind(artifacts);
  const hook = t.mock.method(artifacts, "signed", (...args: Parameters<Artifacts["signed"]>) => {
    const record = save(...args);
    if (stage === "signed" && record.scope === "cleanup") throw new Error("interrupted cleanup");
    return record;
  });
  mock.controls.afterSubmit = () => { if (stage === "accepted") throw new Error("interrupted cleanup"); };
  await assert.rejects(() => cleanupRun(runtime), /interrupted cleanup/);
  hook.mock.restore(); mock.controls.afterSubmit = undefined;
  const saved = artifacts.find("cleanup", "06-cleanup-00")!;
  const next = await reopen(artifacts.directory);
  await prepareBuiltin(scripts, next.runtime);
  await cleanupRun(next.runtime); await checkRecorded(next.runtime, next.artifacts);
  assert.equal(next.artifacts.find("cleanup", saved.name)!.cbor, saved.cbor);
  assert.equal(mock.submissions.filter((tx) => tx.hash === saved.hash).length, 1);
  assert.equal(mock.confirmed.getUtxos().length, 3);
  assert.equal(Object.keys(next.runtime.proofBundle!.assets).length, 3);
  assert(Object.values(next.runtime.resources).filter((resource) => resource.role === "argument").every((resource) => resource.consumedBy));
  next.artifacts.manifest!.status = "passed"; next.artifacts.saveManifest();
  const count = mock.submissions.length;
  const done = await reopen(artifacts.directory); await checkRecorded(done.runtime, done.artifacts); await cleanupRun(done.runtime);
  assert.equal(mock.submissions.length, count);
});

test("resume rejects other versions and tampered complete case checkpoints", async (t) => {
  const { runtime, artifacts } = await fixture(t);
  const setup = await prepareBuiltin(scripts, runtime);
  await runScenario(scripts, builtin.cases[0]!, "referenced", () => {}, setup);
  const scope = "equals_bytearray/unequal/referenced";
  const path = join(artifacts.directory, "manifest.json");
  const original = readFileSync(path, "utf8");
  for (const mutate of [
    ...[1, 2, 3, 4, 6].map((version) => (value: any) => { value.version = version; }),
    (value: any) => { value.cases[scope].chain.transactions.pop(); },
    (value: any) => { value.cases[scope].chain.transactions.reverse(); },
    (value: any) => { value.cases[scope].chain.transactions[2].valid = true; },
    (value: any) => { value.cases[scope].chain.transactions[3].dependencies = []; },
    (value: any) => { value.cases[scope].chain.present.pop(); },
    (value: any) => { value.cases[scope].mode = "direct"; },
    (value: any) => { value.cases[scope].argumentReferences.pop(); },
    (value: any) => { value.cases[scope].argumentIndexes[1] = value.cases[scope].argumentIndexes[0]; },
    (value: any) => { value.cases[scope].redeemer = Data.void(); },
    (value: any) => { value.transactions[0].hash = "ff".repeat(32); },
    (value: any) => { value.scripts[builtin.name].hashes.mint = "ff".repeat(28); },
  ]) {
    const value = JSON.parse(original); mutate(value); writeFileSync(path, JSON.stringify(value));
    assert.throws(() => Artifacts.resume(artifacts.directory));
  }
  writeFileSync(path, "{"); assert.throws(() => Artifacts.resume(artifacts.directory), /Missing or corrupt manifest/);
  rmSync(path); assert(!existsSync(path)); assert.throws(() => Artifacts.resume(artifacts.directory), /Missing or corrupt manifest/);
  writeFileSync(path, original);
  const resumed = Artifacts.resume(artifacts.directory);
  assert.throws(() => validateResumeIdentity(resumed.manifest!, runtime.walletAddress, "Mainnet"), /NETWORK conflicts/);
  assert.throws(() => validateResumeIdentity(resumed.manifest!, credentialToAddress("Preprod", { type: "Key", hash: "aa".repeat(28) })), /Wallet does not match/);
  assert.deepEqual(resumed.manifest!.selection, [builtin]);
  assert(resumed.manifest!.resources[referenceKey(runtime.proofBundle!)]);
});
