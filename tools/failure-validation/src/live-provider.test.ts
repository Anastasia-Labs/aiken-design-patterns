import assert from "node:assert/strict";
import { test } from "node:test";
import { applySingleCborEncoding, type Script } from "@lucid-evolution/lucid";
import { LiveProvider } from "./live-provider.ts";
import { ProviderRequests } from "./provider-requests.ts";

const hash = "ab".repeat(32);
const ref = { txHash: hash, outputIndex: 0 };
const output = { tx_hash: hash, output_index: 0, address: "wallet", amount: [{ unit: "lovelace", quantity: "2000000" }] };
const provider = () => new LiveProvider("https://mock.test", "test-key");

test("converting 1,000 ordinary outputs performs no requests or sleeps", async (t) => {
  t.mock.method(globalThis, "fetch", async () => { throw new Error("Unexpected request"); });
  const requests = new ProviderRequests(Date.now, async () => { throw new Error("Unexpected sleep"); });
  const live = new LiveProvider("https://mock.test", "test-key", undefined, requests);
  assert.equal((await live.convert(Array.from({ length: 1000 }, (_, output_index) => ({ ...output, output_index })))).length, 1000);
  assert.equal(live.currentOutputs.size, 0, "Conversions cannot put pending outputs in the confirmed cache.");
});

test("script metadata and CBOR are cached and concurrent conversions share requests", async (t) => {
  const requests: string[] = [];
  const script: Script = { type: "PlutusV3", script: "424101" };
  t.mock.method(globalThis, "fetch", async (input: string) => {
    requests.push(input);
    await new Promise<void>((resolve) => setImmediate(resolve));
    return Response.json(input.endsWith("/cbor") ? { cbor: applySingleCborEncoding(script.script) } : { type: "plutusV3" });
  });
  const live = provider();
  const outputs = [{ ...output, reference_script_hash: "aa".repeat(28) }];
  const [first, second] = await Promise.all([live.convert(outputs), live.convert(outputs)]);
  assert.deepEqual(first, second);
  assert.equal(requests.length, 2);
  await live.convert(Array(100).fill(outputs[0]));
  assert.equal(requests.length, 2);
});

test("failed script lookups are evicted and can be retried", async (t) => {
  let failed = true;
  let count = 0;
  t.mock.method(globalThis, "fetch", async (input: string) => {
    count++;
    if (failed) return new Response(null, { status: 500 });
    return Response.json(input.endsWith("/cbor") ? { cbor: "4101" } : { type: "plutusV3" });
  });
  const live = provider();
  await assert.rejects(() => live.script("aa"), /HTTP 500/);
  failed = false;
  await live.script("aa");
  assert.equal(count, 3);
});

test("historical address discovery never establishes spendability and known addresses avoid history", async (t) => {
  let current = [output];
  const requests: string[] = [];
  t.mock.method(globalThis, "fetch", async (input: string) => {
    requests.push(input);
    return Response.json(input.includes("/txs/") ? { outputs: [{ ...output, consumed_by_tx: null }] } : current);
  });
  const live = provider();
  assert.equal((await live.getUtxosByOutRef([ref])).length, 1);
  current = [];
  assert.deepEqual(await live.getUtxosByOutRef([ref]), []);
  assert.equal(requests.filter((path) => path.includes("/txs/")).length, 1);
  assert.equal(requests.filter((path) => path.includes("/addresses/")).length, 2);
  live.remember([{ ...ref, address: "wallet", assets: { lovelace: 2_000_000n } }]);
  assert.deepEqual(live.currentOutputs.get("wallet"), []);
});

test("557 wallet outputs need six paginated requests", async (t) => {
  let count = 0;
  t.mock.method(globalThis, "fetch", async (input: string) => {
    count++;
    const page = Number(new URL(input).searchParams.get("page"));
    return Response.json(Array.from({ length: page <= 5 ? 100 : 57 }, (_, index) => ({ ...output, output_index: (page - 1) * 100 + index })));
  });
  assert.equal((await provider().getUtxos("wallet")).length, 557);
  assert.equal(count, 6);
});

test("observations distinguish pending, unknown, and confirmed validity without a second transaction read", async (t) => {
  let state = "pending";
  const paths: string[] = [];
  t.mock.method(globalThis, "fetch", async (input: string) => {
    paths.push(new URL(input).pathname);
    if (state === "confirmed") return Response.json({ block: hash, block_height: 2, slot: 3, valid_contract: false });
    return state === "pending" && input.includes("/mempool/") ? Response.json({ tx_hash: hash }) : new Response(null, { status: 404 });
  });
  const live = provider();
  assert.equal((await live.observe(hash)).status, "pending");
  state = "unknown"; assert.equal((await live.observe(hash)).status, "not_found");
  state = "confirmed";
  const observation = await live.observe(hash);
  assert.equal(observation.status, "confirmed"); assert.equal(observation.valid, false);
  assert.equal(paths.length, 5);
});

test("request control bounds concurrency to four and enforces a 100-request burst with ten per second", async (t) => {
  let now = 0;
  let active = 0;
  let maximum = 0;
  const times: number[] = [];
  t.mock.method(globalThis, "fetch", async () => {
    times.push(now); active++; maximum = Math.max(maximum, active);
    await new Promise<void>((resolve) => setImmediate(resolve));
    active--; return Response.json({});
  });
  const requests = new ProviderRequests(() => now, async (ms) => { now += ms; });
  await Promise.all(Array.from({ length: 112 }, () => requests.request("https://mock.test")));
  assert.equal(maximum, 4);
  assert.equal(times.filter((time) => time === 0).length, 100);
  times.forEach((time, index) => assert(index + 1 <= 100 + Math.floor(time / 100)));
});

test("request slots remain occupied until response bodies finish", async (t) => {
  const streams: ReadableStreamDefaultController<Uint8Array>[] = [];
  t.mock.method(globalThis, "fetch", async () => new Response(new ReadableStream<Uint8Array>({ start(controller) { streams.push(controller); } })));
  const requests = new ProviderRequests();
  const running = Array.from({ length: 5 }, () => requests.request("https://mock.test"));
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(streams.length, 4);
  for (const stream of [...streams]) { stream.enqueue(new Uint8Array([1])); stream.close(); }
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(streams.length, 5);
  streams[4]!.close();
  await Promise.all(running);
});

for (const retryAfter of ["2", "Thu, 01 Jan 1970 00:00:02 GMT"]) test(`429 retries honor Retry-After ${retryAfter}`, async (t) => {
  let calls = 0; let now = 0; const sleeps: number[] = [];
  t.mock.method(globalThis, "fetch", async () => ++calls < 3
    ? new Response(null, { status: 429, headers: { "retry-after": retryAfter } }) : Response.json({}));
  const requests = new ProviderRequests(() => now, async (ms) => { sleeps.push(ms); now += ms; });
  assert((await requests.request("https://mock.test")).ok);
  assert.equal(calls, 3);
  assert.equal(sleeps[0], 2000);
  if (retryAfter === "2") assert.deepEqual(sleeps, [2000, 2000]);
});

test("429 retries are bounded and ambiguous transport errors are never retried", async (t) => {
  let calls = 0;
  const hook = t.mock.method(globalThis, "fetch", async () => { calls++; return new Response(null, { status: 429 }); });
  const requests = new ProviderRequests(Date.now, async () => {});
  assert.equal((await requests.request("https://mock.test")).status, 429);
  assert.equal(calls, 4);
  hook.mock.restore(); calls = 0;
  t.mock.method(globalThis, "fetch", async () => { calls++; throw new Error("lost submission response"); });
  await assert.rejects(() => requests.request("https://mock.test", { method: "POST" }), /lost submission response/);
  assert.equal(calls, 1);
});

test("ambiguous successful submission responses stop without retrying", async (t) => {
  let value: unknown = null;
  let calls = 0;
  t.mock.method(globalThis, "fetch", async () => { calls++; return Response.json(value); });
  const live = provider();
  for (const response of [null, { error: "unknown acceptance" }, "invalid-hash"]) {
    value = response;
    const before = calls;
    await assert.rejects(() => live.submitTx("80"), /Ambiguous transaction submission response/);
    assert.equal(calls - before, 1);
  }
});

test("aborting a queued request prevents it from reaching the service", async (t) => {
  const releases: (() => void)[] = [];
  let calls = 0;
  t.mock.method(globalThis, "fetch", async () => {
    calls++; await new Promise<void>((resolve) => releases.push(resolve)); return Response.json({});
  });
  const requests = new ProviderRequests();
  const running = Array.from({ length: 4 }, () => requests.request("https://mock.test"));
  await new Promise<void>((resolve) => setImmediate(resolve));
  const controller = new AbortController();
  const queued = requests.request("https://mock.test", { signal: controller.signal });
  controller.abort(new Error("stop queued"));
  await assert.rejects(queued, /stop queued/);
  releases.forEach((release) => release()); await Promise.all(running);
  assert.equal(calls, 4);
});
