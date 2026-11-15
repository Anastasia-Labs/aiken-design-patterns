import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { closeSync, existsSync, mkdtempSync, openSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ARTIFACT_DIRECTORY } from "./blueprint.ts";
import { ARGUMENT_MODES, BUILTINS, CASES, parseBuiltins } from "./builtins.ts";

test("Custom CLI compiles each builtin once and completes all 24 executions in mode order", async (t) => {
  const directory = mkdtempSync(join(tmpdir(), "failure-cli-custom-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const log = join(directory, "custom.log");
  const descriptor = openSync(log, "w");
  let code: number | null;
  try {
    const env: NodeJS.ProcessEnv = { ...process.env, NETWORK: "Custom" };
    delete env.NODE_TEST_CONTEXT;
    const child = spawn(process.execPath, ["--experimental-strip-types", new URL("./run.ts", import.meta.url).pathname], {
      env, stdio: ["ignore", descriptor, descriptor],
    });
    code = await new Promise<number | null>((resolve, reject) => { child.once("error", reject); child.once("close", resolve); });
  } finally { closeSync(descriptor); }
  const output = readFileSync(log, "utf8");
  const runDirectory = /Network: Custom\. Artifacts: (.+)/.exec(output)?.[1]?.trim();
  assert(runDirectory, output);
  t.after(() => rmSync(runDirectory, { recursive: true, force: true }));
  assert.equal(code, 0, output);
  assert.match(output, /Passed 24 executions across 4 builtins/);
  assert.equal((output.match(/Building /g) ?? []).length, 4);
  const report = JSON.parse(readFileSync(join(runDirectory, "report.json"), "utf8"));
  assert.equal(report.status, "passed");
  const expected = parseBuiltins(BUILTINS, CASES).flatMap((builtin) => builtin.cases.flatMap((testCase) =>
    ARGUMENT_MODES.map((mode) => ({ builtin: builtin.name, case: testCase.name, mode, outcome: testCase.outcome,
      report: `${builtin.name}/${testCase.name}/${mode}/report.json` }))));
  assert.deepEqual(report.cases, expected);
  let successes = 0;
  let proofs = 0;
  for (const execution of expected) {
    const result = JSON.parse(readFileSync(join(runDirectory, execution.report), "utf8"));
    assert.equal(result.status, "passed");
    assert.equal(result.mode, execution.mode);
    assert.equal(result.validation.argumentReferencesUnspent, true);
    assert.equal(result.cleanup.complete, true);
    assert(result.cleanup.ordinary && result.cleanup.parameters);
    const current = Object.values(result.resources).filter((resource: any) => resource.confirmed && !resource.consumedBy);
    assert.equal(current.length, result.outcome === "success" ? 2 : 3);
    assert(Object.values(result.resources).filter((resource: any) => resource.role === "reference")
      .every((resource: any) => resource.output.address === result.walletAddress && resource.consumedBy));
    if (result.outcome === "success") { successes++; assert.equal(result.nft, null); }
    else { proofs++; assert.equal(result.nft.quantity, "1"); }
    const records = JSON.parse(readFileSync(join(runDirectory, execution.report.replace("report.json", "transaction-status.json")), "utf8"));
    assert.equal(records.some((record: { name: string }) => record.name === "02-arguments"), execution.mode === "referenced");
    assert(records.some((record: { name: string; status: string }) => record.name.startsWith("06-cleanup-") && record.status === "confirmed"));
  }
  assert.equal(successes, 8);
  assert.equal(proofs, 16);
});

test("CLI rejects invalid configuration before compilation and leaves no artifacts or secrets", async (t) => {
  const directory = mkdtempSync(join(tmpdir(), "failure-cli-config-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const marker = join(directory, "compiler-called");
  const compiler = join(directory, "compiler");
  writeFileSync(compiler, `#!${process.execPath}\nrequire('node:fs').writeFileSync(${JSON.stringify(marker)}, 'called');`, { mode: 0o755 });
  const files = () => existsSync(ARTIFACT_DIRECTORY) ? readdirSync(ARTIFACT_DIRECTORY, { recursive: true }).sort() : [];
  const before = files();
  const cases = [
    { NETWORK: "bad-network-sensitive-value", BLOCKFROST_API_KEY: "sensitive-key", WALLET_SEED: "sensitive-seed" },
    ...["Mainnet", "Preprod", "Preview"].flatMap((NETWORK) => [
      { NETWORK, BLOCKFROST_API_KEY: "", WALLET_SEED: "sensitive-seed" },
      { NETWORK, BLOCKFROST_API_KEY: "sensitive-key", WALLET_SEED: "" },
      { NETWORK, BLOCKFROST_API_KEY: "sensitive-key", WALLET_SEED: "sensitive-seed" },
    ]),
  ];
  for (const configuration of cases) {
    const env: NodeJS.ProcessEnv = { ...process.env, ...configuration, AIKEN: compiler };
    // Exercise an ordinary CLI process, outside Node's inherited test reporter.
    delete env.NODE_TEST_CONTEXT;
    const log = join(directory, "cli.log");
    const descriptor = openSync(log, "w");
    let code: number | null;
    try {
      const child = spawn(process.execPath, ["--experimental-strip-types", new URL("./run.ts", import.meta.url).pathname], {
        env, stdio: ["ignore", descriptor, descriptor],
      });
      code = await new Promise<number | null>((resolve, reject) => { child.once("error", reject); child.once("close", resolve); });
    } finally { closeSync(descriptor); }
    assert.equal(code, 1);
    const output = readFileSync(log, "utf8");
    assert.match(output, /NETWORK must|BLOCKFROST_API_KEY is required|WALLET_SEED/);
    assert(!output.includes("sensitive"));
  }
  assert(!existsSync(marker));
  assert.deepEqual(files(), before);
});

test("CLI requires a v4 live run directory and rejects resume with builtin selection", async (t) => {
  const directory = mkdtempSync(join(tmpdir(), "failure-cli-resume-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const [args, expected] of [
    [["--resume", directory, "--builtin", "bls12_381_g1_uncompress"], /--resume cannot be combined/],
    [["--resume", directory], /Missing or corrupt manifest/],
  ] as const) {
    const log = join(directory, "resume.log");
    const descriptor = openSync(log, "w");
    try {
      const child = spawn(process.execPath, ["--experimental-strip-types", new URL("./run.ts", import.meta.url).pathname, ...args], {
        env: { ...process.env, NETWORK: "Custom" }, stdio: ["ignore", descriptor, descriptor],
      });
      assert.equal(await new Promise<number | null>((resolve, reject) => {
        child.once("error", reject); child.once("close", resolve);
      }), 1);
    } finally { closeSync(descriptor); }
    assert.match(readFileSync(log, "utf8"), expected);
  }
});
