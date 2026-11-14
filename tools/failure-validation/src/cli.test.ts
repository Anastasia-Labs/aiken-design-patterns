import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { closeSync, existsSync, mkdtempSync, openSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ARTIFACT_DIRECTORY } from "./blueprint.ts";

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

test("CLI requires a v2 live run directory and rejects resume with builtin selection", async (t) => {
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
