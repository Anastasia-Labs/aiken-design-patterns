import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test, type TestContext } from "node:test";
import { parseBuiltins } from "./builtins.ts";
import { ENVIRONMENT_PATH, GENERATED_END, GENERATED_START, generateEnvironment, replaceEnvironment, withBuiltinProject } from "./environment.ts";

const builtin = parseBuiltins(
  ["bls12_381_g1_uncompress(ByteArray) -> G1Element"],
  ["bls12_381_g1_uncompress/empty|builtin-error|9f40ff"],
)[0]!;
const source = `use aiken/builtin\n\n${GENERATED_START}\nold content\n${GENERATED_END}\n\n// Preserve this.  \n`;

test("replacement preserves unrelated content and CRLF line endings", () => {
  const original = source.replaceAll("\n", "\r\n");
  const updated = replaceEnvironment(original, generateEnvironment(builtin));
  assert(updated.startsWith("use aiken/builtin\r\n\r\n"));
  assert(updated.endsWith("\r\n\r\n// Preserve this.  \r\n"));
  assert(!/(?<!\r)\n/.test(updated));
  assert.equal(replaceEnvironment(updated, generateEnvironment(builtin)), updated);
});

test("ambiguous or missing markers cannot rewrite the environment", () => {
  for (const malformed of [
    source.replace(GENERATED_START, ""), source.replace(GENERATED_END, ""),
    `${source}${GENERATED_START}\n`, `${source}${GENERATED_END}\n`,
    `${GENERATED_END}\n${GENERATED_START}\n`,
    source.replace(GENERATED_START, `prefix ${GENERATED_START}`),
    source.replace(GENERATED_END, `${GENERATED_END} trailing`),
  ]) assert.throws(() => replaceEnvironment(malformed, generateEnvironment(builtin)), /markers/);
});

test("isolated projects preserve source bytes, allow overlapping builds, and clean up after success or error", async (t) => {
  const sourceRoot = mkdtempSync(join(tmpdir(), "failure-source-"));
  t.after(() => rmSync(sourceRoot, { recursive: true, force: true }));
  for (const name of ["env", "lib", "validators", "build/packages"]) mkdirSync(join(sourceRoot, name), { recursive: true });
  for (const name of ["aiken.toml", "aiken.lock", "lib/example.ak", "build/packages/example.ak"]) writeFileSync(join(sourceRoot, name), name);
  const original = Buffer.from(source.replaceAll("\n", "\r\n"));
  writeFileSync(join(sourceRoot, "env/testnet.ak"), original);
  for (const fail of [false, true]) {
    let buildDirectory = "";
    const build = withBuiltinProject(builtin, async (directory) => {
      buildDirectory = directory;
      assert.notEqual(directory, sourceRoot);
      assert(readFileSync(join(directory, "env/failure_tooling.ak"), "utf8").includes("builtin.bls12_381_g1_uncompress"));
      assert.deepEqual(readFileSync(join(sourceRoot, "env/testnet.ak")), original);
      assert.equal(readFileSync(join(directory, "lib/example.ak"), "utf8"), "lib/example.ak");
      writeFileSync(join(directory, "build/packages/example.ak"), "private cache");
      assert.equal(readFileSync(join(sourceRoot, "build/packages/example.ak"), "utf8"), "build/packages/example.ak");
      await withBuiltinProject(builtin, async (other) => { assert.notEqual(other, directory); }, sourceRoot);
      if (fail) throw new Error("compiler failed");
      return 42;
    }, sourceRoot);
    if (fail) await assert.rejects(build, /compiler failed/);
    else assert.equal(await build, 42);
    assert.equal(existsSync(buildDirectory), false);
    assert.deepEqual(readFileSync(join(sourceRoot, "env/testnet.ak")), original);
  }
});

function startCompiler(t: TestContext, wait: boolean) {
  const directory = mkdtempSync(join(tmpdir(), "failure-compiler-"));
  const compiler = join(directory, "fake compiler");
  writeFileSync(compiler, `#!${process.execPath}\n
if (!process.stdout.isTTY) process.exit(99);
console.log("COMPILER_READY " + process.cwd());
${wait ? "setInterval(() => {}, 1000);" : "process.exit(23);"}
`, { mode: 0o755 });
  const moduleUrl = new URL("./blueprint.ts", import.meta.url).href;
  const code = `
import { buildValidators } from ${JSON.stringify(moduleUrl)};
try { await buildValidators(${JSON.stringify(builtin)}, ${JSON.stringify(directory)}); }
catch (error) { process.send({ error: error.message }); process.exitCode ??= 1; }
`;
  const child = spawn(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", code], {
    env: { ...process.env, AIKEN: compiler }, stdio: ["ignore", "pipe", "pipe", "ipc"],
  });
  let output = "";
  let errorMessage: string | undefined;
  child.on("message", (message: { error: string }) => { errorMessage = message.error; });
  child.stdout!.on("data", (data: Buffer) => { output += data.toString(); });
  child.stderr!.on("data", (data: Buffer) => { output += data.toString(); });
  const finished = new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code) => resolve(code));
  });
  const ready = new Promise<void>((resolve, reject) => {
    child.stdout!.on("data", () => { if (/COMPILER_READY [^\r\n]+[\r\n]/.test(output)) resolve(); });
    child.once("error", reject);
    child.once("close", () => { if (!output.includes("COMPILER_READY")) reject(new Error(output)); });
  });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
    await finished;
    rmSync(directory, { recursive: true, force: true });
  });
  return { child, ready, finished, error: () => errorMessage, project: () => /COMPILER_READY ([^\r\n]+)/.exec(output)![1]! };
}

test("nonzero compiler exit preserves repository sources and removes the build copy", { timeout: 15_000 }, async (t) => {
  const original = readFileSync(ENVIRONMENT_PATH);
  const compiler = startCompiler(t, false);
  await compiler.ready;
  assert.equal(await compiler.finished, 1);
  assert.match(compiler.error() ?? "", /Aiken build failed \(exit 23\)/);
  assert.deepEqual(readFileSync(ENVIRONMENT_PATH), original);
  assert.equal(existsSync(compiler.project()), false);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  test(`${signal} stops the compiler and deletes its isolated copy without changing sources`, { timeout: 15_000 }, async (t) => {
    const original = readFileSync(ENVIRONMENT_PATH);
    const compiler = startCompiler(t, true);
    await compiler.ready;
    assert.deepEqual(readFileSync(ENVIRONMENT_PATH), original);
    assert(readFileSync(join(compiler.project(), "env/failure_tooling.ak"), "utf8").includes("builtin.bls12_381_g1_uncompress"));
    compiler.child.kill(signal);
    assert.equal(await compiler.finished, signal === "SIGINT" ? 130 : 143);
    assert.deepEqual(readFileSync(ENVIRONMENT_PATH), original);
    assert.equal(existsSync(compiler.project()), false);
  });
}
