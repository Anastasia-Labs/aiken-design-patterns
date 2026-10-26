import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { applyParamsToScript, validatorToScriptHash, type Script } from "@lucid-evolution/lucid";
import type { Builtin } from "./builtins.ts";
import { withBuiltinEnvironment } from "./environment.ts";

export const REPOSITORY_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
export const ARTIFACT_DIRECTORY = fileURLToPath(new URL("../../../artifacts/failure-validation/", import.meta.url));

export type Validators = {
  builtin: Builtin;
  spendWithdraw: Script;
  mint: Script;
};

export async function buildValidators(
  builtin: Builtin,
  directory = join(ARTIFACT_DIRECTORY, builtin.name),
): Promise<Validators> {
  mkdirSync(directory, { recursive: true });
  const blueprintPath = join(directory, "plutus.json");
  const aiken = process.env.AIKEN ?? "aiken";
  const args = ["build", "--env", "testnet", "--out", blueprintPath];
  // Aiken needs a TTY to render complete diagnostics. Await close before restoring
  // the environment, including when interruption terminates the compiler group.
  await withBuiltinEnvironment(builtin, (signal) => new Promise<void>((resolve, reject) => {
    const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
    const command = process.stdout.isTTY ? aiken : "script";
    const commandArgs = process.stdout.isTTY ? args
      : ["-q", "-e", "-c", [aiken, ...args].map(quote).join(" "), "/dev/null"];
    const child = spawn(command, commandArgs, {
      cwd: REPOSITORY_ROOT, stdio: "inherit", detached: process.platform !== "win32",
    });
    let spawnError: Error | undefined;
    let killTimer: NodeJS.Timeout | undefined;
    const kill = (signal: NodeJS.Signals) => {
      if (!child.pid) return;
      try {
        if (process.platform === "win32") child.kill(signal);
        else process.kill(-child.pid, signal);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ESRCH") spawnError = error as Error;
      }
    };
    const abort = () => {
      kill("SIGTERM");
      killTimer = setTimeout(() => kill("SIGKILL"), 2_000);
      killTimer.unref();
    };
    signal.addEventListener("abort", abort, { once: true });
    child.once("error", (error) => { spawnError = error; });
    child.once("close", (code, terminationSignal) => {
      signal.removeEventListener("abort", abort);
      if (killTimer) clearTimeout(killTimer);
      if (signal.aborted) reject(signal.reason);
      else if (spawnError) reject(spawnError);
      else if (code !== 0) reject(new Error(`Aiken build failed (${terminationSignal ?? `exit ${code}`}).`));
      else resolve();
    });
    if (signal.aborted) abort();
  }));

  const blueprint = JSON.parse(readFileSync(blueprintPath, "utf8")) as {
    preamble: { plutusVersion: string };
    validators: { title: string; compiledCode: string }[];
  };
  assert.equal(blueprint.preamble.plutusVersion, "v3");
  const script = (name: string): Script => {
    const title = `failure_validation.${name}`;
    const entry = blueprint.validators.find((v) => v.title === title);
    assert(entry, `Blueprint is missing ${title}.`);
    return { type: "PlutusV3", script: entry.compiledCode };
  };
  const spendWithdraw = script("builtin_probe.spend");
  assert.deepEqual(script("builtin_probe.withdraw"), spendWithdraw);
  assert.deepEqual(script("builtin_probe.publish"), spendWithdraw);
  const mint = script("failure_proof.mint");
  return {
    builtin,
    spendWithdraw,
    mint: {
      ...mint,
      script: applyParamsToScript(mint.script, [validatorToScriptHash(spendWithdraw)]),
    },
  };
}
