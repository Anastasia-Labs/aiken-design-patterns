import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Script } from "@lucid-evolution/lucid";
import type { Builtin } from "./builtins.ts";
import { withBuiltinProject } from "./environment.ts";

export const ARTIFACT_DIRECTORY = fileURLToPath(new URL("../../../artifacts/failure-validation/", import.meta.url));

export type Validators = {
  builtin: Builtin;
  withdrawal: Script;
  parameters: Script;
  mint: Script;
};

export async function buildValidators(
  builtin: Builtin,
  directory = join(ARTIFACT_DIRECTORY, builtin.name),
): Promise<Validators> {
  mkdirSync(directory, { recursive: true });
  const blueprintPath = resolve(directory, "plutus.json");
  const aiken = process.env.AIKEN ?? "aiken";
  const args = ["build", "--env", "testnet", "--out", blueprintPath];
  // Wait for the compiler group before deleting its isolated project, including
  // on interruption. Repository sources are never changed by builtin selection.
  await withBuiltinProject(builtin, (project, signal) => new Promise<void>((resolve, reject) => {
    const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
    const command = process.stdout.isTTY ? aiken : "script";
    const commandArgs = process.stdout.isTTY ? args
      : ["-q", "-e", "-c", [aiken, ...args].map(quote).join(" "), "/dev/null"];
    const child = spawn(command, commandArgs, {
      cwd: project, stdio: "inherit", detached: process.platform !== "win32",
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
  const withdrawal = script("builtin_probe.withdraw");
  assert.deepEqual(script("builtin_probe.publish"), withdrawal);
  const parameters = script("failure_parameters.mint");
  assert.deepEqual(script("failure_parameters.spend"), parameters);
  return {
    builtin,
    withdrawal,
    parameters,
    mint: script("failure_proof.mint"),
  };
}
