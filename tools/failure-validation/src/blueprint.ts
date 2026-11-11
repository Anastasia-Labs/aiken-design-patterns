import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Script } from "@lucid-evolution/lucid";
import type { Builtin } from "./builtins.ts";
import { withBuiltinProject } from "./environment.ts";
import type { Network } from "./network.ts";

export const ARTIFACT_DIRECTORY = fileURLToPath(new URL("../../../artifacts/failure-validation/", import.meta.url));

export type Validators = {
  networkTag: 0 | 1;
  builtin: Builtin;
  withdrawal: Script;
  parameters: Script;
  mint: Script;
};

export async function buildValidators(
  builtin: Builtin,
  directory?: string,
  network: Network = "Custom",
): Promise<Validators> {
  const outputDirectory = directory ?? mkdtempSync(join(tmpdir(), "failure-validation-blueprint-"));
  try {
    mkdirSync(outputDirectory, { recursive: true });
    const blueprintPath = resolve(outputDirectory, "plutus.json");
    const aiken = process.env.AIKEN ?? "aiken";
    const args = ["build", "--env", "failure_tooling", "--out", blueprintPath];
    // Wait for the compiler group before deleting its isolated project, including
    // on interruption. Repository sources are never changed by builtin selection.
    await withBuiltinProject(builtin, (project, signal) => new Promise<void>((resolve, reject) => {
      const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
      const command = process.stdout.isTTY ? aiken : "script";
      const commandArgs = process.stdout.isTTY ? args
        : ["-q", "-e", "-c", [aiken, ...args].map(quote).join(" "), "/dev/null"];
      const compilerEnvironment = { ...process.env };
      delete compilerEnvironment.BLOCKFROST_API_KEY;
      delete compilerEnvironment.WALLET_SEED;
      const child = spawn(command, commandArgs, {
        cwd: project, env: compilerEnvironment, stdio: "inherit", detached: process.platform !== "win32",
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
    }), undefined, network);

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
      networkTag: network === "Mainnet" ? 1 : 0,
      builtin,
      withdrawal,
      parameters,
      mint: script("failure_proof.mint"),
    };
  } finally {
    if (!directory) rmSync(outputDirectory, { recursive: true, force: true });
  }
}
