import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { applyParamsToScript, validatorToScriptHash, type Script } from "@lucid-evolution/lucid";

export const REPOSITORY_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
export const ARTIFACT_DIRECTORY = fileURLToPath(new URL("../../../artifacts/failure-validation/", import.meta.url));

export type Validators = {
  spendWithdraw: Script;
  mint: Script;
};

export function buildValidators(): Validators {
  mkdirSync(ARTIFACT_DIRECTORY, { recursive: true });
  const blueprintPath = `${ARTIFACT_DIRECTORY}/plutus.json`;
  const aiken = process.env.AIKEN ?? "/home/km/code/aiken/target/debug/aiken";
  const args = ["build", "--env", "testnet", "--out", blueprintPath];
  // execFileSync throws on a nonzero compiler exit. Give Aiken a TTY even in CI,
  // where its non-TTY reporter may otherwise omit compiler diagnostics.
  if (process.stdout.isTTY) {
    execFileSync(aiken, args, { cwd: REPOSITORY_ROOT, stdio: "inherit" });
  } else {
    const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
    execFileSync("script", ["-q", "-e", "-c", [aiken, ...args].map(quote).join(" "), "/dev/null"], {
      cwd: REPOSITORY_ROOT,
      stdio: "inherit",
    });
  }

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
  const spendWithdraw = script("delegated_spend.spend");
  assert.deepEqual(script("delegated_spend.withdraw"), spendWithdraw);
  assert.deepEqual(script("delegated_spend.publish"), spendWithdraw);
  const mint = script("failure_proof.mint");
  return {
    spendWithdraw,
    mint: {
      ...mint,
      script: applyParamsToScript(mint.script, [validatorToScriptHash(spendWithdraw)]),
    },
  };
}
