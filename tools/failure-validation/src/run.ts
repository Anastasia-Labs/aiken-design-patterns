import assert from "node:assert/strict";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { parseArgs } from "node:util";
import { ARTIFACT_DIRECTORY, buildValidators } from "./blueprint.ts";
import { BUILTINS, CASES, parseBuiltins, type Outcome } from "./builtins.ts";
import { runScenario } from "./scenario.ts";

const { values } = parseArgs({
  options: { builtin: { type: "string" }, help: { type: "boolean", short: "h" } },
});
if (values.help) {
  console.log("Usage: pnpm scenario [--builtin <aiken_name>]");
  process.exit(0);
}
// Validate the complete configuration, including unselected entries, before a build.
const configured = parseBuiltins(BUILTINS, CASES);
const selected = values.builtin ? configured.filter((builtin) => builtin.name === values.builtin) : configured;
assert(selected.length > 0, `Unknown builtin: ${values.builtin}`);

function writeJson(path: string, value: unknown) {
  writeFileSync(path, `${JSON.stringify(value, (_, value: unknown) => typeof value === "bigint" ? value.toString() : value, 2)}\n`);
}

const summary: {
  status: "running" | "passed" | "failed";
  builtins: string[];
  cases: { builtin: string; case: string; outcome: Outcome; report: string }[];
  error?: string;
} = { status: "running", builtins: selected.map((builtin) => builtin.name), cases: [] };
mkdirSync(ARTIFACT_DIRECTORY, { recursive: true });
const summaryPath = join(ARTIFACT_DIRECTORY, "report.json");
writeJson(summaryPath, summary);
try {
  for (const builtin of selected) {
    console.log(`Building ${builtin.name}.`);
    const scripts = await buildValidators(builtin);
    for (const testCase of builtin.cases) {
      const label = `${builtin.name}/${testCase.name}`;
      const directory = join(ARTIFACT_DIRECTORY, builtin.name, testCase.name);
      rmSync(directory, { recursive: true, force: true });
      mkdirSync(directory, { recursive: true });
      const { report, transactions } = await runScenario(scripts, testCase, (message) => console.log(`[${label}] ${message}`));
      for (const [name, cbor] of Object.entries(transactions)) writeFileSync(join(directory, `${name}.cbor`), `${cbor}\n`);
      const reportPath = join(directory, "report.json");
      writeJson(reportPath, report);
      summary.cases.push({ builtin: builtin.name, case: testCase.name, outcome: report.outcome, report: relative(ARTIFACT_DIRECTORY, reportPath) });
      writeJson(summaryPath, summary);
      console.log(`[${label}] Passed (${report.outcome}).`);
    }
  }
  summary.status = "passed";
  writeJson(summaryPath, summary);
  console.log(`Passed ${summary.cases.length} cases across ${selected.length} builtins. Artifacts: ${ARTIFACT_DIRECTORY}`);
} catch (error) {
  summary.status = "failed";
  summary.error = error instanceof Error ? error.message : String(error);
  writeJson(summaryPath, summary);
  console.error(error);
  process.exitCode ??= 1;
}
