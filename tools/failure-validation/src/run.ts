import assert from "node:assert/strict";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { Artifacts } from "./artifacts.ts";
import { ARTIFACT_DIRECTORY, buildValidators } from "./blueprint.ts";
import { BUILTINS, CASES, parseBuiltins } from "./builtins.ts";
import { loadEnvironment, readNetworkConfig, redactSecrets } from "./network.ts";
import { createRuntime, referenceKey, type Runtime } from "./runtime.ts";
import { prepareBuiltin, runScenario, type BuiltinSetup } from "./scenario.ts";

loadEnvironment();
const redact = redactSecrets();
const controller = new AbortController();
const interrupt = (signal: "SIGINT" | "SIGTERM") => {
  process.exitCode = signal === "SIGINT" ? 130 : 143;
  controller.abort(new Error(`Run interrupted by ${signal}; check recorded transaction hashes before restarting.`));
};
const onInterrupt = () => interrupt("SIGINT");
const onTerminate = () => interrupt("SIGTERM");
process.on("SIGINT", onInterrupt);
process.on("SIGTERM", onTerminate);
let artifacts: Artifacts | undefined;
let activeScope: string | undefined;
try {
  const { values } = parseArgs({ options: { builtin: { type: "string" }, help: { type: "boolean", short: "h" } } });
  if (values.help) {
    console.log("Usage: pnpm scenario [--builtin <aiken_name>]\nNETWORK: Custom (default), Mainnet, Preprod, Preview.");
  } else {
    // Configuration and wallet derivation are checked before compilation or submission.
    const config = readNetworkConfig();
    const configured = parseBuiltins(BUILTINS, CASES);
    const selected = values.builtin ? configured.filter((builtin) => builtin.name === values.builtin) : configured;
    assert(selected.length > 0, "Unknown builtin selection.");
    artifacts = new Artifacts(ARTIFACT_DIRECTORY, config.network, redact);
    artifacts.report("", { status: "running", network: config.network, builtins: selected.map((b) => b.name), cases: [] });
    console.log(`Network: ${config.network}. Artifacts: ${artifacts.directory}`);
    const live = config.network === "Custom" ? undefined : await createRuntime(config, controller.signal);
    const completed: { builtin: string; case: string; outcome: string; report: string }[] = [];
    for (const builtin of selected) {
      controller.signal.throwIfAborted();
      activeScope = builtin.name;
      artifacts.report(activeScope, { status: "compiling", network: config.network });
      console.log(`Building ${builtin.name}.`);
      const scripts = await buildValidators(builtin, join(artifacts.directory, builtin.name), config.network);
      artifacts.report(activeScope, { status: "compiled", networkTag: scripts.networkTag });
      let shared: BuiltinSetup | undefined;
      if (live) {
        live.artifacts = artifacts;
        activeScope = `${builtin.name}/setup`;
        live.scope = activeScope;
        artifacts.report(activeScope, { status: "preparing", network: config.network });
        shared = await prepareBuiltin(scripts, live, (message) => console.log(`[${activeScope}] ${message}`));
      }
      for (const testCase of builtin.cases) {
        controller.signal.throwIfAborted();
        const label = `${builtin.name}/${testCase.name}`;
        activeScope = label;
        artifacts.report(label, { status: "running", network: config.network, builtin: builtin.name, case: testCase.name });
        const progress = (message: string) => { console.log(`[${label}] ${message}`); artifacts!.report(label, { stage: message }); };
        let setup = shared;
        if (!setup) {
          const custom: Runtime = await createRuntime({ network: "Custom" }, controller.signal);
          custom.artifacts = artifacts;
          custom.scope = label;
          setup = await prepareBuiltin(scripts, custom, progress);
        }
        setup.runtime.scope = label;
        const { report } = await runScenario(scripts, testCase, progress, setup);
        artifacts.report(label, { ...report, status: "passed" });
        completed.push({ builtin: builtin.name, case: testCase.name, outcome: report.outcome, report: `${label}/report.json` });
        artifacts.report("", { cases: completed });
        activeScope = undefined;
        console.log(`[${label}] Passed (${report.outcome}; ${config.network === "Custom" ? "emulator" : "confirmed chain effects"}).`);
      }
      if (shared) shared.runtime.reserved.delete(referenceKey(shared.mintCollateral));
    }
    activeScope = undefined;
    artifacts.report("", { status: "passed" });
    console.log(`Passed ${completed.length} cases across ${selected.length} builtins. Artifacts: ${artifacts.directory}`);
  }
} catch (error) {
  const message = redact(error instanceof Error ? error.message : "Run failed.");
  if (activeScope) artifacts?.report(activeScope, { status: "stopped", error: message });
  artifacts?.report("", { status: "stopped", error: message });
  console.error(message);
  process.exitCode ??= 1;
} finally {
  process.off("SIGINT", onInterrupt);
  process.off("SIGTERM", onTerminate);
}
