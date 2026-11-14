import assert from "node:assert/strict";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { getAddressDetails } from "@lucid-evolution/lucid";
import { Artifacts, validateResumeIdentity } from "./artifacts.ts";
import { ARTIFACT_DIRECTORY, buildValidators, type Validators } from "./blueprint.ts";
import { BUILTINS, CASES, parseBuiltins } from "./builtins.ts";
import { loadEnvironment, readNetworkConfig, redactSecrets } from "./network.ts";
import { createRuntime, type Runtime } from "./runtime.ts";
import { checkRecorded, recoverMint } from "./resume.ts";
import { prepareBuiltin, prepareLiveRun, runScenario, type BuiltinSetup } from "./scenario.ts";

loadEnvironment();
const redact = redactSecrets();
const controller = new AbortController();
const interrupt = (signal: "SIGINT" | "SIGTERM") => {
  process.exitCode = signal === "SIGINT" ? 130 : 143;
  controller.abort(new Error(`Run interrupted by ${signal}; resume this run directory to check recorded transaction hashes.`));
};
const onInterrupt = () => interrupt("SIGINT");
const onTerminate = () => interrupt("SIGTERM");
process.on("SIGINT", onInterrupt);
process.on("SIGTERM", onTerminate);
let artifacts: Artifacts | undefined;
let activeScope: string | undefined;
let started = false;

try {
  const { values } = parseArgs({ options: {
    builtin: { type: "string" }, resume: { type: "string" }, help: { type: "boolean", short: "h" },
  } });
  if (values.help) {
    console.log("Usage: pnpm scenario [--builtin <aiken_name>] | pnpm scenario --resume <run-directory>\nNETWORK: Custom (default), Mainnet, Preprod, Preview.");
  } else {
    workflow: {
      assert(!(values.resume && values.builtin), "--resume cannot be combined with --builtin.");
      artifacts = values.resume ? Artifacts.resume(values.resume, redact) : undefined;
      if (artifacts?.manifest && process.env.NETWORK && process.env.NETWORK !== artifacts.manifest.network)
        throw new Error("NETWORK conflicts with the saved run network.");
      const config = readNetworkConfig(artifacts?.manifest ? { ...process.env, NETWORK: artifacts.manifest.network } : process.env);
      const selected = artifacts?.manifest?.selection ?? (() => {
        const configured = parseBuiltins(BUILTINS, CASES);
        return values.builtin ? configured.filter((builtin) => builtin.name === values.builtin) : configured;
      })();
      assert(selected.length > 0, "Unknown builtin selection.");
      artifacts ??= new Artifacts(ARTIFACT_DIRECTORY, config.network, redact);
      console.log(`Network: ${config.network}. Artifacts: ${artifacts.directory}`);
      const live = config.network === "Custom" ? undefined : await createRuntime(config, controller.signal);
      if (live) {
        live.artifacts = artifacts;
        if (artifacts.manifest) {
          validateResumeIdentity(artifacts.manifest, live.walletAddress, process.env.NETWORK);
          artifacts.renderAll();
          if (artifacts.manifest.status === "passed") {
            assert(selected.every((builtin) => builtin.cases.every((testCase) =>
              artifacts!.manifest!.reports[`${builtin.name}/${testCase.name}`]?.status === "passed")),
            "Completed manifest is missing case reports.");
            await checkRecorded(live, artifacts);
            console.log(`Completed run checked; no transactions submitted. Artifacts: ${artifacts.directory}`);
            process.exitCode = 0;
            break workflow;
          }
        }
      }
      started = true;
      const scripts: Validators[] = [];
      if (artifacts.manifest) {
        for (const builtin of selected) scripts.push(artifacts.manifest.scripts[builtin.name] as Validators);
      } else {
        for (const builtin of selected) {
          activeScope = builtin.name;
          artifacts.report(activeScope, { status: "compiling", network: config.network });
          console.log(`Building ${builtin.name}.`);
          const built = await buildValidators(builtin, join(artifacts.directory, builtin.name), config.network);
          artifacts.report(activeScope, { status: "compiled", networkTag: built.networkTag });
          scripts.push(built);
        }
      }
      activeScope = undefined;
      if (live && !artifacts.manifest) {
        artifacts.initialize(config.network, live.walletAddress,
          getAddressDetails(live.walletAddress).paymentCredential!.hash, selected, scripts);
      }
      artifacts.report("", { status: "running", network: config.network, builtins: selected.map((b) => b.name), cases: [] });
      const completed: { builtin: string; case: string; outcome: string; report: string }[] = [];
      const liveSetups: Record<string, BuiltinSetup> = {};
      if (live) {
        activeScope = "setup";
        live.scope = activeScope;
        Object.assign(liveSetups, (await prepareLiveRun(scripts, live, (message) => console.log(`[setup] ${message}`))).builtins);
      }
      for (const compiled of scripts) {
        controller.signal.throwIfAborted();
        const builtin = compiled.builtin;
        const pending = builtin.cases.some((testCase) => artifacts!.manifest?.reports[`${builtin.name}/${testCase.name}`]?.status !== "passed");
        if (!pending && artifacts.manifest) {
          for (const testCase of builtin.cases) completed.push({ builtin: builtin.name, case: testCase.name, outcome: testCase.outcome,
            report: `${builtin.name}/${testCase.name}/report.json` });
          continue;
        }
        const shared = live ? liveSetups[builtin.name] : undefined;
        for (const testCase of builtin.cases) {
          controller.signal.throwIfAborted();
          const label = `${builtin.name}/${testCase.name}`;
          activeScope = label;
          if (artifacts.manifest?.reports[label]?.status === "passed"
            || (live && testCase.outcome !== "success" && await recoverMint(live, artifacts, label, testCase.outcome))) {
            completed.push({ builtin: builtin.name, case: testCase.name, outcome: testCase.outcome, report: `${label}/report.json` });
            continue;
          }
          artifacts.report(label, { status: "running", network: config.network, builtin: builtin.name, case: testCase.name });
          const progress = (message: string) => { console.log(`[${label}] ${message}`); artifacts!.report(label, { stage: message }); };
          let setup = shared;
          if (!setup) {
            const custom: Runtime = await createRuntime({ network: "Custom" }, controller.signal);
            custom.artifacts = artifacts;
            custom.scope = label;
            setup = await prepareBuiltin(compiled, custom, progress);
          }
          setup.runtime.scope = label;
          const { report } = await runScenario(compiled, testCase, progress, setup);
          artifacts.report(label, { ...report, status: "passed" });
          completed.push({ builtin: builtin.name, case: testCase.name, outcome: report.outcome, report: `${label}/report.json` });
          artifacts.report("", { cases: completed });
          activeScope = undefined;
          console.log(`[${label}] Passed (${report.outcome}; ${config.network === "Custom" ? "emulator" : "confirmed chain effects"}).`);
        }
      }
      activeScope = undefined;
      if (live && artifacts.manifest) await checkRecorded(live, artifacts);
      if (artifacts.manifest) { artifacts.manifest.status = "passed"; artifacts.saveManifest(); }
      artifacts.report("", { status: "passed", cases: completed });
      console.log(`Passed ${completed.length} cases across ${selected.length} builtins. Artifacts: ${artifacts.directory}`);
    }
  }
} catch (error) {
  const message = redact(error instanceof Error ? error.message : "Run failed.");
  if (started || !artifacts?.manifest) {
    if (activeScope) artifacts?.report(activeScope, { status: "stopped", error: message });
    if (artifacts?.manifest) { artifacts.manifest.status = "stopped"; artifacts.saveManifest(); }
    artifacts?.report("", { status: "stopped", error: message });
  }
  console.error(message);
  process.exitCode ??= 1;
} finally {
  process.off("SIGINT", onInterrupt);
  process.off("SIGTERM", onTerminate);
}
