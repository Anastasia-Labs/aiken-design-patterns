import { writeFileSync } from "node:fs";
import { ARTIFACT_DIRECTORY, buildValidators } from "./blueprint.ts";
import { runScenario } from "./scenario.ts";

const { report, transactions } = await runScenario(buildValidators(), console.log);
for (const [name, cbor] of Object.entries(transactions)) {
  writeFileSync(`${ARTIFACT_DIRECTORY}/${name}.cbor`, `${cbor}\n`);
}
const json = JSON.stringify(report, (_, value: unknown) => typeof value === "bigint" ? value.toString() : value, 2);
writeFileSync(`${ARTIFACT_DIRECTORY}/report.json`, `${json}\n`);
console.log(json);
console.log(`Scenario passed. Artifacts: ${ARTIFACT_DIRECTORY}`);
