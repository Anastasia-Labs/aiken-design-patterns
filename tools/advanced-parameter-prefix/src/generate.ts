#!/usr/bin/env -S node --experimental-strip-types

import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  CML,
  Constr,
  Data,
  applyParamsToScript,
  type Data as PlutusData,
  type Datum,
} from "@lucid-evolution/lucid";

const REPOSITORY_ROOT = fileURLToPath(new URL("../../..", import.meta.url));
process.chdir(REPOSITORY_ROOT);

const AIKEN = process.env.AIKEN ?? "aiken";
const BLUEPRINT = process.env.BLUEPRINT ?? "plutus.json";
const ENV_FILE = process.env.ENV_FILE ?? "env/default.ak";
const MODULE = "examples/parameter_validation/advanced";

type Parameter = {
  readonly constant: string;
  readonly validator: string;
  readonly environment: string;
  readonly value: PlutusData;
};

const PARAMETERS = [
  {
    constant: "bytearray_flat_prefix_without_parameter_header",
    validator: "parameterized_spend_bytearray",
    environment: "BYTES_PARAMETER",
    value: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  },
  {
    constant: "int_flat_prefix_without_parameter_header",
    validator: "parameterized_spend_int",
    environment: "INT_PARAMETER",
    value: 1_000_000n,
  },
  {
    constant: "list_flat_prefix_without_parameter_header",
    validator: "parameterized_spend_list",
    environment: "LIST_PARAMETER",
    value: [42n, 1_000n, 1_000_000n],
  },
  {
    constant: "pairs_flat_prefix_without_parameter_header",
    validator: "parameterized_spend_pairs",
    environment: "PAIRS_PARAMETER",
    value: new Map<PlutusData, PlutusData>([
      ["aabb", 42n],
      ["ccddee", 1_000_000n],
    ]),
  },
  {
    constant: "custom_flat_prefix_without_parameter_header",
    validator: "parameterized_spend_custom",
    environment: "CUSTOM_PARAMETER",
    value: new Constr(0, ["aabbccddee", 1_000_000n]),
  },
] satisfies readonly Parameter[];

type Blueprint = {
  readonly validators: readonly {
    readonly title: string;
    readonly compiledCode: string;
  }[];
};

const runAiken = (...arguments_: string[]): void => {
  execFileSync(AIKEN, arguments_, { stdio: "inherit" });
};

const unwrapCborBytestring = (encoded: string): string => {
  const script = CML.PlutusV3Script.from_cbor_hex(encoded);
  try {
    return script.to_hex();
  } finally {
    script.free();
  }
};

const flatEncodeBytestring = (cbor: string): string => {
  let encoded = "";
  for (let offset = 0; offset < cbor.length; offset += 510) {
    const chunk = cbor.slice(offset, offset + 510);
    const length = (chunk.length / 2).toString(16).padStart(2, "0");
    encoded += `${length}${chunk}`;
  }
  return `${encoded}00`;
};

const resolveParameter = ({ environment, value }: Parameter): PlutusData => {
  const encoded = process.env[environment];
  return encoded === undefined ? value : Data.from(encoded as Datum);
};

const generatePrefix = (blueprint: Blueprint, parameter: Parameter): string => {
  const title = `${MODULE}.${parameter.validator}.spend`;
  const validator = blueprint.validators.find((entry) => entry.title === title);
  if (validator === undefined) {
    throw new Error(`${BLUEPRINT} does not contain ${title}`);
  }

  const value = resolveParameter(parameter);
  // The retained prefix ends before the CBOR, so definite and indefinite
  // encodings produce the same prefix.
  const applied = applyParamsToScript(validator.compiledCode, [value]);
  const flatScript = unwrapCborBytestring(unwrapCborBytestring(applied));
  const suffix = `${flatEncodeBytestring(Data.to(value))}01`;
  if (!flatScript.endsWith(suffix)) {
    throw new Error(`applied ${parameter.validator} has an unexpected suffix`);
  }
  return flatScript.slice(0, -suffix.length);
};

const main = (): void => {
  runAiken("build");
  const blueprint = JSON.parse(readFileSync(BLUEPRINT, "utf8")) as Blueprint;
  const constants = PARAMETERS.map((parameter) => {
    const prefix = generatePrefix(blueprint, parameter);
    return `pub const ${parameter.constant} = #"${prefix}"`;
  });

  mkdirSync(dirname(ENV_FILE), { recursive: true });
  const temporary = `${ENV_FILE}.tmp.${randomUUID()}.ak`;
  try {
    writeFileSync(temporary, `${constants.join("\n\n")}\n`);
    runAiken("fmt", temporary);
    renameSync(temporary, ENV_FILE);
  } finally {
    rmSync(temporary, { force: true });
  }
  runAiken("build");
};

try {
  main();
} catch (error) {
  console.error(`error: ${error instanceof Error ? error.message : error}`);
  process.exitCode = 1;
}
