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
  Cbor,
  CborArray,
  CborMap,
  CborTag,
  type CborObj,
} from "@harmoniclabs/cbor";
import {
  CML,
  Constr,
  Data,
  applyParamsToScript,
  validatorToScriptHash,
  type Data as PlutusData,
  type Datum,
} from "@lucid-evolution/lucid";

const REPOSITORY_ROOT = fileURLToPath(new URL("../../..", import.meta.url));
process.chdir(REPOSITORY_ROOT);

const AIKEN = process.env.AIKEN ?? "aiken";
const BLUEPRINT = process.env.BLUEPRINT ?? "plutus.json";
const ENV_FILE = process.env.ENV_FILE ?? "env/default.ak";
const MODULE = "examples/parameter_validation/advanced";
const GENERAL_FORM_CONSTRUCTOR_TAG = 102n;

type Parameter = {
  readonly name: string;
  readonly environment: string;
  readonly value: PlutusData;
};

const PARAMETERS = [
  {
    name: "bytearray",
    environment: "BYTES_PARAMETER",
    value: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  },
  {
    name: "int",
    environment: "INT_PARAMETER",
    value: 1_000_000n,
  },
  {
    name: "list",
    environment: "LIST_PARAMETER",
    value: [42n, 1_000n, 1_000_000n],
  },
  {
    name: "pairs",
    environment: "PAIRS_PARAMETER",
    value: new Map<PlutusData, PlutusData>([
      ["aabb", 42n],
      ["ccddee", 1_000_000n],
    ]),
  },
  {
    name: "pairs_list",
    environment: "PAIRS_LIST_PARAMETER",
    value: new Map<PlutusData, PlutusData>([["aa", [1n]]]),
  },
  {
    name: "custom",
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

const wrapFlatScript = (flatScript: string): string => {
  const script = CML.PlutusV3Script.from_raw_bytes(
    Buffer.from(flatScript, "hex"),
  );
  try {
    return script.to_cbor_hex();
  } finally {
    script.free();
  }
};

type DataCborFormat = "aiken" | "uplc";

const normaliseDataCbor = (
  data: CborObj,
  format: DataCborFormat,
): CborObj => {
  if (data instanceof CborMap) {
    return new CborMap(
      data.map.map(({ k, v }) => ({
        k: normaliseDataCbor(k, format),
        v: normaliseDataCbor(v, format),
      })),
      { indefinite: format === "uplc" && data.map.length > 0 },
    );
  }

  if (data instanceof CborArray) {
    return new CborArray(
      data.array.map((item) => normaliseDataCbor(item, format)),
      {
        indefinite: data.array.length > 0,
      },
    );
  }

  if (data instanceof CborTag) {
    if (data.tag === GENERAL_FORM_CONSTRUCTOR_TAG) {
      if (!(data.data instanceof CborArray) || data.data.array.length !== 2) {
        throw new Error("invalid general-form constructor encoding");
      }
      // Tag 102 wraps the constructor index and fields in a definite pair;
      // the fields array itself follows the usual Aiken list encoding above.
      return new CborTag(
        data.tag,
        new CborArray(
          data.data.array.map((item) => normaliseDataCbor(item, format)),
          { indefinite: false },
        ),
      );
    }

    return new CborTag(data.tag, normaliseDataCbor(data.data, format));
  }

  return data;
};

const encodeData = (encoded: string, format: DataCborFormat): string => {
  return Cbor.encode(normaliseDataCbor(Cbor.parse(encoded), format)).toString();
};

const resolveParameter = ({ environment, value }: Parameter): PlutusData => {
  const encoded = process.env[environment];
  return encoded === undefined ? value : Data.from(encoded as Datum);
};

const generateScript = (
  blueprint: Blueprint,
  parameter: Parameter,
  value: PlutusData,
): { prefix: string; parameterCbor: string; scriptHash: string } => {
  const spendTitle = `${MODULE}.parameterized_spend_${parameter.name}.spend`;
  const mintTitle = `${MODULE}.dependent_mint_${parameter.name}.mint`;
  const validator = blueprint.validators.find(
    (entry) => entry.title === spendTitle,
  );
  if (validator === undefined) {
    throw new Error(`${BLUEPRINT} does not contain ${spendTitle}`);
  }
  if (!blueprint.validators.some((entry) => entry.title === mintTitle)) {
    throw new Error(`${BLUEPRINT} does not contain ${mintTitle}`);
  }

  // The retained prefix ends before the CBOR, so definite and indefinite
  // encodings produce the same prefix.
  const applied = applyParamsToScript(validator.compiledCode, [value]);
  const flatScript = unwrapCborBytestring(unwrapCborBytestring(applied));
  const lucidCbor = Data.to(value);
  const uplcCbor = encodeData(lucidCbor, "uplc");
  const suffix = `${flatEncodeBytestring(uplcCbor)}01`;
  if (!flatScript.endsWith(suffix)) {
    throw new Error(
      `applied parameterized_spend_${parameter.name} has an unexpected suffix`,
    );
  }
  const prefix = flatScript.slice(0, -suffix.length);
  const parameterCbor = encodeData(lucidCbor, "aiken");
  const aikenFlatScript = `${prefix}${flatEncodeBytestring(parameterCbor)}01`;
  return {
    prefix,
    parameterCbor,
    scriptHash: validatorToScriptHash({
      type: "PlutusV3",
      script: wrapFlatScript(aikenFlatScript),
    }),
  };
};

const main = (): void => {
  runAiken("build");
  const blueprint = JSON.parse(readFileSync(BLUEPRINT, "utf8")) as Blueprint;
  const constants = PARAMETERS.flatMap((parameter) => {
    const { prefix, parameterCbor, scriptHash } = generateScript(
      blueprint,
      parameter,
      resolveParameter(parameter),
    );
    return [
      `pub const ${parameter.name}_flat_prefix_without_parameter_header = #"${prefix}"`,
      `pub const ${parameter.name}_parameter_cbor = #"${parameterCbor}"`,
      `pub const ${parameter.name}_script_hash = #"${scriptHash}"`,
    ];
  });
  const bytearrayParameter = PARAMETERS.find(
    (parameter) => parameter.name === "bytearray",
  );
  if (bytearrayParameter === undefined) {
    throw new Error("missing bytearray parameter configuration");
  }
  const { scriptHash: bytearrayEmptyScriptHash } = generateScript(
    blueprint,
    bytearrayParameter,
    "",
  );
  constants.push(
    `pub const bytearray_empty_script_hash = #"${bytearrayEmptyScriptHash}"`,
  );
  const intParameter = PARAMETERS.find(
    (parameter) => parameter.name === "int",
  );
  if (intParameter === undefined) {
    throw new Error("missing int parameter configuration");
  }
  const { scriptHash: intNegativeOneScriptHash } = generateScript(
    blueprint,
    intParameter,
    -1n,
  );
  constants.push(
    `pub const int_negative_one_script_hash = #"${intNegativeOneScriptHash}"`,
  );
  const customParameter = PARAMETERS.find(
    (parameter) => parameter.name === "custom",
  );
  if (customParameter === undefined) {
    throw new Error("missing custom parameter configuration");
  }
  const {
    parameterCbor: customTag128ParameterCbor,
    scriptHash: customTag128ScriptHash,
  } = generateScript(blueprint, customParameter, new Constr(128, [42n]));
  constants.push(
    `pub const custom_tag_128_parameter_cbor = #"${customTag128ParameterCbor}"`,
    `pub const custom_tag_128_script_hash = #"${customTag128ScriptHash}"`,
  );
  const listParameter = PARAMETERS.find(
    (parameter) => parameter.name === "list",
  );
  if (listParameter === undefined) {
    throw new Error("missing list parameter configuration");
  }
  constants.push("pub const list_flat_chunk_element = 0");
  for (const [flatChunkLength, elementCount] of [
    [255, 253],
    [256, 254],
    [510, 508],
    [511, 509],
  ] as const) {
    const value = Array.from({ length: elementCount }, () => 0n);
    if (Data.to(value).length / 2 !== flatChunkLength) {
      throw new Error(`invalid ${flatChunkLength}-byte Flat chunk fixture`);
    }
    const { scriptHash } = generateScript(blueprint, listParameter, value);
    constants.push(
      `pub const list_flat_chunk_${flatChunkLength}_element_count = ${elementCount}`,
      `pub const list_flat_chunk_${flatChunkLength}_script_hash = #"${scriptHash}"`,
    );
  }

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
