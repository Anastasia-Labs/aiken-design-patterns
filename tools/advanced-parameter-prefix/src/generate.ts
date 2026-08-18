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

type ParameterExample = {
  readonly id: string;
  readonly family: string;
  readonly value: PlutusData;
  readonly environment?: string;
  readonly expectedCborBytes?: number;
  readonly repeatedIntList?: {
    readonly element: bigint;
    readonly elementCount: number;
  };
};

const repeatInt = (element: bigint, elementCount: number) => ({
  value: Array.from({ length: elementCount }, () => element),
  repeatedIntList: { element, elementCount },
});

const PARAMETER_EXAMPLES: readonly ParameterExample[] = [
  {
    id: "bytearray",
    family: "bytearray",
    environment: "BYTES_PARAMETER",
    value: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  },
  {
    id: "int",
    family: "int",
    environment: "INT_PARAMETER",
    value: 1_000_000n,
  },
  {
    id: "list",
    family: "list",
    environment: "LIST_PARAMETER",
    value: [42n, 1_000n, 1_000_000n],
  },
  {
    id: "pairs",
    family: "pairs",
    environment: "PAIRS_PARAMETER",
    value: new Map<PlutusData, PlutusData>([
      ["aabb", 42n],
      ["ccddee", 1_000_000n],
    ]),
  },
  {
    id: "pairs_list",
    family: "pairs_list",
    environment: "PAIRS_LIST_PARAMETER",
    value: new Map<PlutusData, PlutusData>([["aa", [1n]]]),
  },
  {
    id: "custom",
    family: "custom",
    environment: "CUSTOM_PARAMETER",
    value: new Constr(0, ["aabbccddee", 1_000_000n]),
  },
  {
    id: "bytearray_empty",
    family: "bytearray",
    value: "",
  },
  {
    id: "int_negative_one",
    family: "int",
    value: -1n,
  },
  {
    id: "custom_tag_128",
    family: "custom",
    value: new Constr(128, [42n]),
  },
  {
    id: "list_flat_chunk_255",
    family: "list",
    ...repeatInt(0n, 253),
    expectedCborBytes: 255,
  },
  {
    id: "list_flat_chunk_256",
    family: "list",
    ...repeatInt(0n, 254),
    expectedCborBytes: 256,
  },
  {
    id: "list_flat_chunk_510",
    family: "list",
    ...repeatInt(0n, 508),
    expectedCborBytes: 510,
  },
  {
    id: "list_flat_chunk_511",
    family: "list",
    ...repeatInt(0n, 509),
    expectedCborBytes: 511,
  },
];

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

const resolveParameterCbor = ({
  environment,
  value,
}: ParameterExample): string => {
  const encoded =
    environment === undefined ? undefined : process.env[environment];
  if (encoded !== undefined) Data.from(encoded as Datum);
  return encoded ?? Data.to(value);
};

const generateScript = (
  blueprint: Blueprint,
  family: string,
  value: PlutusData,
  sourceCbor = Data.to(value),
): { prefix: string; parameterCbor: string; scriptHash: string } => {
  const spendTitle = `${MODULE}.parameterized_spend_${family}.spend`;
  const mintTitle = `${MODULE}.dependent_mint_${family}.mint`;
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
      `applied parameterized_spend_${family} has an unexpected suffix`,
    );
  }
  const prefix = flatScript.slice(0, -suffix.length);
  const parameterCbor = encodeData(sourceCbor, "aiken");
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

const AIKEN_IDENTIFIER = /^[a-z][a-z0-9_]*$/;

const validateParameterExamples = (): void => {
  const ids = new Set<string>();
  for (const {
    id,
    family,
    value,
    expectedCborBytes,
    repeatedIntList,
  } of PARAMETER_EXAMPLES) {
    if (!AIKEN_IDENTIFIER.test(id)) {
      throw new Error(`invalid Aiken identifier for parameter example: ${id}`);
    }
    if (!AIKEN_IDENTIFIER.test(family)) {
      throw new Error(`invalid Aiken identifier for parameter family: ${family}`);
    }
    if (ids.has(id)) {
      throw new Error(`duplicate parameter example id: ${id}`);
    }
    if (
      expectedCborBytes !== undefined &&
      (!Number.isSafeInteger(expectedCborBytes) || expectedCborBytes < 0)
    ) {
      throw new Error(`invalid expected CBOR byte length for ${id}`);
    }
    if (repeatedIntList !== undefined) {
      const { element, elementCount } = repeatedIntList;
      if (!Number.isSafeInteger(elementCount) || elementCount < 0) {
        throw new Error(`invalid repeated-list element count for ${id}`);
      }
      const reconstructed = Array.from(
        { length: elementCount },
        () => element,
      );
      if (Data.to(value) !== Data.to(reconstructed)) {
        throw new Error(`repeated-list metadata does not match ${id}`);
      }
    }
    ids.add(id);
  }
};

const main = (): void => {
  validateParameterExamples();
  runAiken("build");
  const blueprint = JSON.parse(readFileSync(BLUEPRINT, "utf8")) as Blueprint;
  const constants: string[] = [];
  const prefixes = new Map<string, string>();

  for (const parameter of PARAMETER_EXAMPLES) {
    const { id, family, value, expectedCborBytes, repeatedIntList } = parameter;
    const { prefix, parameterCbor, scriptHash } = generateScript(
      blueprint,
      family,
      value,
      resolveParameterCbor(parameter),
    );

    if (
      expectedCborBytes !== undefined &&
      parameterCbor.length / 2 !== expectedCborBytes
    ) {
      throw new Error(
        `${id} produced ${parameterCbor.length / 2} CBOR bytes; expected ${expectedCborBytes}`,
      );
    }

    const familyPrefix = prefixes.get(family);
    if (familyPrefix === undefined) {
      prefixes.set(family, prefix);
      constants.push(
        `pub const ${family}_flat_prefix_without_parameter_header = #"${prefix}"`,
      );
    } else if (familyPrefix !== prefix) {
      throw new Error(`parameter family ${family} produced conflicting prefixes`);
    }

    constants.push(
      `pub const ${id}_parameter_cbor = #"${parameterCbor}"`,
      `pub const ${id}_script_hash = #"${scriptHash}"`,
    );
    if (repeatedIntList !== undefined) {
      const { element, elementCount } = repeatedIntList;
      constants.push(
        `pub const ${id}_element = ${element}`,
        `pub const ${id}_element_count = ${elementCount}`,
      );
    }
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
