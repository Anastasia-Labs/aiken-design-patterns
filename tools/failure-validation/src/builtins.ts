import assert from "node:assert/strict";
import { Cbor } from "@harmoniclabs/cbor";
import { Data } from "@lucid-evolution/lucid";

// Add a signature here and named test inputs in CASES. No runner changes needed.
export const BUILTINS: readonly string[] = [
  "bls12_381_g2_uncompress(ByteArray) -> G2Element",
  "bls12_381_g1_uncompress(ByteArray) -> G1Element",
  "verify_ecdsa_secp256k1_signature(ByteArray, ByteArray, ByteArray) -> Bool",
  "verify_schnorr_secp256k1_signature(ByteArray, ByteArray, ByteArray) -> Bool",
];

// builtin/case-name | success, false, or builtin-error | inline datum CBOR
export const CASES: readonly string[] = [
  // Compressed generators from aiken/crypto/bls12_381/{g1,g2}.
  `bls12_381_g2_uncompress/generator|success|${Data.to([
    "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
  ])}`,
  `bls12_381_g2_uncompress/empty|builtin-error|${Data.to([""])}`,
  `bls12_381_g2_uncompress/invalid-encoding|builtin-error|${Data.to(["00".repeat(96)])}`,
  `bls12_381_g1_uncompress/generator|success|${Data.to([
    "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
  ])}`,
  `bls12_381_g1_uncompress/empty|builtin-error|${Data.to([""])}`,
  `bls12_381_g1_uncompress/invalid-encoding|builtin-error|${Data.to(["00".repeat(48)])}`,
  // Aiken's vendored Plutus conformance v3/builtin/semantics/
  // verifyEcdsaSecp256k1Signature/test-vector-01.
  // The message argument is SHA-256 of the empty message signed by that vector.
  `verify_ecdsa_secp256k1_signature/valid|success|${Data.to([
    "032e433589dce61863199171f4d1e3fa946a5832621fcd29559940a0950f96fb6f",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "4941155e2303988a1be97a021fbaf9fe6064d05ea694bc5e89328f297154e5c63a2f3e7b5f509294a4c2e22feb697a16b792fabfebe9d0f38403b1c929836b5a",
  ])}`,
  `verify_ecdsa_secp256k1_signature/wrong-message|false|${Data.to([
    "032e433589dce61863199171f4d1e3fa946a5832621fcd29559940a0950f96fb6f",
    "01".repeat(32),
    "4941155e2303988a1be97a021fbaf9fe6064d05ea694bc5e89328f297154e5c63a2f3e7b5f509294a4c2e22feb697a16b792fabfebe9d0f38403b1c929836b5a",
  ])}`,
  `verify_ecdsa_secp256k1_signature/empty|builtin-error|${Data.to(["", "", ""])}`,
  // BIP-340 test vector 0: https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
  `verify_schnorr_secp256k1_signature/valid|success|${Data.to([
    "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    "00".repeat(32),
    "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
  ])}`,
  `verify_schnorr_secp256k1_signature/wrong-message|false|${Data.to([
    "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    "01".repeat(32),
    "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
  ])}`,
  `verify_schnorr_secp256k1_signature/empty|builtin-error|${Data.to(["", "", ""])}`,
];

export type Outcome = "success" | "false" | "builtin-error";
export type BuiltinCase = { name: string; outcome: Outcome; datum: string };
export type Builtin = { name: string; arity: number; returnType: string; cases: BuiltinCase[] };

export const WITHDRAWAL_RESULTS = {
  success: "success",
  false: "SCRIPT_FAILURE",
  "builtin-error": "BUILTIN_FAILURE",
} as const;

export function parseBuiltins(signatures: readonly string[], cases: readonly string[]): Builtin[] {
  assert(signatures.length > 0, "Configure at least one builtin.");
  const builtins = new Map<string, Builtin>();
  for (const signature of signatures) {
    const match = /^\s*([a-z][a-z0-9_]*)\s*\(([^()]*)\)\s*->\s*([A-Z][A-Za-z0-9_]*(?:<[A-Za-z0-9_<>, ]+>)?)\s*$/.exec(signature);
    assert(match, `Invalid builtin signature: ${signature}`);
    const [, name, rawArguments, returnType] = match;
    assert(name && rawArguments !== undefined && returnType);
    const arguments_ = rawArguments.trim() === "" ? [] : rawArguments.split(",").map((s) => s.trim());
    assert(arguments_.every((type) => type === "ByteArray"), `${name}: only ByteArray arguments are supported.`);
    assert(arguments_.length <= 6, `${name}: at most six arguments are supported.`);
    assert(!builtins.has(name), `Duplicate builtin: ${name}`);
    builtins.set(name, { name, arity: arguments_.length, returnType, cases: [] });
  }
  for (const entry of cases) {
    const match = /^\s*([a-z][a-z0-9_]*)\/([a-z0-9][a-z0-9_-]*)\s*\|\s*(success|false|builtin-error)\s*\|\s*((?:[a-fA-F0-9]{2})+)\s*$/.exec(entry);
    assert(match, `Invalid builtin case: ${entry}`);
    const [, name, caseName, rawOutcome, datum] = match;
    assert(name && caseName && rawOutcome && datum);
    const outcome = rawOutcome as Outcome;
    const builtin = builtins.get(name);
    assert(builtin, `Case references unknown builtin: ${name}`);
    assert(!builtin.cases.some((c) => c.name === caseName), `Duplicate case: ${name}/${caseName}`);
    assert(outcome !== "false" || builtin.returnType === "Bool", `${name}/${caseName}: false requires a Bool result.`);
    assert.equal(Cbor.parseWithOffset(datum).offset, datum.length / 2, `${name}/${caseName}: trailing datum CBOR.`);
    const arguments_ = Data.from(datum);
    assert(Array.isArray(arguments_) && arguments_.length === builtin.arity,
      `${name}/${caseName}: expected a Data list with ${builtin.arity} arguments.`);
    assert(arguments_.every((arg) => typeof arg === "string"), `${name}/${caseName}: arguments must be byte strings.`);
    builtin.cases.push({ name: caseName, outcome, datum: datum.toLowerCase() });
  }
  for (const builtin of builtins.values()) assert(builtin.cases.length > 0, `${builtin.name}: missing cases.`);
  return [...builtins.values()];
}
