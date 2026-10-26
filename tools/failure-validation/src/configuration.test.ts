import assert from "node:assert/strict";
import { test } from "node:test";
import { Data } from "@lucid-evolution/lucid";
import { BUILTINS, CASES, parseBuiltins } from "./builtins.ts";

const signature = "bls12_381_g1_uncompress(ByteArray) -> G1Element";
const testCase = "bls12_381_g1_uncompress/empty|builtin-error|9f40ff";

test("configuration keeps builtin order and associates cases by name", () => {
  const parsed = parseBuiltins(BUILTINS, [...CASES].reverse());
  assert.deepEqual(parsed.map((b) => b.name), BUILTINS.map((b) => b.split("(")[0]));
  assert.equal(parsed.flatMap((b) => b.cases).length, CASES.length);
  assert(parsed.every((b) => b.cases.every((c) => CASES.some((entry) => entry.startsWith(`${b.name}/${c.name}|`)))));
});

for (const [label, signatures, cases, message] of [
  ["empty registry", [], [], /at least one/],
  ["unsupported input type", ["foo(G1Element) -> Bool"], [], /only ByteArray/],
  ["too many arguments", [`foo(${Array(7).fill("ByteArray").join(",")}) -> Bool`], [], /at most six/],
  ["malformed signature", ["foo(ByteArray)"], [], /Invalid builtin signature/],
  ["duplicate builtin", [signature, signature], [testCase], /Duplicate builtin/],
  ["missing cases", [signature], [], /missing cases/],
  ["unknown reference", [signature], ["foo/empty|success|9f40ff"], /unknown builtin/],
  ["duplicate case", [signature], [testCase, testCase], /Duplicate case/],
  ["invalid outcome", [signature], [testCase.replace("builtin-error", "error")], /Invalid builtin case/],
  ["false with non-Boolean result", [signature], [testCase.replace("builtin-error", "false")], /Bool result/],
  ["invalid CBOR", [signature], [testCase.replace("9f40ff", "ff")], /./],
  ["trailing CBOR", [signature], [testCase + "00"], /trailing datum/],
  ["wrong datum shape", [signature], [testCase.replace("9f40ff", Data.void())], /Data list/],
  ["wrong arity", [signature], [testCase.replace("9f40ff", Data.to([]))], /Data list/],
  ["wrong argument type", [signature], [testCase.replace("9f40ff", Data.to([1n]))], /byte strings/],
  ["unsafe case path", [signature], [testCase.replace("/empty", "/../empty")], /Invalid builtin case/],
] as const) {
  test(`rejects ${label} before compiling`, () => {
    assert.throws(() => parseBuiltins(signatures, cases), message);
  });
}

test("accepts zero through six bytestring arguments", () => {
  for (let arity = 0; arity <= 6; arity++) {
    const [builtin] = parseBuiltins(
      [`foo(${Array(arity).fill("ByteArray").join(", ")}) -> Int`],
      [`foo/valid|success|${Data.to(Array(arity).fill(""))}`],
    );
    assert.equal(builtin?.arity, arity);
  }
});
