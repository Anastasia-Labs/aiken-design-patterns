import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  GENERATED_PREFIX_END as end,
  GENERATED_PREFIX_START as start,
  replaceGeneratedPrefix,
} from "./environment.ts";

const before = "use aiken/builtin\n\n// Handwritten spacing stays intact.  \n";
const after = "\n\npub const builtin_function = builtin.verify_ed25519_signature\n\n";
const oldConstants = 'pub const old_prefix = #"00"';
const newConstants = 'pub const new_prefix = #"abcd"\n\npub const example_count = 2';
const source = before + start + "\n" + oldConstants + "\n\n" + end + after;

test("replaces the generated section and preserves surrounding source verbatim", () => {
  assert.equal(
    replaceGeneratedPrefix(source, newConstants + "\n"),
    before + start + "\n" + newConstants + "\n\n" + end + after,
  );
});

test("repeated regeneration is idempotent", () => {
  const first = replaceGeneratedPrefix(source, newConstants);
  assert.equal(replaceGeneratedPrefix(first, newConstants), first);
});

test("preserves CRLF source outside the generated section", () => {
  const crlfSource = source.replace(/\n/g, "\r\n");
  const expected = (before + start + "\n" + newConstants + "\n\n" + end + after).replace(/\n/g, "\r\n");
  assert.equal(replaceGeneratedPrefix(crlfSource, newConstants), expected);
});

test("preserves an end marker at end of file without adding a trailing newline", () => {
  const result = replaceGeneratedPrefix(start + "\n" + oldConstants + "\n" + end, newConstants);
  assert.equal(result, start + "\n" + newConstants + "\n\n" + end);
});

for (const [name, malformed] of [
  ["both missing", oldConstants],
  ["begin missing", oldConstants + "\n" + end],
  ["end missing", start + "\n" + oldConstants],
  ["begin duplicated", start + "\n" + source],
  ["end duplicated", source + end + "\n"],
  ["reversed", end + "\n" + oldConstants + "\n" + start + "\n"],
  ["begin inline", "some source " + start + "\n" + oldConstants + "\n" + end],
  ["begin has trailing text", start + " extra\n" + oldConstants + "\n" + end],
  ["end inline", start + "\n" + oldConstants + " " + end],
  ["end has trailing text", start + "\n" + oldConstants + "\n" + end + " extra"],
]) {
  test("rejects malformed markers: " + name, () => {
    assert.equal(typeof malformed, "string");
    if (malformed === undefined) throw new Error("missing test fixture");
    assert.throws(() => replaceGeneratedPrefix(malformed, newConstants), /generated prefix markers/);
  });
}

for (const environment of ["default", "testnet"]) {
  test("preserves builtin selection and application in the " + environment + " environment", () => {
    const actual = readFileSync(new URL("../../../env/" + environment + ".ak", import.meta.url), "utf8");
    const updated = replaceGeneratedPrefix(actual, newConstants);
    assert(updated.includes("pub const builtin_function:"));
    assert(updated.includes("pub const apply_builtin:"));
    assert(updated.includes("arguments.with_arity_3(datum)"));
    assert(!updated.includes("pub const bytearray_flat_prefix_without_parameter_header"));
    assert.equal(updated.slice(updated.indexOf(end)), actual.slice(actual.indexOf(end)));
    assert.equal(updated.slice(0, updated.indexOf(start)), actual.slice(0, actual.indexOf(start)));
  });
}
