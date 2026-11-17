import assert from "node:assert/strict";
import { test } from "node:test";
import {
  Data,
  credentialToAddress,
  credentialToRewardAddress,
  fromHex,
  validatorToScriptHash,
  type Script,
} from "@lucid-evolution/lucid";
import { Asset, CardanoInfo, Emulator, Utxo, Value, scriptHash } from "scalus";
import { ScalusProvider, toLucidUtxo, toScalusUtxo } from "./scalus-provider.ts";

const HASH = "ab".repeat(28);
const ADDRESS = credentialToAddress("Preview", { type: "Key", hash: HASH });
const REFERENCE_SCRIPT: Script = { type: "PlutusV3", script: "450101002499" };

test("UTxO conversion preserves assets, datums, and reference script hashes", () => {
  const base = new Utxo("12".repeat(32), 7, ADDRESS, new Value(8_000_000n, [new Asset(HASH, "00ff", 3n)]));
  for (const utxo of [
    base,
    base.withDatumHash("34".repeat(32)),
    base.withInlineDatum(fromHex(Data.void())),
    base.withScriptRef(REFERENCE_SCRIPT),
    base.withInlineDatum(fromHex(Data.void())).withScriptRef(REFERENCE_SCRIPT),
  ]) {
    const lucid = toLucidUtxo(utxo);
    assert.deepEqual(toScalusUtxo(lucid).toObject(), utxo.toObject());
    if (utxo.scriptRef) {
      assert(lucid.scriptRef);
      assert.equal(validatorToScriptHash(lucid.scriptRef), scriptHash(utxo.scriptRef));
    }
  }
});

test("conversion rejects ambiguous resolved hash datums", () => {
  const utxo = toLucidUtxo(new Utxo("12".repeat(32), 0, ADDRESS, Value.ada(5n)));
  assert.throws(() => toScalusUtxo({ ...utxo, datumHash: "34".repeat(32), datum: Data.void() }), /Cannot distinguish/);
});

test("provider keeps key and script credentials distinct and reports stake registration", async () => {
  const scriptAddress = credentialToAddress("Preview", { type: "Script", hash: HASH });
  const emulator = Emulator.create(CardanoInfo.preview(), {
    slot: 1_000_000,
    utxos: [
      new Utxo("00".repeat(32), 0, ADDRESS, Value.ada(5n)),
      new Utxo("00".repeat(32), 1, scriptAddress, Value.ada(10n)),
    ],
    stakeRegistrations: [{ credentialType: "script", credentialHash: HASH, rewards: 0n }],
  });
  const provider = new ScalusProvider(emulator);
  assert.deepEqual((await provider.getUtxos({ type: "Key", hash: HASH })).map((u) => u.outputIndex), [0]);
  assert.deepEqual((await provider.getUtxos({ type: "Script", hash: HASH })).map((u) => u.outputIndex), [1]);
  assert.equal((await provider.getRewardAccount(credentialToRewardAddress("Preview", { type: "Script", hash: HASH }))).registered, true);
  assert.equal((await provider.getRewardAccount(credentialToRewardAddress("Preview", { type: "Key", hash: HASH }))).registered, false);
  assert.equal(await provider.awaitTx("ff".repeat(32)), false);
});
