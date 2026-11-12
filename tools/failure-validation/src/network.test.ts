import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CML, getAddressDetails, walletFromSeed } from "@lucid-evolution/lucid";
import { NETWORKS, BLOCKFROST_URLS, loadEnvironment, readNetworkConfig, redactSecrets } from "./network.ts";
import { createRuntime } from "./runtime.ts";
import { withBuiltinProject } from "./environment.ts";
import { parseBuiltins } from "./builtins.ts";
import { buildValidators, ARTIFACT_DIRECTORY } from "./blueprint.ts";
import { CardanoInfo } from "scalus";

// Public BIP-39 test vector, never fund this wallet on a real network.
export const TEST_SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const credentials = { BLOCKFROST_API_KEY: "test-api-key", WALLET_SEED: TEST_SEED };
const builtin = parseBuiltins(["equals_bytearray(ByteArray, ByteArray) -> Bool"], ["equals_bytearray/equal|success|9f4040ff"]);

test(".env loading supports quoted credentials, shell overrides, missing files, and secret redaction", () => {
  const directory = mkdtempSync(join(tmpdir(), "failure-env-"));
  const names = ["NETWORK", "BLOCKFROST_API_KEY", "WALLET_SEED", "AIKEN"] as const;
  const previous = names.map((name) => [name, process.env[name]] as const);
  try {
    for (const name of names) delete process.env[name];
    const path = join(directory, ".env");
    loadEnvironment(path);
    assert.deepEqual(readNetworkConfig(), { network: "Custom" });
    writeFileSync(path, `NETWORK=Preprod\nBLOCKFROST_API_KEY="test-key#quoted"\nWALLET_SEED="${TEST_SEED}"\nAIKEN="compiler with spaces"\n`);
    loadEnvironment(path);
    assert.deepEqual(readNetworkConfig(), { network: "Preprod", apiKey: "test-key#quoted", seed: TEST_SEED });
    assert.equal(process.env.AIKEN, "compiler with spaces");
    assert.equal(redactSecrets()(`test-key#quoted ${TEST_SEED}`), "[redacted] [redacted]");
    process.env.NETWORK = "Custom";
    process.env.BLOCKFROST_API_KEY = "shell-key";
    loadEnvironment(path);
    assert.deepEqual(readNetworkConfig(), { network: "Custom" });
    assert.equal(process.env.BLOCKFROST_API_KEY, "shell-key");
    assert.throws(() => loadEnvironment(directory), /Could not load the failure-validation \.env file\./);
  } finally {
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
    rmSync(directory, { recursive: true, force: true });
  }
});

// Configuration parsing must not reflect any user-supplied value in an error.
test("network configuration accepts only the four exact settings and validates credentials", () => {
  assert.deepEqual(readNetworkConfig({}), { network: "Custom" });
  for (const network of NETWORKS) assert.equal(readNetworkConfig({ NETWORK: network, ...credentials }).network, network);
  for (const network of ["", "mainnet", "custom", "preview", "Testnet", "Preprod ", credentials.WALLET_SEED]) {
    assert.throws(() => readNetworkConfig({ NETWORK: network }), /^Error: NETWORK must/);
  }
  for (const network of NETWORKS.filter((n) => n !== "Custom")) {
    assert.throws(() => readNetworkConfig({ NETWORK: network, WALLET_SEED: TEST_SEED }), /BLOCKFROST_API_KEY is required/);
    assert.throws(() => readNetworkConfig({ NETWORK: network, BLOCKFROST_API_KEY: "x" }), /WALLET_SEED is required/);
    assert.throws(() => readNetworkConfig({ NETWORK: network, BLOCKFROST_API_KEY: "x", WALLET_SEED: "invalid seed" }), /^Error: WALLET_SEED must be a valid mnemonic\.$/);
  }
});

for (const network of NETWORKS) {
  test(`${network} derives the wallet, selects its endpoint, and generates the compilation tag`, async (t) => {
    const requests: string[] = [];
    const config = readNetworkConfig({ NETWORK: network, ...credentials });
    const info = network === "Mainnet" ? CardanoInfo.mainnet() : network === "Preprod" ? CardanoInfo.preprod() : CardanoInfo.preview();
    const fetcher: typeof fetch = async (input) => {
      requests.push(String(input));
      return Response.json(JSON.parse(info.protocolParams.toBlockfrostJson()));
    };
    t.mock.method(globalThis, "fetch", fetcher);
    const runtime = await createRuntime(config);
    assert.equal(runtime.network, network);
    assert.equal(getAddressDetails(runtime.walletAddress).networkId, network === "Mainnet" ? 1 : 0);
    if (network === "Custom") { assert(runtime.emulator); assert.equal(runtime.threshold, 2); assert.deepEqual(requests, []); }
    else {
      assert.equal(runtime.emulator, undefined);
      const wallet = walletFromSeed(TEST_SEED, { network, accountIndex: 0, addressType: "Base" });
      assert.equal(runtime.walletAddress, wallet.address);
      assert.equal(runtime.signers.length, 1);
      assert.equal(runtime.signers[0]!.hash, getAddressDetails(wallet.address).paymentCredential!.hash);
      assert.equal(runtime.threshold, 1);
      assert.equal(requests[0], `${BLOCKFROST_URLS[network]}/epochs/latest/parameters`);
      // Independent derivation of CIP-1852 account 0, payment role 0, index 0.
      const root = CML.Bip32PrivateKey.from_bip39_entropy(new Uint8Array(16), new Uint8Array());
      const derived = root.derive(1852 + 0x80000000).derive(1815 + 0x80000000).derive(0x80000000).derive(0).derive(0).to_raw_key();
      assert.equal(derived.to_bech32(), wallet.paymentKey);
      derived.free(); root.free();
    }
    await withBuiltinProject(builtin[0]!, async (directory) => {
      const config = readFileSync(`${directory}/aiken.toml`, "utf8");
      assert(config.endsWith(`[config.failure_tooling]\nnetwork_tag = ${network === "Mainnet" ? 1 : 0}\n`));
      assert(readFileSync(`${directory}/env/failure_tooling.ak`, "utf8").includes("builtin.equals_bytearray"));
    }, undefined, network);
  });
}

test("Mainnet and testnet compilation produce distinct proof scripts without CLI artifacts", async () => {
  const files = () => { try { return readdirSync(ARTIFACT_DIRECTORY, { recursive: true }).sort(); } catch { return []; } };
  const before = files();
  const mainnet = await buildValidators(builtin[0]!, undefined, "Mainnet");
  const testnet = await buildValidators(builtin[0]!, undefined, "Preprod");
  assert.equal(mainnet.networkTag, 1);
  assert.equal(testnet.networkTag, 0);
  assert.notEqual(mainnet.mint.script, testnet.mint.script);
  assert.equal(mainnet.withdrawal.script, testnet.withdrawal.script);
  assert.deepEqual(files(), before);
});
