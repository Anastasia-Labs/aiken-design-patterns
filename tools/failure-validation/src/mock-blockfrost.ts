import assert from "node:assert/strict";
import { CML, applySingleCborEncoding, fromHex, validatorToScriptHash, walletFromSeed, type Script, type UTxO } from "@lucid-evolution/lucid";
import { CardanoInfo, Emulator, Utxo, Value } from "scalus";
import { toLucidUtxo } from "./scalus-provider.ts";
import { referenceKey } from "./runtime.ts";

// Public BIP-39 test vector. This fixture has no access to a live service.
export const MOCK_SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
export const MOCK_KEY = "blockfrost-test-secret";

export function mockBlockfrost(network: "Mainnet" | "Preprod" | "Preview" = "Preprod", funding: readonly bigint[] = [1000n]) {
  const info = network === "Mainnet" ? CardanoInfo.mainnet() : network === "Preprod" ? CardanoInfo.preprod() : CardanoInfo.preview();
  const emulator = Emulator.create(info, { slot: 1_000_000 });
  const wallet = walletFromSeed(MOCK_SEED, { network, accountIndex: 0, addressType: "Base" });
  funding.forEach((ada, index) => emulator.addUtxo(new Utxo("01".repeat(32), index, wallet.address, Value.ada(ada))));
  const history = new Map<string, UTxO>();
  const scripts = new Map<string, Script>();
  const submissions: { hash: string; cbor: string; valid: boolean }[] = [];
  const requests: string[] = [];
  const polls = new Map<string, number>();
  const controls = { confirmationDelay: 0, indexingDelay: 0, hideConfirmations: false, rejectSubmission: false, afterSubmit: undefined as (() => void) | undefined };
  let lastHash = "";
  let indexPolls = 0;
  let beforeSubmission: UTxO[] = [];
  let rawParameters = JSON.parse(info.protocolParams.toBlockfrostJson());
  const jsonOutput = (u: UTxO) => ({
    tx_hash: u.txHash, output_index: u.outputIndex, address: u.address,
    amount: Object.entries(u.assets).map(([unit, quantity]) => ({ unit, quantity: quantity.toString() })),
    inline_datum: u.datum ?? null, data_hash: u.datumHash ?? null,
    reference_script_hash: u.scriptRef ? validatorToScriptHash(u.scriptRef) : null,
    consumed_by_tx: null, // Deliberately never updated, even after collateral is consumed.
  });
  const remember = () => {
    for (const value of emulator.getUtxos().map(toLucidUtxo)) {
      history.set(referenceKey(value), value);
      if (value.scriptRef) scripts.set(validatorToScriptHash(value.scriptRef), value.scriptRef);
    }
  };
  remember();
  const missing = () => Response.json({ status_code: 404 }, { status: 404 });
  const fetcher: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    const path = url.pathname.replace('/api/v0', '');
    requests.push(path);
    assert.equal(new Headers(init?.headers).get("project_id"), MOCK_KEY);
    init?.signal?.throwIfAborted();
    if (path === "/epochs/latest/parameters") return Response.json(rawParameters);
    if (path === "/tx/submit") {
      assert.equal(init?.method, "POST");
      assert.equal(new Headers(init.headers).get("content-type"), "application/cbor");
      if (controls.rejectSubmission) return Response.json({ error: `${MOCK_KEY} ${MOCK_SEED}` }, { status: 400 });
      const bytes = Buffer.from(init.body as Uint8Array);
      const tx = CML.Transaction.from_cbor_bytes(bytes);
      const valid = tx.is_valid(); tx.free();
      beforeSubmission = emulator.getUtxos().map(toLucidUtxo);
      const result = emulator.submitTx(bytes);
      assert(result.isSuccess, `${result.errorRule}: ${result.error}`);
      assert(result.txHash);
      lastHash = result.txHash; indexPolls = 0;
      submissions.push({ hash: result.txHash, cbor: bytes.toString("hex"), valid });
      remember();
      controls.afterSubmit?.();
      return Response.json(result.txHash);
    }
    const txMatch = /^\/txs\/([0-9a-f]+)(\/utxos)?$/.exec(path);
    if (txMatch) {
      const [, hash, utxos] = txMatch;
      if (utxos) {
        const outputs = [...history.values()].filter((u) => u.txHash === hash).map(jsonOutput);
        return outputs.length ? Response.json({ outputs }) : missing();
      }
      const tx = submissions.find((t) => t.hash === hash);
      const count = (polls.get(hash!) ?? 0) + 1; polls.set(hash!, count);
      if (!tx || controls.hideConfirmations || count <= controls.confirmationDelay) return missing();
      return Response.json({ hash, block: "ab".repeat(32), block_height: 10, slot: 1_000_000, valid_contract: tx.valid });
    }
    const addressMatch = /^\/addresses\/([^/]+)\/utxos$/.exec(path);
    if (addressMatch) {
      const delayed = lastHash && indexPolls++ < controls.indexingDelay;
      const values = delayed ? beforeSubmission : emulator.getUtxos().map(toLucidUtxo);
      const count = Number(url.searchParams.get("count") ?? 100);
      const start = (Number(url.searchParams.get("page") ?? 1) - 1) * count;
      return Response.json(values.filter((u) => u.address === addressMatch[1]).slice(start, start + count).map(jsonOutput));
    }
    const account = /^\/accounts\/(.+)$/.exec(path);
    if (account) {
      const reward = emulator.getStakeReward(account[1]!);
      return reward === undefined ? missing() : Response.json({ active: true, pool_id: null, withdrawable_amount: reward.toString() });
    }
    const scriptMatch = /^\/scripts\/([0-9a-f]+)(\/cbor)?$/.exec(path);
    if (scriptMatch) {
      const script = scripts.get(scriptMatch[1]!); assert(script);
      if (scriptMatch[2]) return Response.json({ cbor: applySingleCborEncoding(script.script) });
      return Response.json({ type: script.type.replace("Plutus", "plutus") });
    }
    const asset = /^\/assets\/(.+)\/addresses$/.exec(path);
    if (asset) return Response.json([...new Set(emulator.getUtxos({ unit: asset[1]! }).map((u) => u.address))].map((address) => ({ address })));
    throw new Error(`Unhandled mock request: ${path}`);
  };
  return { info, emulator, wallet, history, submissions, requests, polls, controls, fetcher,
    setParameters: (value: typeof rawParameters) => { rawParameters = value; },
    rawParameters: () => structuredClone(rawParameters),
    validCbor: (index: number) => fromHex(submissions[index]!.cbor),
  };
}
