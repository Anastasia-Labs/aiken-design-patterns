import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import {
  CML, Lucid, credentialToAddress, getAddressDetails,
  type LucidEvolution, type OutRef, type ProtocolParameters, type Wallet,
} from "@lucid-evolution/lucid";
import { CardanoInfo, Emulator, EvaluationOptions, Utxo, Value } from "scalus";
import { BlockfrostProvider } from "./blockfrost-provider.ts";
import { ScalusProvider } from "./scalus-provider.ts";
import type { Network, NetworkConfig } from "./network.ts";
import type { Artifacts } from "./artifacts.ts";

export function testKey(seed: number) {
  const privateKey = CML.PrivateKey.from_normal_bytes(new Uint8Array(32).fill(seed));
  const publicKey = privateKey.to_public();
  const hash = publicKey.hash();
  try { return { key: privateKey.to_bech32(), hash: hash.to_hex() }; }
  finally { hash.free(); publicKey.free(); privateKey.free(); }
}
export const referenceKey = (ref: OutRef) => `${ref.txHash}#${ref.outputIndex}`;
export type Runtime = {
  network: Network; provider: ScalusProvider | BlockfrostProvider; emulator?: Emulator;
  lucid: LucidEvolution; wallet: Wallet; walletAddress: string; referenceAddress: string;
  info: CardanoInfo; slotConfig: CardanoInfo["slotConfig"]; parameters: ProtocolParameters;
  evaluationOptions: ReturnType<typeof EvaluationOptions.fromProtocolParams>;
  signers: { hash: string; key?: string }[]; threshold: number; reserved: Set<string>;
  signal: AbortSignal; artifacts?: Artifacts; scope: string;
  now: () => number; sleep: (ms: number) => Promise<void>; confirmationTimeout: number;
};

export async function createRuntime(config: NetworkConfig, signal = new AbortController().signal, fetcher = fetch): Promise<Runtime> {
  const info = config.network === "Mainnet" ? CardanoInfo.mainnet() : config.network === "Preprod" ? CardanoInfo.preprod() : CardanoInfo.preview();
  const emulator = config.network === "Custom" ? Emulator.create(info, { slot: 1_000_000 }) : undefined;
  const provider = config.network === "Custom" ? new ScalusProvider(emulator!) : new BlockfrostProvider(config.network, config.apiKey, signal, fetcher);
  const parameters = await provider.getProtocolParameters();
  const currentInfo = provider instanceof BlockfrostProvider ? info.withProtocolParams(provider.protocolParams!) : info;
  const lucid = await Lucid(provider, config.network, { slotConfig: info.slotConfig, presetProtocolParameters: parameters });
  if (config.network === "Custom") lucid.selectWallet.fromPrivateKey(testKey(1).key);
  else lucid.selectWallet.fromSeed(config.seed, { accountIndex: 0, addressType: "Base" });
  const wallet = lucid.wallet();
  const walletAddress = await wallet.address();
  const payment = getAddressDetails(walletAddress).paymentCredential;
  assert(payment?.type === "Key");
  if (emulator) {
    emulator.addUtxo(new Utxo("00".repeat(32), 0, walletAddress, Value.ada(998n)));
    emulator.addUtxo(new Utxo("00".repeat(32), 1, walletAddress, Value.ada(2n)));
  }
  return {
    network: config.network, provider, ...(emulator ? { emulator } : {}), lucid, wallet, walletAddress,
    referenceAddress: emulator ? credentialToAddress(config.network, { type: "Key", hash: testKey(2).hash }) : walletAddress,
    info: currentInfo, slotConfig: info.slotConfig, parameters,
    evaluationOptions: EvaluationOptions.fromProtocolParams("PlutusV3", currentInfo.protocolParams),
    signers: emulator ? [testKey(1), testKey(3), testKey(4)] : [{ hash: payment.hash }], threshold: emulator ? 2 : 1,
    reserved: new Set(), signal, scope: "", now: Date.now,
    sleep: (ms) => delay(ms, undefined, { signal }), confirmationTimeout: 600_000,
  };
}

export async function refreshProtocol(runtime: Runtime) {
  if (runtime.network === "Custom") return;
  const parameters = await runtime.provider.getProtocolParameters();
  assert(runtime.provider instanceof BlockfrostProvider);
  runtime.parameters = parameters;
  runtime.info = runtime.info.withProtocolParams(runtime.provider.protocolParams!);
  runtime.evaluationOptions = EvaluationOptions.fromProtocolParams("PlutusV3", runtime.info.protocolParams);
  const lucid = await Lucid(runtime.provider, runtime.network, { slotConfig: runtime.slotConfig, presetProtocolParameters: parameters });
  lucid.config().wallet = runtime.wallet;
  runtime.lucid = lucid;
}

export async function ordinaryFunding(runtime: Runtime) {
  return (await runtime.provider.getUtxos(runtime.walletAddress))
    .filter((u) => !runtime.reserved.has(referenceKey(u)) && !u.scriptRef && !u.datum && !u.datumHash && Object.keys(u.assets).length === 1)
    .sort((a, b) => a.assets.lovelace! > b.assets.lovelace! ? -1 : 1);
}

export type Effects = { present?: OutRef[]; absent?: OutRef[]; addresses?: string[]; stakeRegistered?: string };

export async function submitTransaction(runtime: Runtime, name: string, cbor: string, effects: Effects = {}) {
  runtime.signal.throwIfAborted();
  const transaction = CML.Transaction.from_cbor_hex(cbor);
  const body = transaction.body();
  const bodyHash = CML.hash_transaction(body);
  const hash = bodyHash.to_hex();
  const valid = transaction.is_valid();
  bodyHash.free(); body.free(); transaction.free();
  const record = runtime.artifacts?.signed(runtime.scope, name, cbor, hash);
  const update = () => { if (record) runtime.artifacts!.flush(record); };
  try {
    assert(cbor.length / 2 <= runtime.parameters.maxTxSize,
      `${name}: signed transaction is ${cbor.length / 2} bytes; maximum is ${runtime.parameters.maxTxSize}.`);
    if (record) { record.status = "submitting"; update(); }
    assert.equal(await runtime.provider.submitTx(cbor), hash);
    if (record) { record.status = "submitted"; record.submittedAt = new Date().toISOString(); update(); }
    const deadline = runtime.now() + runtime.confirmationTimeout;
    const timeout = AbortSignal.timeout(runtime.confirmationTimeout);
    const waitForEffects = async () => {
      while (true) {
        runtime.signal.throwIfAborted();
        if (runtime.now() >= deadline || timeout.aborted) throw new Error(`Confirmation timed out for ${hash}; check this hash before another run.`);
        const confirmation = runtime.provider instanceof BlockfrostProvider
          ? await runtime.provider.transaction(hash, timeout)
          : runtime.emulator!.hasTx(hash) ? { hash, block: "emulator", valid_contract: valid } : undefined;
        if (confirmation?.block) {
          if (record && !record.includedAt) { record.includedAt = new Date().toISOString(); record.confirmation = confirmation; update(); }
          assert.equal(confirmation.valid_contract, valid, "Confirmed script validity differs from submitted envelope.");
          const current = [];
          for (const address of new Set(effects.addresses ?? [runtime.walletAddress])) current.push(...await runtime.provider.getUtxos(address));
          const present = new Set(current.map(referenceKey));
          const ready = (effects.present ?? []).every((r) => present.has(referenceKey(r)))
            && (effects.absent ?? []).every((r) => !present.has(referenceKey(r)))
            && (!effects.stakeRegistered || (await runtime.provider.getRewardAccount(effects.stakeRegistered)).registered);
          if (ready) {
            if (record) { record.status = "confirmed"; record.confirmedAt = new Date().toISOString(); record.confirmation = confirmation; update(); }
            return hash;
          }
        }
        await runtime.sleep(Math.min(3_000, Math.max(1, deadline - runtime.now())));
      }
    };
    try {
      return await (runtime.provider instanceof BlockfrostProvider ? runtime.provider.withSignal(timeout, waitForEffects) : waitForEffects());
    } catch (error) {
      if (timeout.aborted) throw new Error(`Confirmation timed out for ${hash}; check this hash before another run.`);
      throw error;
    }
  } catch (error) {
    if (record) { record.status = "stopped"; record.error = error instanceof Error ? error.message : "Transaction stopped."; update(); }
    throw error;
  }
}
