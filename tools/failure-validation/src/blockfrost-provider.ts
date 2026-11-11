import assert from "node:assert/strict";
import {
  CML, applyDoubleCborEncoding, fromHex, scriptFromNative,
  type Credential, type OutRef, type Provider, type Script, type UTxO,
} from "@lucid-evolution/lucid";
import { ProtocolParams, SlotConfig, evaluator } from "scalus";
import { BLOCKFROST_URLS, type LiveNetwork } from "./network.ts";
import { REDEEMER_TAGS, toLucidParameters, toScalusUtxo } from "./scalus-provider.ts";
import { inputReferences, outRef } from "./transactions.ts";

type Output = {
  tx_hash: string; output_index: number; address: string;
  amount: { unit: string; quantity: string }[];
  inline_datum?: string | null; data_hash?: string | null; reference_script_hash?: string | null;
};

export class BlockfrostProvider implements Provider {
  readonly url: string;
  readonly slotConfig: SlotConfig;
  #apiKey: string;
  #fetch: typeof fetch;
  #signal: AbortSignal;
  #operationSignal: AbortSignal | undefined;
  #scripts = new Map<string, Script>();
  #addresses = new Map<string, string>();
  protocolParams?: ProtocolParams;

  constructor(network: LiveNetwork, apiKey: string, signal: AbortSignal, fetcher = fetch) {
    this.url = BLOCKFROST_URLS[network];
    this.slotConfig = network === "Mainnet" ? SlotConfig.mainnet : network === "Preprod" ? SlotConfig.preprod : SlotConfig.preview;
    this.#apiKey = apiKey;
    this.#fetch = fetcher;
    this.#signal = signal;
  }

  async withSignal<T>(signal: AbortSignal, action: () => Promise<T>): Promise<T> {
    const previous = this.#operationSignal;
    this.#operationSignal = signal;
    try { return await action(); } finally { this.#operationSignal = previous; }
  }

  async request<T>(path: string, init: RequestInit = {}, missing = false): Promise<T | undefined> {
    let response: Response;
    try {
      response = await this.#fetch(`${this.url}${path}`, {
        ...init, headers: { ...init.headers, project_id: this.#apiKey },
        signal: AbortSignal.any([this.#signal, this.#operationSignal ?? this.#signal, init.signal ?? this.#signal, AbortSignal.timeout(30_000)]),
      });
      if (missing && response.status === 404) return undefined;
      // Never include server bodies or request headers in errors: they may echo credentials.
      if (!response.ok) throw new Error(`Blockfrost ${init.method ?? "GET"} failed (HTTP ${response.status}).`);
      return await response.json() as T;
    } catch (error) {
      this.#signal.throwIfAborted();
      this.#operationSignal?.throwIfAborted();
      init.signal?.throwIfAborted();
      if (error instanceof Error && /^Blockfrost .*failed \(HTTP \d+\)\.$/.test(error.message)) throw error;
      throw new Error("Blockfrost request failed or timed out; submission status may be unknown.");
    }
  }

  async getProtocolParameters() {
    const raw = await this.request<Record<string, unknown>>("/epochs/latest/parameters");
    assert(raw, "Missing protocol parameters.");
    const params = ProtocolParams.fromBlockfrostJson(JSON.stringify(raw));
    const result = toLucidParameters(params);
    assert(result.protocolMajorVersion && result.costModels.PlutusV3?.length && result.maxTxExMem > 0n && result.maxTxExSteps > 0n,
      "Incomplete Plutus V3 protocol parameters.");
    this.protocolParams = params;
    return result;
  }

  async getUtxos(addressOrCredential: string | Credential): Promise<UTxO[]> {
    let address: string;
    if (typeof addressOrCredential === "string") address = addressOrCredential;
    else {
      const hash = addressOrCredential.type === "Key" ? CML.Ed25519KeyHash.from_hex(addressOrCredential.hash) : CML.ScriptHash.from_hex(addressOrCredential.hash);
      try { address = hash.to_bech32(addressOrCredential.type === "Key" ? "addr_vkh" : "script"); } finally { hash.free(); }
    }
    const outputs: Output[] = [];
    for (let page = 1; ; page++) {
      const batch = await this.request<Output[]>(`/addresses/${address}/utxos?count=100&page=${page}`, {}, true);
      if (!batch) break;
      outputs.push(...batch);
      if (batch.length < 100) break;
    }
    const result: UTxO[] = [];
    for (const output of outputs) {
      const utxo: UTxO = {
        txHash: output.tx_hash, outputIndex: output.output_index, address: output.address,
        assets: Object.fromEntries(output.amount.map(({ unit, quantity }) => [unit, BigInt(quantity)])),
      };
      if (output.inline_datum) utxo.datum = output.inline_datum;
      else if (output.data_hash) utxo.datumHash = output.data_hash;
      if (output.reference_script_hash) utxo.scriptRef = await this.script(output.reference_script_hash);
      this.#addresses.set(`${utxo.txHash}#${utxo.outputIndex}`, utxo.address);
      result.push(utxo);
    }
    return result;
  }

  private async script(hash: string): Promise<Script> {
    const cached = this.#scripts.get(hash);
    if (cached) return cached;
    const info = await this.request<{ type: string }>(`/scripts/${hash}`);
    let script: Script;
    if (info?.type === "timelock") {
      const native = await this.request<{ json: Parameters<typeof scriptFromNative>[0] }>(`/scripts/${hash}/json`);
      assert(native); script = scriptFromNative(native.json);
    } else {
      const types: Record<string, Script["type"]> = { plutusV1: "PlutusV1", plutusV2: "PlutusV2", plutusV3: "PlutusV3" };
      const type = types[info?.type ?? ""];
      const data = await this.request<{ cbor: string }>(`/scripts/${hash}/cbor`);
      assert(type && data?.cbor, "Missing reference script.");
      script = { type, script: applyDoubleCborEncoding(data.cbor) };
    }
    this.#scripts.set(hash, script);
    return script;
  }

  async getUtxosWithUnit(address: string | Credential, unit: string) {
    return (await this.getUtxos(address)).filter((u) => (u.assets[unit] ?? 0n) > 0n);
  }

  async getUtxoByUnit(unit: string) {
    const addresses = await this.request<{ address: string }[]>(`/assets/${unit}/addresses?count=2`);
    assert(addresses?.length === 1, "Expected a unique token address.");
    const utxos = await this.getUtxosWithUnit(addresses[0]!.address, unit);
    assert(utxos.length === 1, "Expected a unique token UTxO.");
    return utxos[0]!;
  }

  async getUtxosByOutRef(refs: OutRef[]) {
    // History identifies addresses only. In particular consumed_by_tx can remain
    // null after collateral is spent; only current address UTxOs prove spendability.
    const addresses = new Set<string>();
    const unknown: OutRef[] = [];
    for (const ref of refs) {
      const address = this.#addresses.get(`${ref.txHash}#${ref.outputIndex}`);
      if (address) addresses.add(address); else unknown.push(ref);
    }
    for (const hash of new Set(unknown.map((r) => r.txHash))) {
      const history = await this.request<{ outputs: Output[] }>(`/txs/${hash}/utxos`, {}, true);
      for (const output of history?.outputs ?? []) {
        if (refs.some((r) => r.txHash === hash && r.outputIndex === output.output_index)) addresses.add(output.address);
      }
    }
    const found: UTxO[] = [];
    for (const address of addresses) found.push(...await this.getUtxos(address));
    return found.filter((u) => refs.some((r) => r.txHash === u.txHash && r.outputIndex === u.outputIndex));
  }

  async getRewardAccount(address: string) {
    const account = await this.request<{ active: boolean; pool_id: string | null; withdrawable_amount: string }>(`/accounts/${address}`, {}, true);
    return { registered: account?.active ?? false, poolId: account?.pool_id ?? null, rewards: BigInt(account?.withdrawable_amount ?? 0) };
  }
  async getDelegation(address: string) { const { poolId, rewards } = await this.getRewardAccount(address); return { poolId, rewards }; }
  async getDatum(hash: string) { const datum = await this.request<{ cbor: string }>(`/scripts/datum/${hash}/cbor`); assert(datum); return datum.cbor; }

  async transaction(hash: string, signal?: AbortSignal) {
    return this.request<{ hash: string; block: string; block_height: number; slot: number; valid_contract: boolean }>(
      `/txs/${hash}`, signal ? { signal } : {}, true);
  }
  async awaitTx(hash: string) { return !!(await this.transaction(hash))?.block; }
  async submitTx(cbor: string) {
    // Submit the exact envelope, including isValid=false, with no wallet rewrite or retry.
    const hash = await this.request<string>("/tx/submit", { method: "POST", headers: { "Content-Type": "application/cbor" }, body: Buffer.from(cbor, "hex") });
    assert(typeof hash === "string" && /^[0-9a-f]{64}$/.test(hash), "Missing submitted transaction hash.");
    return hash;
  }

  async evaluateTx(tx: string, additionalUTxOs: UTxO[] = []) {
    assert(this.protocolParams, "Load protocol parameters before evaluation.");
    const transaction = CML.Transaction.from_cbor_hex(tx);
    const body = transaction.body();
    let refs: OutRef[];
    try { refs = [...inputReferences(body.inputs()), ...inputReferences(body.reference_inputs())]; }
    finally { body.free(); transaction.free(); }
    const missing = refs.filter((r) => !additionalUTxOs.some((u) => JSON.stringify(outRef(u)) === JSON.stringify(r)));
    const resolved = [...additionalUTxOs, ...await this.getUtxosByOutRef(missing)];
    const p = this.protocolParams;
    return evaluator.evaluateTx(fromHex(tx), resolved.map(toScalusUtxo), this.slotConfig, p.costModels, p.protocolMajorVersion,
      { memory: p.maxTxExecutionMemory, steps: p.maxTxExecutionSteps }).map((r) => ({
        redeemer_tag: REDEEMER_TAGS[r.tag], redeemer_index: r.index,
        ex_units: { mem: Number(r.budget.memory), steps: Number(r.budget.steps) },
      }));
  }
}
