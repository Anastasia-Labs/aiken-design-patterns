import assert from "node:assert/strict";
import {
  Blockfrost, CML, applyDoubleCborEncoding, fromHex, scriptFromNative,
  type Credential, type OutRef, type ProtocolParameters, type RewardAccountState, type Script,
  type TransactionStatus, type TransactionStatusOptions, type UTxO,
} from "@lucid-evolution/lucid";
import { ProviderRequests } from "./provider-requests.ts";

type BlockfrostOutput = {
  tx_hash: string; output_index: number; address: string;
  amount: { unit: string; quantity: string }[];
  inline_datum?: string | null; data_hash?: string | null; reference_script_hash?: string | null;
};
export type TransactionObservation = TransactionStatus & { valid?: boolean };
const key = (ref: OutRef) => `${ref.txHash}#${ref.outputIndex}`;

export class LiveProvider extends Blockfrost {
  readonly requests: ProviderRequests;
  readonly knownAddresses = new Map<string, string>();
  readonly currentOutputs = new Map<string, UTxO[]>();
  readonly scripts = new Map<string, Promise<Script>>();
  readonly discoveries = new Map<string, Promise<void>>();
  readonly signal: AbortSignal | undefined;
  requestSignal?: AbortSignal;
  constructor(url: string, projectId: string, signal?: AbortSignal, requests = new ProviderRequests()) {
    super(url, projectId);
    this.signal = signal;
    this.requests = requests;
  }
  async request(path: string, init: RequestInit = {}) {
    const headers = new Headers(init.headers);
    headers.set("project_id", this.projectId);
    const signals = [this.signal, this.requestSignal, init.signal].filter((signal): signal is AbortSignal => !!signal);
    return this.requests.request(`${this.url}${path}`, { ...init, headers, ...(signals.length ? { signal: AbortSignal.any(signals) } : {}) });
  }
  async json<T>(path: string, missing?: T): Promise<T> {
    const response = await this.request(path);
    if (response.status === 404 && missing !== undefined) return missing;
    assert(response.ok, `Blockfrost ${path} failed (HTTP ${response.status}).`);
    return response.json() as Promise<T>;
  }
  override async getProtocolParameters(): Promise<ProtocolParameters> {
    const p = await this.json<Record<string, any>>("/epochs/latest/parameters");
    return {
      protocolMajorVersion: Number(p.protocol_major_ver), protocolMinorVersion: Number(p.protocol_minor_ver),
      minFeeA: Number(p.min_fee_a), minFeeB: Number(p.min_fee_b), maxTxSize: Number(p.max_tx_size), maxValSize: Number(p.max_val_size),
      keyDeposit: BigInt(p.key_deposit), poolDeposit: BigInt(p.pool_deposit), drepDeposit: BigInt(p.drep_deposit), govActionDeposit: BigInt(p.gov_action_deposit),
      priceMem: Number(p.price_mem), priceStep: Number(p.price_step), maxTxExMem: BigInt(p.max_tx_ex_mem), maxTxExSteps: BigInt(p.max_tx_ex_steps),
      coinsPerUtxoByte: BigInt(p.coins_per_utxo_size), collateralPercentage: Number(p.collateral_percent), maxCollateralInputs: Number(p.max_collateral_inputs),
      minFeeRefScriptCostPerByte: Number(p.min_fee_ref_script_cost_per_byte), costModels: p.cost_models_raw,
    };
  }
  remember(outputs: UTxO[]) { for (const output of outputs) this.knownAddresses.set(key(output), output.address); }
  async script(hash: string): Promise<Script> {
    let pending = this.scripts.get(hash);
    if (!pending) {
      pending = (async () => {
        const { type } = await this.json<{ type: string }>(`/scripts/${hash}`);
        if (type === "timelock") {
          const { json } = await this.json<{ json: Parameters<typeof scriptFromNative>[0] }>(`/scripts/${hash}/json`);
          return scriptFromNative(json);
        }
        assert(["plutusV1", "plutusV2", "plutusV3"].includes(type), "Unsupported reference script type.");
        const { cbor } = await this.json<{ cbor: string }>(`/scripts/${hash}/cbor`);
        return { type: type.replace("plutus", "Plutus") as Script["type"], script: applyDoubleCborEncoding(cbor) };
      })();
      this.scripts.set(hash, pending);
      pending.catch(() => this.scripts.delete(hash));
    }
    return pending;
  }
  async convert(outputs: BlockfrostOutput[]): Promise<UTxO[]> {
    const converted = await Promise.all(outputs.map(async (output): Promise<UTxO> => ({
      txHash: output.tx_hash, outputIndex: output.output_index, address: output.address,
      assets: Object.fromEntries(output.amount.map(({ unit, quantity }) => [unit, BigInt(quantity)])),
      ...(output.inline_datum ? { datum: output.inline_datum } : output.data_hash ? { datumHash: output.data_hash } : {}),
      ...(output.reference_script_hash ? { scriptRef: await this.script(output.reference_script_hash) } : {}),
    })));
    this.remember(converted);
    return converted;
  }
  async addressUtxos(address: string | Credential, unit?: string) {
    let predicate: string;
    if (typeof address === "string") predicate = address;
    else {
      const hash = address.type === "Key" ? CML.Ed25519KeyHash.from_hex(address.hash) : CML.ScriptHash.from_hex(address.hash);
      try { predicate = hash.to_bech32(address.type === "Key" ? "addr_vkh" : "script"); }
      finally { hash.free(); }
    }
    const outputs: BlockfrostOutput[] = [];
    for (let page = 1; ; page++) {
      const batch = await this.json<BlockfrostOutput[]>(`/addresses/${predicate}/utxos${unit ? `/${unit}` : ""}?count=100&page=${page}`, []);
      outputs.push(...batch);
      if (batch.length < 100) break;
    }
    return this.convert(outputs);
  }
  override async getUtxos(address: string | Credential) {
    const outputs = await this.addressUtxos(address);
    if (typeof address === "string") this.currentOutputs.set(address, outputs);
    return outputs;
  }
  override getUtxosWithUnit(address: string | Credential, unit: string) { return this.addressUtxos(address, unit); }
  override async getUtxoByUnit(unit: string) {
    const addresses = await this.json<{ address: string }[]>(`/assets/${unit}/addresses?count=2`);
    assert.equal(addresses.length, 1, "Expected exactly one address holding the NFT.");
    const outputs = await this.getUtxosWithUnit(addresses[0]!.address, unit);
    assert.equal(outputs.length, 1, "Expected exactly one NFT output.");
    return outputs[0]!;
  }
  // History discovers addresses only. Every spendability check reads current outputs.
  async currentUtxosByOutRef(refs: OutRef[], knownAddresses: string[] = []): Promise<UTxO[]> {
    if (!refs.length) return [];
    const unknown = new Set(refs.filter((ref) => !this.knownAddresses.has(key(ref))).map((ref) => ref.txHash));
    await Promise.all([...unknown].map(async (hash) => {
      let pending = this.discoveries.get(hash);
      if (!pending) {
        pending = (async () => {
          const response = await this.json<{ outputs: BlockfrostOutput[] }>(`/txs/${hash}/utxos`, { outputs: [] });
          for (const output of response.outputs) this.knownAddresses.set(key({ txHash: hash, outputIndex: output.output_index }), output.address);
        })();
        this.discoveries.set(hash, pending);
        pending.finally(() => this.discoveries.delete(hash)).catch(() => {});
      }
      await pending;
    }));
    const addresses = new Set([...knownAddresses, ...refs.flatMap((ref) => this.knownAddresses.get(key(ref)) ?? [])]);
    const current = (await Promise.all([...addresses].map((address) => this.getUtxos(address)))).flat();
    const wanted = new Set(refs.map(key));
    return current.filter((output) => wanted.has(key(output)));
  }
  override getUtxosByOutRef(refs: OutRef[]) { return this.currentUtxosByOutRef(refs); }
  override async getRewardAccount(rewardAddress: string): Promise<RewardAccountState> {
    const account = await this.json<{ registered: boolean; pool_id: string | null; withdrawable_amount: string } | null>(`/accounts/${rewardAddress}`, null);
    if (!account) return { registered: false, poolId: null, rewards: 0n };
    assert(typeof account.registered === "boolean" && typeof account.withdrawable_amount === "string", "Blockfrost returned an incomplete reward account state.");
    return { registered: account.registered, poolId: account.pool_id, rewards: BigInt(account.withdrawable_amount) };
  }
  async observe(hash: string, options: TransactionStatusOptions = {}): Promise<TransactionObservation> {
    const response = await this.request(`/txs/${hash}`, options);
    if (response.status === 404) {
      const pending = await this.request(`/mempool/txs/${hash}`, options);
      if (pending.status === 404) return { status: "not_found", txHash: hash };
      assert(pending.ok, `Could not check mempool status (HTTP ${pending.status}).`);
      return { status: "pending", txHash: hash };
    }
    assert(response.ok, `Could not fetch transaction status (HTTP ${response.status}).`);
    const result = await response.json() as { block: string; block_height: number; slot: number; valid_contract: boolean };
    assert(typeof result.valid_contract === "boolean", "Missing confirmed transaction validity.");
    return { status: "confirmed", txHash: hash, valid: result.valid_contract,
      confirmation: { txHash: hash, blockHash: result.block, blockHeight: result.block_height, slot: result.slot } };
  }
  override getTransactionStatus(hash: string, options: TransactionStatusOptions = {}) { return this.observe(hash, options); }
  override async submitTx(cbor: string) {
    const response = await this.request("/tx/submit", { method: "POST", headers: { "content-type": "application/cbor" }, body: new Uint8Array(fromHex(cbor)) });
    assert(response.ok, `Could not submit transaction (HTTP ${response.status}).`);
    const hash: unknown = await response.json();
    assert(typeof hash === "string" && /^[0-9a-f]{64}$/.test(hash), "Ambiguous transaction submission response.");
    return hash;
  }
  override async getDatum(hash: string) { return (await this.json<{ cbor: string }>(`/scripts/datum/${hash}/cbor`)).cbor; }
  override async getTreasury() { return BigInt((await this.json<{ supply: { treasury: string } }>("/network")).supply.treasury); }
}
