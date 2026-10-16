import {
  CML,
  coreToUtxo,
  fromHex,
  toHex,
  type Credential,
  type EvalRedeemer,
  type OutRef,
  type ProtocolParameters,
  type Provider,
  type RedeemerTag,
  type UTxO,
} from "@lucid-evolution/lucid";
import { Asset, Emulator, Utxo, Value, type UtxoFilter } from "scalus";

const REDEEMER_TAGS = {
  Spend: "spend",
  Mint: "mint",
  Cert: "publish",
  Reward: "withdraw",
  Voting: "vote",
  Proposing: "propose",
} as const satisfies Record<string, RedeemerTag>;

export function toLucidUtxo(utxo: Utxo): UTxO {
  const core = CML.TransactionUnspentOutput.from_cbor_bytes(utxo.toCbor());
  try {
    return coreToUtxo(core);
  } finally {
    core.free();
  }
}

export function toScalusUtxo(utxo: UTxO): Utxo {
  if (utxo.datumHash && utxo.datum) {
    throw new Error("Cannot distinguish an inline datum from a resolved hash datum.");
  }
  const assets = Object.entries(utxo.assets)
    .filter(([unit]) => unit !== "lovelace")
    .map(([unit, quantity]) => new Asset(unit.slice(0, 56), unit.slice(56), quantity));
  let output = new Utxo(utxo.txHash, utxo.outputIndex, utxo.address, new Value(utxo.assets.lovelace ?? 0n, assets));
  if (utxo.datumHash) output = output.withDatumHash(utxo.datumHash);
  if (utxo.datum) output = output.withInlineDatum(fromHex(utxo.datum));
  if (utxo.scriptRef) output = output.withScriptRef(utxo.scriptRef);
  return output;
}

export class ScalusProvider implements Provider {
  readonly emulator: Emulator;

  constructor(emulator: Emulator) {
    this.emulator = emulator;
  }

  async getProtocolParameters(): Promise<ProtocolParameters> {
    const p = this.emulator.getProtocolParameters();
    return {
      protocolMajorVersion: p.protocolMajorVersion,
      minFeeA: p.txFeePerByte,
      minFeeB: p.txFeeFixed,
      maxTxSize: p.maxTxSize,
      maxValSize: p.maxValueSize,
      keyDeposit: p.stakeAddressDeposit,
      poolDeposit: p.stakePoolDeposit,
      drepDeposit: p.dRepDeposit,
      govActionDeposit: p.govActionDeposit,
      priceMem: p.priceMemory,
      priceStep: p.priceSteps,
      maxTxExMem: p.maxTxExecutionMemory,
      maxTxExSteps: p.maxTxExecutionSteps,
      coinsPerUtxoByte: p.utxoCostPerByte,
      collateralPercentage: p.collateralPercentage,
      maxCollateralInputs: p.maxCollateralInputs,
      minFeeRefScriptCostPerByte: p.minFeeRefScriptCostPerByte,
      costModels: p.costModels,
    };
  }

  private addressFilter(addressOrCredential: string | Credential): UtxoFilter {
    return typeof addressOrCredential === "string"
      ? { address: addressOrCredential }
      : {
          paymentCredential: addressOrCredential.hash,
          paymentCredentialType: addressOrCredential.type === "Key" ? "key" : "script",
        };
  }

  async getUtxos(addressOrCredential: string | Credential): Promise<UTxO[]> {
    return this.emulator.getUtxos(this.addressFilter(addressOrCredential)).map(toLucidUtxo);
  }

  async getUtxosWithUnit(addressOrCredential: string | Credential, unit: string): Promise<UTxO[]> {
    return this.emulator
      .getUtxos({ ...this.addressFilter(addressOrCredential), unit })
      .map(toLucidUtxo);
  }

  async getUtxoByUnit(unit: string): Promise<UTxO> {
    const found = this.emulator.getUtxos({ unit, limit: 2 });
    if (found.length !== 1 || !found[0]) {
      throw new Error(`Expected one UTxO holding ${unit}, found ${found.length}.`);
    }
    return toLucidUtxo(found[0]);
  }

  async getUtxosByOutRef(outRefs: OutRef[]): Promise<UTxO[]> {
    return this.emulator.getUtxos({ outRefs }).map(toLucidUtxo);
  }

  async getDelegation(rewardAddress: string) {
    const delegation = this.emulator.getDelegation(rewardAddress);
    return { poolId: delegation.poolId ?? null, rewards: delegation.rewards };
  }

  async getRewardAccount(rewardAddress: string) {
    const delegation = await this.getDelegation(rewardAddress);
    return {
      registered: this.emulator.getStakeReward(rewardAddress) !== undefined,
      ...delegation,
    };
  }

  async getDatum(datumHash: string): Promise<string> {
    const datum = this.emulator.getDatum(datumHash);
    if (datum === undefined) throw new Error(`Missing datum ${datumHash}.`);
    return toHex(datum);
  }

  async awaitTx(txHash: string): Promise<boolean> {
    return this.emulator.hasTx(txHash);
  }

  async submitTx(tx: string): Promise<string> {
    const result = this.emulator.submitTx(fromHex(tx));
    if (!result.isSuccess || !result.txHash) {
      throw new Error(`${result.errorRule}: ${result.error}\n${result.logs.join("\n")}`);
    }
    return result.txHash;
  }

  async evaluateTx(tx: string, additionalUTxOs: UTxO[] = []): Promise<EvalRedeemer[]> {
    return this.emulator.evaluateTx(fromHex(tx), additionalUTxOs.map(toScalusUtxo)).map((r) => ({
      redeemer_tag: REDEEMER_TAGS[r.tag],
      redeemer_index: r.index,
      ex_units: { mem: Number(r.budget.memory), steps: Number(r.budget.steps) },
    }));
  }
}
