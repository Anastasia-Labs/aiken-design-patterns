import assert from "node:assert/strict";
import {
  CML, Data, TxOutRefData, coreToOutRef, toScriptRef,
  type OutRef, type ProtocolParameters, type Script, type TxSignBuilder, type UTxO,
} from "@lucid-evolution/lucid";

export type Budget = { memory: bigint; steps: bigint };

export function outRef({ txHash, outputIndex }: OutRef): OutRef {
  return { txHash, outputIndex };
}

export function outRefData({ txHash, outputIndex }: OutRef): Data {
  return Data.from(Data.to({ txOutRefId: txHash, txOutRefIdx: BigInt(outputIndex) }, TxOutRefData));
}

export function inputReferences(inputs: CML.TransactionInputList | undefined): OutRef[] {
  if (!inputs) return [];
  try {
    return Array.from({ length: inputs.len() }, (_, index) => {
      const input = inputs.get(index);
      try { return coreToOutRef(input); }
      finally { input.free(); }
    });
  } finally {
    inputs.free();
  }
}

export function minimumCollateral(fee: bigint, percentage: number): bigint {
  return (fee * BigInt(percentage) + 99n) / 100n;
}

export function minimumFee(transaction: CML.Transaction, parameters: ProtocolParameters, referenceScripts: Script[]): bigint {
  const linear = CML.LinearFee.new(BigInt(parameters.minFeeA), BigInt(parameters.minFeeB), BigInt(parameters.minFeeRefScriptCostPerByte));
  const memory = CML.SubCoin.new(BigInt(Math.round(parameters.priceMem * 1e8)), 100_000_000n);
  const steps = CML.SubCoin.new(BigInt(Math.round(parameters.priceStep * 1e8)), 100_000_000n);
  const prices = CML.ExUnitPrices.new(memory, steps);
  try {
    const size = referenceScripts.reduce((total, script) => {
      const reference = toScriptRef(script);
      const plutus = reference.as_plutus_v3();
      assert(plutus, "Expected a Plutus V3 reference script.");
      try {
        return total + BigInt(plutus.to_raw_bytes().length);
      } finally {
        plutus.free();
        reference.free();
      }
    }, 0n);
    return CML.min_fee(transaction, linear, prices, size);
  } finally {
    prices.free();
    memory.free();
    steps.free();
    linear.free();
  }
}

export async function completeWithMinimumCollateral(
  collateralPercentage: number,
  build: (collateral: bigint) => Promise<TxSignBuilder>,
): Promise<TxSignBuilder> {
  let collateral = 0n;
  for (let attempt = 0; attempt < 8; attempt++) {
    const completed = await build(collateral);
    const transaction = CML.Transaction.from_cbor_hex(completed.toCBOR());
    const body = transaction.body();
    try {
      const required = minimumCollateral(body.fee(), collateralPercentage);
      assert(body.total_collateral() !== undefined, "Missing total collateral.");
      if (body.total_collateral() === required) return completed;
      collateral = required;
    } finally {
      body.free();
      transaction.free();
    }
  }
  throw new Error("Collateral and transaction fee did not converge after 8 builds.");
}

// Lucid's balancing uses a conservative fee estimate. Finalize this deliberately
// restricted body before signing so its sole input can pay the exact ledger fee.
// The template supplies the canonical redeemers and their script-data hash.
export function finalizeWithdrawal(
  template: CML.Transaction,
  funding: OutRef,
  fee: bigint,
  collateral: UTxO,
  collateralPercentage: number,
  walletAddress: string,
): CML.Transaction {
  const original = template.body();
  const inputs = CML.TransactionInputList.new();
  const hash = CML.TransactionHash.from_hex(funding.txHash);
  const input = CML.TransactionInput.new(hash, BigInt(funding.outputIndex));
  inputs.add(input);
  const outputs = CML.TransactionOutputList.new();
  const body = CML.TransactionBody.new(inputs, outputs, fee);
  const withdrawals = original.withdrawals();
  const references = original.reference_inputs();
  const collateralInputs = CML.TransactionInputList.new();
  const collateralHash = CML.TransactionHash.from_hex(collateral.txHash);
  const collateralInput = CML.TransactionInput.new(collateralHash, BigInt(collateral.outputIndex));
  collateralInputs.add(collateralInput);
  const scriptDataHash = original.script_data_hash();
  const witnesses = template.witness_set();
  const charge = minimumCollateral(fee, collateralPercentage);
  assert(collateral.assets.lovelace !== undefined && collateral.assets.lovelace > charge);
  const address = CML.Address.from_bech32(walletAddress);
  const value = CML.Value.from_coin(collateral.assets.lovelace - charge);
  const returned = CML.TransactionOutput.new(address, value);
  try {
    assert(withdrawals && collateralInputs && scriptDataHash);
    assert.equal(witnesses.vkeywitnesses(), undefined, "Finalize before adding signatures.");
    body.set_withdrawals(withdrawals);
    if (references) body.set_reference_inputs(references);
    body.set_collateral_inputs(collateralInputs);
    body.set_script_data_hash(scriptDataHash);
    body.set_total_collateral(charge);
    body.set_collateral_return(returned);
    return CML.Transaction.new(body, witnesses, true);
  } finally {
    returned.free();
    value.free();
    address.free();
    witnesses.free();
    scriptDataHash?.free();
    collateralInputs?.free();
    collateralInput.free();
    collateralHash.free();
    references?.free();
    withdrawals?.free();
    body.free();
    outputs.free();
    input.free();
    hash.free();
    inputs.free();
    original.free();
  }
}
