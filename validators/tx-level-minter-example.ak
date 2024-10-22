use aiken/dict
use aiken/fuzz
use aiken/hash.{Blake2b_224, Hash}
use aiken/interval
use aiken/transaction.{
  Input, Mint, NoDatum, Output, OutputReference, Redeemer, ScriptContext, Spend,
  Transaction, TransactionId, placeholder,
}
use aiken/transaction/credential.{Address, Script, ScriptCredential}
use aiken/transaction/value
use aiken_design_patterns/tx_level_minter as tx_level_minter

validator {
  fn spend(_datum, redeemer: Int, ctx: ScriptContext) {
    tx_level_minter.spend("BEACON", redeemer, ctx)
  }

  fn mint(redeemer: Redeemer, ctx: ScriptContext) {
    tx_level_minter.mint(fn(_r, _own_policy, _tx) { True }, redeemer, ctx)
  }
}

// Test case for the spend validator
test spend_validator() {
  let own_ref =
    OutputReference {
      transaction_id: TransactionId {
        hash: #"ee220ba9258ef159bb44f0d3522b840a80475eac2df7176f2c513d59a2ead71f",
      },
      output_index: 0,
    }
  let own_val_hash: Hash<Blake2b_224, Script> =
    #"99999999999999999999999999999999999999999999999999999999"
  let script_purpose = Spend(own_ref)
  let redeemer = 0
  let input_utxo =
    Input {
      output_reference: own_ref,
      output: Output {
        address: Address {
          payment_credential: ScriptCredential(own_val_hash),
          stake_credential: None,
        },
        value: value.zero(),
        datum: NoDatum,
        reference_script: None,
      },
    }

  let minted_value =
    value.from_asset(own_val_hash, "BEACON", 1)
      |> value.to_minted_value()
  let tx =
    Transaction {
      inputs: [input_utxo],
      reference_inputs: [],
      outputs: [],
      fee: value.zero(),
      mint: minted_value,
      certificates: [],
      withdrawals: [],
      validity_range: interval.everything(),
      extra_signatories: [],
      redeemers: [],
      datums: dict.new(),
      id: TransactionId {
        hash: #"0000000000000000000000000000000000000000000000000000000000000000",
      },
    }
  let ctx = ScriptContext { purpose: script_purpose, transaction: tx }
  spend(NoDatum, redeemer, ctx)
}

// Definition of a custom data type for spend input
type SpendInput {
  tx_id: ByteArray,
  val_hash: ByteArray,
  mint_amount: Int,
}

// Function to generate random spend input
fn random_spend_input() -> Fuzzer<SpendInput> {
  fuzz.map3(
    fuzz.bytearray_between(64, 64),
    fuzz.bytearray_between(56, 56),
    fuzz.int_at_least(1),
    fn(tx_id, val_hash, mint_amount) {
      SpendInput(tx_id, val_hash, mint_amount)
    },
  )
}

// Property test to verify the spend validator function
test prop_spend_validator(r via random_spend_input()) {
  let own_ref =
    OutputReference {
      transaction_id: TransactionId { hash: r.tx_id },
      output_index: 0,
    }
  let own_val_hash: Hash<Blake2b_224, Script> = r.val_hash
  let script_purpose = Spend(own_ref)
  let redeemer = 0
  let input_utxo =
    Input {
      output_reference: own_ref,
      output: Output {
        address: Address {
          payment_credential: ScriptCredential(own_val_hash),
          stake_credential: None,
        },
        value: value.zero(),
        datum: NoDatum,
        reference_script: None,
      },
    }

  let minted_value =
    value.from_asset(own_val_hash, "BEACON", r.mint_amount)
      |> value.to_minted_value()
  let tx =
    Transaction {
      inputs: [input_utxo],
      reference_inputs: [],
      outputs: [],
      fee: value.zero(),
      mint: minted_value,
      certificates: [],
      withdrawals: [],
      validity_range: interval.everything(),
      extra_signatories: [],
      redeemers: [],
      datums: dict.new(),
      id: TransactionId {
        hash: #"0000000000000000000000000000000000000000000000000000000000000000",
      },
    }
  let ctx = ScriptContext { purpose: script_purpose, transaction: tx }
  spend(NoDatum, redeemer, ctx)
}

// Test case for the mint validator
test mint_policy() {
  let own_policy: Hash<Blake2b_224, Script> =
    #"99999999999999999999999999999999999999999999999999999999"
  let redeemer = 1
  let ctx =
    ScriptContext { purpose: Mint(own_policy), transaction: placeholder() }
  mint(redeemer, ctx)
}

type MintInput {
  bs: ByteArray,
  redeemer: Int,
}

// Function to generate random mint input
fn random_mint_input() -> Fuzzer<MintInput> {
  fuzz.map2(
    fuzz.bytearray_between(56, 56),
    fuzz.int(),
    fn(bs, r) { MintInput(bs, r) },
  )
}

// Property test to verify the mint validator function
test prop_mint_policy(r via random_mint_input()) {
  let ctx = ScriptContext { purpose: Mint(r.bs), transaction: placeholder() }
  mint(r.redeemer, ctx)
}
