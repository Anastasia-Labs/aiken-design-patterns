use aiken/dict
use aiken/fuzz
use aiken/interval
use aiken/transaction.{
  Input, NoDatum, Output, OutputReference, ScriptContext, Spend, Transaction,
  TransactionId,
}
use aiken/transaction/credential.{Address, ScriptCredential}
use aiken/transaction/value
use aiken_design_patterns/singular_utxo_indexer_one_to_many as singular_utxo_indexer

validator(
  _state_token_symbol: value.PolicyId,
  _state_token_name: value.AssetName,
) {
  fn spend(_datum, redeemer: (Int, List<Int>), ctx: ScriptContext) {
    singular_utxo_indexer.spend(
      fn(_input) { True },
      fn(_in_utxo, _out_utxo) { True },
      fn(_out_utxos, _output_count) { True },
      redeemer,
      ctx,
    )
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
  let script_purpose = Spend(own_ref)
  let own_val_hash = #"88888888888888888888888888888888888888888888888888888888"
  let input_utxo =
    Input {
      output_reference: own_ref,
      output: Output {
        address: Address {
          payment_credential: ScriptCredential(own_val_hash),
          stake_credential: None,
        },
        value: value.from_lovelace(2_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    }
  let output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(own_val_hash),
        stake_credential: None,
      },
      value: value.from_lovelace(2_000_000),
      datum: NoDatum,
      reference_script: None,
    }
  let redeemer = (0, [0])
  let arbitrary_datum = 0
  let tx =
    Transaction {
      inputs: [input_utxo],
      reference_inputs: [],
      outputs: [output],
      fee: value.zero(),
      mint: value.zero() |> value.to_minted_value(),
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
  let policy_id = #"99999999999999999999999999999999999999999999999999999999"
  let asset_name = #"99999999999999999999999999999999999999999999999999999999"
  spend(policy_id, asset_name, arbitrary_datum, redeemer, ctx)
}

// Definition of a custom data type for spend input
type SpendInput {
  policy_id: ByteArray,
  tx_id: ByteArray,
  val_hash: ByteArray,
  token_name: ByteArray,
}

// Function to generate random spend input
fn random_spend_input() -> Fuzzer<SpendInput> {
  fuzz.map4(
    fuzz.bytearray_between(56, 56),
    fuzz.bytearray_between(64, 64),
    fuzz.bytearray_between(56, 56),
    fuzz.bytearray_between(0, 32),
    fn(policy_id, tx_id, val_hash, token_name) {
      SpendInput(policy_id, tx_id, val_hash, token_name)
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
  let script_purpose = Spend(own_ref)
  let input_utxo =
    Input {
      output_reference: own_ref,
      output: Output {
        address: Address {
          payment_credential: ScriptCredential(r.val_hash),
          stake_credential: None,
        },
        value: value.from_lovelace(2_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    }
  let output =
    Output {
      address: Address {
        payment_credential: ScriptCredential(r.val_hash),
        stake_credential: None,
      },
      value: value.from_lovelace(2_000_000),
      datum: NoDatum,
      reference_script: None,
    }
  let redeemer = (0, [0])
  let arbitrary_datum = 0
  let tx =
    Transaction {
      inputs: [input_utxo],
      reference_inputs: [],
      outputs: [output],
      fee: value.zero(),
      mint: value.zero() |> value.to_minted_value(),
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
  spend(r.policy_id, r.token_name, arbitrary_datum, redeemer, ctx)
}
