use aiken/collection/dict
use aiken/fuzz
use aiken/interval
use aiken_design_patterns/singular_utxo_indexer_one_to_many as singular_utxo_indexer
use cardano/address.{Address}
use cardano/assets
use cardano/transaction.{
  Input, NoDatum, Output, OutputReference, Spend, Transaction,
}

validator example(
  _state_token_symbol: assets.PolicyId,
  _state_token_name: assets.AssetName,
) {
  spend(
    _datum,
    redeemer: Pair<Int, List<Int>>,
    _own_ref: OutputReference,
    tx: Transaction,
  ) {
    singular_utxo_indexer.spend(
      fn(_input) { True },
      fn(_in_utxo, _out_utxo) { True },
      fn(_output_value, _output_count) { True },
      redeemer,
      tx,
    )
  }

  else(_) {
    fail
  }
}

// Test case for the spend validator
test spend_validator() {
  let own_ref =
    OutputReference {
      transaction_id: #"ee220ba9258ef159bb44f0d3522b840a80475eac2df7176f2c513d59a2ead71f",
      output_index: 0,
    }
  let script_purpose = Spend(own_ref)
  let own_val_hash = #"88888888888888888888888888888888888888888888888888888888"
  let input_utxo =
    Input {
      output_reference: own_ref,
      output: Output {
        address: Address {
          payment_credential: Script(own_val_hash),
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
        payment_credential: Script(own_val_hash),
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
      withdrawals: dict.new(),
      validity_range: interval.everything(),
      extra_signatories: [],
      redeemers: dict.new(),
      datums: dict.new(),
      id: #"0000000000000000000000000000000000000000000000000000000000000000",
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
      transaction_id: r.tx_id,
      output_index: 0,
    }
  let script_purpose = Spend(own_ref)
  let input_utxo =
    Input {
      output_reference: own_ref,
      output: Output {
        address: Address {
          payment_credential: Script(r.val_hash),
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
        payment_credential: Script(r.val_hash),
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
      withdrawals: dict.new(),
      validity_range: interval.everything(),
      extra_signatories: [],
      redeemers: dict.new(),
      datums: dict.new(),
      id: #"0000000000000000000000000000000000000000000000000000000000000000",
    }
  let ctx = ScriptContext { purpose: script_purpose, transaction: tx }
  spend(r.policy_id, r.token_name, arbitrary_datum, redeemer, ctx)
}
