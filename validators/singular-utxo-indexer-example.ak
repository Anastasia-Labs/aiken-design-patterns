use aiken/dict
use aiken/fuzz
use aiken/interval
use aiken/transaction.{
  Input, NoDatum, Output, OutputReference, ScriptContext, Spend, Transaction,
  TransactionId,
}
use aiken/transaction/credential.{Address, ScriptCredential}
use aiken/transaction/value
use aiken_design_patterns/singular_utxo_indexer as singular_utxo_indexer
use aiken_design_patterns/utils.{authentic_input_is_reproduced_unchanged}

validator(state_token_symbol: value.PolicyId) {
  fn spend(_datum, redeemer: (Int, Int), ctx: ScriptContext) {
    singular_utxo_indexer.spend(
      fn(in_utxo, out_utxo) {
        authentic_input_is_reproduced_unchanged(
          state_token_symbol,
          None,
          in_utxo,
          out_utxo,
        )
      },
      redeemer,
      ctx,
    )
  }
}

// Test case for the spend validator function
test spend_validator() {
  let own_ref =
    OutputReference {
      transaction_id: TransactionId {
        hash: #"ee220ba9258ef159bb44f0d3522b840a80475eac2df7176f2c513d59a2ead71f",
      },
      output_index: 0,
    }
  let script_purpose = Spend(own_ref)
  let state_token_symbol =
    #"99999999999999999999999999999999999999999999999999999999"
  let token_name = #"02"
  let own_val_hash = #"88888888888888888888888888888888888888888888888888888888"
  let input_utxo =
    Input {
      output_reference: own_ref,
      output: Output {
        address: Address {
          payment_credential: ScriptCredential(own_val_hash),
          stake_credential: None,
        },
        value: value.add(
          value.from_lovelace(2_000_000),
          state_token_symbol,
          token_name,
          1,
        ),
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
      value: value.add(
        value.from_lovelace(2_000_000),
        state_token_symbol,
        token_name,
        1,
      ),
      datum: NoDatum,
      reference_script: None,
    }
  let redeemer = (0, 0)
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
  spend(state_token_symbol, arbitrary_datum, redeemer, ctx)
}

// Definition of a custom data type for spend input
type SpendInput {
  state_token_symbol: ByteArray,
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
    fn(state_token_symbol, tx_id, val_hash, token_name) {
      SpendInput(state_token_symbol, tx_id, val_hash, token_name)
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
        value: value.add(
          value.from_lovelace(2_000_000),
          r.state_token_symbol,
          r.token_name,
          1,
        ),
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
      value: value.add(
        value.from_lovelace(2_000_000),
        r.state_token_symbol,
        r.token_name,
        1,
      ),
      datum: NoDatum,
      reference_script: None,
    }
  let redeemer = (0, 0)
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
  spend(r.state_token_symbol, arbitrary_datum, redeemer, ctx)
}
