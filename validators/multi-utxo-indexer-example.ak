use aiken/dict
use aiken/fuzz
use aiken/hash.{Blake2b_224, Hash}
use aiken/interval
use aiken/list
use aiken/transaction.{
  Input, NoDatum, Output, OutputReference, ScriptContext, Spend, Transaction,
  TransactionId, WithdrawFrom,
}
use aiken/transaction/credential.{Address, Inline, Script, ScriptCredential}
use aiken/transaction/value
use aiken_design_patterns/multi_utxo_indexer as multi_utxo_indexer
use aiken_design_patterns/stake_validator as stake_validator
use aiken_design_patterns/utils.{authentic_input_is_reproduced_unchanged}

validator(
  state_token_symbol: value.PolicyId,
  state_token_name: value.AssetName,
) {
  fn spend(_datum, _redeemer, ctx: ScriptContext) {
    stake_validator.spend(ctx)
  }

  fn withdraw(redeemer: List<(Int, Int)>, ctx: ScriptContext) {
    multi_utxo_indexer.withdraw(
      fn(in_utxo, out_utxo) {
        authentic_input_is_reproduced_unchanged(
          state_token_symbol,
          Some(state_token_name),
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
  let own_val_hash: Hash<Blake2b_224, Script> =
    #"99999999999999999999999999999999999999999999999999999999"
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
  let withdrawals =
    [Pair(Inline(ScriptCredential(own_val_hash)), 1)]
  let tx =
    Transaction {
      inputs: [input_utxo],
      reference_inputs: [],
      outputs: [],
      fee: value.zero(),
      mint: value.zero() |> value.to_minted_value(),
      certificates: [],
      withdrawals,
      validity_range: interval.everything(),
      extra_signatories: [],
      redeemers: [],
      datums: dict.new(),
      id: TransactionId {
        hash: #"0000000000000000000000000000000000000000000000000000000000000000",
      },
    }
  let ctx = ScriptContext { purpose: script_purpose, transaction: tx }
  spend(#"", #"", 0, 0, ctx)
}

// Definition of a custom data type for spend input
type SpendInput {
  tx_id: ByteArray,
  val_hash: ByteArray,
  withdraw_amount: Int,
  policy_id: ByteArray,
  token_name: ByteArray,
}

// Function to generate random spend input
fn random_spend_input() -> Fuzzer<SpendInput> {
  fuzz.map5(
    fuzz.bytearray_between(64, 64),
    fuzz.bytearray_between(56, 56),
    fuzz.int_at_least(1),
    fuzz.bytearray_between(56, 56),
    fuzz.bytearray_between(0, 32),
    fn(tx_id, val_hash, withdraw_amount, policy_id, token_name) {
      SpendInput(tx_id, val_hash, withdraw_amount, policy_id, token_name)
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
  let own_val_hash: Hash<Blake2b_224, Script> = r.val_hash
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
  let withdrawals =
    [Pair(Inline(ScriptCredential(own_val_hash)), r.withdraw_amount)]
  let tx =
    Transaction {
      inputs: [input_utxo],
      reference_inputs: [],
      outputs: [],
      fee: value.zero(),
      mint: value.zero() |> value.to_minted_value(),
      certificates: [],
      withdrawals,
      validity_range: interval.everything(),
      extra_signatories: [],
      redeemers: [],
      datums: dict.new(),
      id: TransactionId {
        hash: #"0000000000000000000000000000000000000000000000000000000000000000",
      },
    }
  let ctx = ScriptContext { purpose: script_purpose, transaction: tx }
  let arbitrary_datum = #""
  let arbitrary_redeemer = #""
  spend(r.policy_id, r.token_name, arbitrary_datum, arbitrary_redeemer, ctx)
}

// Test case for the withdraw validator
test withdraw_validator() {
  let own_ref =
    OutputReference {
      transaction_id: TransactionId {
        hash: #"ee220ba9258ef159bb44f0d3522b840a80475eac2df7176f2c513d59a2ead71f",
      },
      output_index: 0,
    }
  let own_val_hash = #"99999999999999999999999999999999999999999999999999999999"
  let script_purpose = WithdrawFrom(Inline(ScriptCredential(own_val_hash)))
  let state_token_symbol =
    #"88888888888888888888888888888888888888888888888888888888"
  let token_name = #"02"
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
  let redeemer =
    [(0, 0)]
  let withdrawals =
    [Pair(Inline(ScriptCredential(own_val_hash)), 1)]
  let tx =
    Transaction {
      inputs: [input_utxo],
      reference_inputs: [],
      outputs: [output],
      fee: value.zero(),
      mint: value.zero() |> value.to_minted_value(),
      certificates: [],
      withdrawals,
      validity_range: interval.everything(),
      extra_signatories: [],
      redeemers: [],
      datums: dict.new(),
      id: TransactionId {
        hash: #"0000000000000000000000000000000000000000000000000000000000000000",
      },
    }
  let ctx = ScriptContext { purpose: script_purpose, transaction: tx }
  withdraw(state_token_symbol, token_name, redeemer, ctx)
}

// Definition of a custom data type for withdraw input
type WithdrawInput {
  state_token_symbol: ByteArray,
  tx_id: ByteArray,
  val_hash: ByteArray,
  token_name: ByteArray,
  inputs: List<Input>,
  outputs: List<Output>,
  redeemer: List<(Int, Int)>,
}

// Function to generate random withdraw input
fn random_withdraw_input() -> Fuzzer<WithdrawInput> {
  fuzz.map5(
    fuzz.bytearray_between(56, 56),
    fuzz.bytearray_between(64, 64),
    fuzz.bytearray_between(56, 56),
    fuzz.bytearray_between(0, 32),
    fuzz.int_between(1, 10),
    fn(state_token_symbol, tx_id, val_hash, token_name, num_pairs) {
      let inputs: List<Input> =
        list.map(
          list.range(1, num_pairs),
          fn(i) {
            Input(
              OutputReference(TransactionId(tx_id), i),
              Output(
                Address(ScriptCredential(val_hash), None),
                value.add(
                  value.from_lovelace(i * 2_000_000),
                  state_token_symbol,
                  token_name,
                  1,
                ),
                NoDatum,
                None,
              ),
            )
          },
        )
      let outputs: List<Output> =
        list.map(
          list.range(1, num_pairs),
          fn(i) {
            Output(
              Address(ScriptCredential(val_hash), None),
              value.add(
                value.from_lovelace(i * 2_000_000),
                state_token_symbol,
                token_name,
                1,
              ),
              NoDatum,
              None,
            )
          },
        )
      let redeemer: List<(Int, Int)> =
        list.map(list.range(1, num_pairs), fn(i) { (i - 1, i - 1) })
      WithdrawInput(
        state_token_symbol,
        tx_id,
        val_hash,
        token_name,
        inputs,
        outputs,
        redeemer,
      )
    },
  )
}

// Property test to verify the withdraw validator
test prop_withdraw_validator(r via random_withdraw_input()) {
  let script_purpose = WithdrawFrom(Inline(ScriptCredential(r.val_hash)))
  let withdrawals =
    [Pair(Inline(ScriptCredential(r.val_hash)), 1)]
  let tx =
    Transaction {
      inputs: r.inputs,
      reference_inputs: [],
      outputs: r.outputs,
      fee: value.zero(),
      mint: value.zero() |> value.to_minted_value(),
      certificates: [],
      withdrawals,
      validity_range: interval.everything(),
      extra_signatories: [],
      redeemers: [],
      datums: dict.new(),
      id: TransactionId {
        hash: #"0000000000000000000000000000000000000000000000000000000000000000",
      },
    }
  let ctx = ScriptContext { purpose: script_purpose, transaction: tx }
  withdraw(r.state_token_symbol, r.token_name, r.redeemer, ctx)
}
