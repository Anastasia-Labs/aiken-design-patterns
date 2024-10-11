use aiken/collection/dict
use aiken/crypto.{ScriptHash}
use aiken/fuzz
use aiken/interval
use aiken_design_patterns/stake_validator as stake_validator
use cardano/address.{Address, Credential, Inline, Script}
use cardano/assets
use cardano/transaction.{
  Input, NoDatum, Output, OutputReference, Redeemer, Spend, Transaction,
  TransactionId, Withdraw,
}

validator example {
  spend(_datum, _redeemer, own_out_ref: OutputReference, tx: Transaction) {
    stake_validator.spend(own_out_ref, tx)
  }

  withdraw(redeemer: Redeemer, own_credential: Credential, tx: Transaction) {
    stake_validator.withdraw(
      fn(_r, _own_validator, _tx) { True },
      redeemer,
      own_credential,
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
      transaction_id: TransactionId {
        hash: #"ee220ba9258ef159bb44f0d3522b840a80475eac2df7176f2c513d59a2ead71f",
      },
      output_index: 0,
    }
  let script_purpose = Spend(own_ref)
  let own_val_hash: ScriptHash =
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
    dict.new()
      |> dict.insert(Inline(ScriptCredential(own_val_hash)), 1, fn(_, _) { Less })
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
      redeemers: dict.new(),
      datums: dict.new(),
      id: TransactionId {
        hash: #"0000000000000000000000000000000000000000000000000000000000000000",
      },
    }
  let ctx = ScriptContext { purpose: script_purpose, transaction: tx }
  spend(0, 0, ctx)
}

// Definition of a custom data type for spend input
type SpendInput {
  tx_id: ByteArray,
  val_hash: ByteArray,
  withdraw_amount: Int,
}

// Function to generate random spend input
fn random_spend_input() -> Fuzzer<SpendInput> {
  fuzz.map3(
    fuzz.bytearray_between(64, 64),
    fuzz.bytearray_between(56, 56),
    fuzz.int_at_least(1),
    fn(tx_id, val_hash, withdraw_amount) {
      SpendInput(tx_id, val_hash, withdraw_amount)
    },
  )
}

// Property test to verify the spend validator
test prop_spend_validator(r via random_spend_input()) {
  let own_ref =
    OutputReference {
      transaction_id: TransactionId { hash: r.tx_id },
      output_index: 0,
    }
  let script_purpose = Spend(own_ref)
  let own_val_hash: ScriptHash = r.val_hash
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
    dict.new()
      |> dict.insert(
          Inline(ScriptCredential(own_val_hash)),
          r.withdraw_amount,
          fn(_, _) { Less },
        )
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
      redeemers: dict.new(),
      datums: dict.new(),
      id: TransactionId {
        hash: #"0000000000000000000000000000000000000000000000000000000000000000",
      },
    }
  let ctx = ScriptContext { purpose: script_purpose, transaction: tx }
  spend(0, 0, ctx)
}

// Test case for the withdraw validator
test withdraw_validator() {
  let redeemer = 1
  let ctx =
    ScriptContext {
      purpose: WithdrawFrom(
        Inline(
          ScriptCredential(
            #"99999999999999999999999999999999999999999999999999999999",
          ),
        ),
      ),
      transaction: transaction.placeholder(),
    }
  withdraw(redeemer, ctx)
}

// Definition of a custom data type for withdraw input
type WithdrawInput {
  bs: ByteArray,
  redeemer: Int,
}

// Function to generate random withdraw input
fn random_withdraw_input() -> Fuzzer<WithdrawInput> {
  fuzz.map2(
    fuzz.bytearray_between(56, 56),
    fuzz.int(),
    fn(bs, r) { WithdrawInput(bs, r) },
  )
}

// Property test to verify the withdraw validator
test prop_withdraw_validator(r via random_withdraw_input()) {
  let ctx =
    ScriptContext {
      purpose: WithdrawFrom(Inline(ScriptCredential(r.bs))),
      transaction: transaction.placeholder(),
    }
  withdraw(r.redeemer, ctx)
}
