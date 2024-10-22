use aiken/dict
use aiken/fuzz
use aiken/hash.{Blake2b_224, Hash}
use aiken/interval
use aiken/transaction.{ScriptContext, Transaction, TransactionId, WithdrawFrom}
use aiken/transaction/credential.{Inline, Script, ScriptCredential}
use aiken/transaction/value
use aiken_design_patterns/merkelized_validator.{WithdrawRedeemer} as merkelized_validator
use aiken_design_patterns/utils.{sum_of_squares}

// Definition of a custom validator for spending transactions
validator(stake_validator: Hash<Blake2b_224, Script>) {
  fn spend(x: Int, y: Int, ctx: ScriptContext) {
    let ScriptContext { transaction: tx, .. } = ctx
    let xData: Data = x
    let yData: Data = y
    expect [sumData] =
      merkelized_validator.spend(stake_validator, [xData, yData], tx.redeemers)
    expect sum: Int = sumData
    sum < 42
  }
}

// Definition of a custom validator for withdrawal transactions
validator {
  fn withdraw(redeemer: WithdrawRedeemer<Int, Int>, ctx: ScriptContext) {
    merkelized_validator.withdraw(sum_of_squares, redeemer, ctx)
  }
}

// Test case for the spend validator function
test spend_validator() {
  let stake_validator: Hash<Blake2b_224, Script> =
    #"99999999999999999999999999999999999999999999999999999999"
  let redeemer: Data = WithdrawRedeemer { input_args: [2, 4], results: [20] }
  let redeemers =
    [Pair(WithdrawFrom(Inline(ScriptCredential(stake_validator))), redeemer)]
  let tx =
    Transaction {
      inputs: [],
      reference_inputs: [],
      outputs: [],
      fee: value.zero(),
      mint: value.zero() |> value.to_minted_value(),
      certificates: [],
      withdrawals: [],
      validity_range: interval.everything(),
      extra_signatories: [],
      redeemers,
      datums: dict.new(),
      id: TransactionId {
        hash: #"0000000000000000000000000000000000000000000000000000000000000000",
      },
    }
  let ctx =
    ScriptContext {
      purpose: WithdrawFrom(
        Inline(
          ScriptCredential(
            #"99999999999999999999999999999999999999999999999999999999",
          ),
        ),
      ),
      transaction: tx,
    }
  spend(stake_validator, 2, 4, ctx)
}

// Test case for the withdraw validator function
test withdraw_validator() {
  let redeemer: WithdrawRedeemer<Int, Int> =
    WithdrawRedeemer { input_args: [1, 2, 3, 4], results: [30] }
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

// Definition of a custom data type for withdrawal input
type WithdrawInput {
  xs: List<Int>,
  bs: ByteArray,
}

// Function to generate random withdrawal input
fn random_withdraw_input() -> Fuzzer<WithdrawInput> {
  fuzz.map2(
    fuzz.list(fuzz.int()),
    fuzz.bytearray_between(56, 56),
    fn(xs, bs) { WithdrawInput { xs, bs } },
  )
}

// Property test to verify withdraw validator
test prop_withdraw_validator(r via random_withdraw_input()) {
  let expected_sum_of_squares = utils.sum_of_squares(r.xs)
  let redeemer: WithdrawRedeemer<Int, Int> =
    WithdrawRedeemer { input_args: r.xs, results: expected_sum_of_squares }
  let ctx =
    ScriptContext {
      purpose: WithdrawFrom(Inline(ScriptCredential(r.bs))),
      transaction: transaction.placeholder(),
    }
  withdraw(redeemer, ctx)
}

// Definition of a custom data type for spend input
type SpendInput {
  x: Int,
  y: Int,
  bs: ByteArray,
}

// Function to generate random spend input
fn random_spend_input() -> Fuzzer<SpendInput> {
  fuzz.map3(
    fuzz.int_between(-4, 4),
    fuzz.int_between(-4, 4),
    fuzz.bytearray_between(56, 56),
    fn(x, y, bs) { SpendInput { x, y, bs } },
  )
}

// Property test to verify the spend validator
test prop_spend_validator(r via random_spend_input()) {
  let xs =
    [r.x, r.y]
  let expected_sum_of_squares = utils.sum_of_squares(xs)
  let stake_validator: Hash<Blake2b_224, Script> = r.bs
  let redeemer: Data =
    WithdrawRedeemer { input_args: xs, results: expected_sum_of_squares }
  let redeemers =
    [Pair(WithdrawFrom(Inline(ScriptCredential(stake_validator))), redeemer)]
  let tx =
    Transaction {
      inputs: [],
      reference_inputs: [],
      outputs: [],
      fee: value.zero(),
      mint: value.zero() |> value.to_minted_value(),
      certificates: [],
      withdrawals: [],
      validity_range: interval.everything(),
      extra_signatories: [],
      redeemers,
      datums: dict.new(),
      id: TransactionId {
        hash: #"0000000000000000000000000000000000000000000000000000000000000000",
      },
    }
  let ctx =
    ScriptContext {
      purpose: WithdrawFrom(Inline(ScriptCredential(r.bs))),
      transaction: tx,
    }
  spend(stake_validator, r.x, r.y, ctx)
}
