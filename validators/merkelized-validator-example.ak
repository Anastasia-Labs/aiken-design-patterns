use aiken/builtin
use aiken/collection/dict
use aiken/crypto.{ScriptHash}
use aiken/fuzz
use aiken/interval
use aiken_design_patterns/merkelized_validator.{WithdrawRedeemer} as merkelized_validator
use aiken_design_patterns/utils.{sum_of_squares}
use cardano/address.{Inline, Script}
use cardano/assets
use cardano/transaction.{Redeemer, ScriptPurpose, Transaction, Withdraw}

// Definition of a custom validator for spending transactions
validator spending_example(stake_validator: ScriptHash) {
  spend(x: Int, y: Int, _own_ref: OutputReference, tx: Transaction) {
    expect [sum] =
      [x, y]
        |> merkelized_validator.delegated_compute(
            stake_validator,
            builtin.un_i_data,
            builtin.un_i_data,
            tx.redeemers,
          )
    sum < 42
  }

  else(_) {
    fail
  }
}

// Definition of a custom validator for withdrawal transactions
validator logic_example {
  withdraw(redeemer: WithdrawRedeemer<Int, Int>, ctx: ScriptContext) {
    merkelized_validator.withdraw(sum_of_squares, redeemer, ctx)
  }

  else(_) {
    fail
  }
}
