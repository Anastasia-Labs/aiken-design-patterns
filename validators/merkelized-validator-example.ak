use aiken/hash.{Blake2b_224, Hash}
use aiken/transaction.{ScriptContext, Transaction}
use aiken/transaction/credential.{Script}
use aiken_design_patterns/merkelized_validator.{WithdrawRedeemer} as merkelized_validator
use aiken_design_patterns/utils.{sum_of_squares}

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

validator {
  fn withdraw(redeemer: WithdrawRedeemer<Int, Int>, ctx: ScriptContext) {
    merkelized_validator.withdraw(sum_of_squares, redeemer, ctx)
  }
}
