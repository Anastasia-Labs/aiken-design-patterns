use aiken/hash.{Blake2b_224, Hash}
use aiken/transaction.{Redeemer, ScriptContext, Transaction}
use aiken/transaction/credential.{Script}
use aiken_design_patterns/merkelized_validator.{WithdrawRedeemer} as merkelized_validator
use aiken_design_patterns/stake_validator as stake_validator
use aiken_design_patterns/utils.{sum_of_squares}

validator(stake_validator: Hash<Blake2b_224, Script>) {
  fn spend(x: Int, redeemer: (Int, Int), ctx: ScriptContext) {
    let ScriptContext { transaction: tx, .. } = ctx
    let (y, sum) = redeemer
    let xData: Data = x
    let yData: Data = y
    let sumData: Data = sum
    merkelized_validator.spend(
      stake_validator,
      [xData, yData],
      [sumData],
      tx.redeemers,
    )
  }
}

validator {
  fn withdraw(redeemer: Redeemer, ctx: ScriptContext) {
    stake_validator.withdraw(
      fn(r, _own_validator, _tx) {
        expect WithdrawRedeemer { input_args, results }: WithdrawRedeemer<Int> =
          r
        let computation_results = sum_of_squares(input_args)
        computation_results == results
      },
      redeemer,
      ctx,
    )
  }
}
