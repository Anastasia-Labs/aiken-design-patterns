use aiken/transaction.{
  ScriptContext,
}
use design_patterns/stake_validator as stake_validator


validator {
  fn spend(_datum, _redeemer, ctx: ScriptContext) {
    stake_validator.spend(ctx)
  }

  fn withdraw(redeemer: Data, ctx: ScriptContext) {
    stake_validator.withdraw(
      fn(_r, _own_validator, _tx) {
        True
      },
      redeemer,
      ctx
    )
  }
}
