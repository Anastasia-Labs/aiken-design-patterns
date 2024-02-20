use aiken/transaction.{Redeemer, ScriptContext}
use aiken_design_patterns/tx_level_minter as tx_level_minter

validator {
  fn spend(_datum, _redeemer, ctx: ScriptContext) {
    tx_level_minter.spend("BEACON", ctx)
  }

  fn mint(redeemer: Redeemer, ctx: ScriptContext) {
    tx_level_minter.mint(fn(_r, _own_policy, _tx) { True }, redeemer, ctx)
  }
}
