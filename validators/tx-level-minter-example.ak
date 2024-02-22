use aiken/transaction.{Redeemer, ScriptContext}
use aiken_design_patterns/tx_level_minter as tx_level_minter

validator {
  fn spend(_datum, redeemer: Int, ctx: ScriptContext) {
    tx_level_minter.spend("BEACON", redeemer, ctx)
  }

  fn mint(redeemer: Redeemer, ctx: ScriptContext) {
    tx_level_minter.mint(fn(_r, _own_policy, _tx) { True }, redeemer, ctx)
  }
}
