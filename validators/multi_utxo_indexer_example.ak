use aiken/transaction.{ScriptContext}
use aiken/transaction/value.{AssetName, PolicyId}
use aiken_design_patterns/multi_utxo_indexer as multi_utxo_indexer
use aiken_design_patterns/stake_validator as stake_validator
use aiken_design_patterns/utils.{authentic_input_is_reproduced_unchanged}

validator(state_token_symbol: PolicyId, state_token_name: AssetName) {
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
