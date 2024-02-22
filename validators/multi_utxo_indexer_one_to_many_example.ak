use aiken/transaction.{ScriptContext}
use aiken/transaction/value.{AssetName, PolicyId}
use aiken_design_patterns/multi_utxo_indexer_one_to_many as multi_utxo_indexer
use aiken_design_patterns/stake_validator as stake_validator

validator(_state_token_symbol: PolicyId, _state_token_name: AssetName) {
  fn spend(_datum, _redeemer, ctx: ScriptContext) {
    stake_validator.spend(ctx)
  }

  fn withdraw(redeemer: List<(Int, List<Int>)>, ctx: ScriptContext) {
    multi_utxo_indexer.withdraw(
      fn(_input) { True },
      fn(_in_utxo, _out_utxo) { True },
      fn(_out_utxos) { True },
      redeemer,
      ctx,
    )
  }
}
