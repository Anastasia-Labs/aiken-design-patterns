use aiken/transaction.{ScriptContext}
use aiken/transaction/value.{AssetName, PolicyId}
use aiken_design_patterns/singular_utxo_indexer_one_to_many as singular_utxo_indexer

validator(_state_token_symbol: PolicyId, _state_token_name: AssetName) {
  fn spend(_datum, redeemer: (Int, List<Int>), ctx: ScriptContext) {
    singular_utxo_indexer.spend(
      fn(_input) { True },
      fn(_in_utxo, _out_utxo) { True },
      fn(_out_utxos) { True },
      redeemer,
      ctx,
    )
  }
}
