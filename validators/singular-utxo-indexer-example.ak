use aiken/transaction.{ScriptContext}
use aiken/transaction/value.{PolicyId}
use aiken_design_patterns/singular_utxo_indexer as singular_utxo_indexer
use aiken_design_patterns/utils.{authentic_input_is_reproduced_unchanged}

validator(state_token_symbol: PolicyId) {
  fn spend(_datum, redeemer: (Int, Int), ctx: ScriptContext) {
    singular_utxo_indexer.spend(
      fn(in_utxo, out_utxo) {
        authentic_input_is_reproduced_unchanged(
          state_token_symbol,
          None,
          in_utxo,
          out_utxo,
        )
      },
      redeemer,
      ctx,
    )
  }
}
