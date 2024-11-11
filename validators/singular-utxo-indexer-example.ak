use aiken_design_patterns/singular_utxo_indexer as singular_utxo_indexer
use aiken_design_patterns/utils.{authentic_input_is_reproduced_unchanged}
use cardano/assets
use cardano/transaction.{OutputReference, Transaction}

validator example(state_token_symbol: assets.PolicyId) {
  spend(
    _datum,
    redeemer: Pair<Int, Int>,
    own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    singular_utxo_indexer.spend(
      fn(_ii, in_utxo, _r, _oi, out_utxo) {
        authentic_input_is_reproduced_unchanged(
          state_token_symbol,
          None,
          in_utxo.output,
          out_utxo,
        )
      },
      redeemer,
      redeemer,
      own_out_ref,
      tx,
    )
  }

  else(_) {
    fail
  }
}
