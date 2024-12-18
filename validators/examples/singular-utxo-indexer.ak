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
      validation_logic: fn(
        _input_index,
        input,
        _redeemer,
        _output_index,
        output,
      ) {
        authentic_input_is_reproduced_unchanged(
          state_token_symbol,
          None,
          input.output,
          output,
        )
      },
      redeemer: redeemer,
      indices: redeemer,
      own_ref: own_out_ref,
      tx: tx,
    )
  }

  else(_) {
    fail
  }
}
