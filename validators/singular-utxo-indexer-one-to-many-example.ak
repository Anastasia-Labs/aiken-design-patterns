use aiken_design_patterns/singular_utxo_indexer_one_to_many
use cardano/assets
use cardano/transaction.{OutputReference, Transaction}

validator example(
  _state_token_symbol: assets.PolicyId,
  _state_token_name: assets.AssetName,
) {
  spend(
    _datum,
    redeemer: Pair<Int, List<Int>>,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    singular_utxo_indexer_one_to_many.spend(
      fn(_in_index, _in_input, _r, _out_index, _out_utxo) { True },
      fn(_in_index, _in_input, _r, _outputs) { True },
      redeemer,
      redeemer,
      own_ref,
      tx,
    )
  }

  else(_) {
    fail
  }
}
