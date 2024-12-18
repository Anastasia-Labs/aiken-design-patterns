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
      input_output_validator: fn(
        _input_index,
        _input,
        _redeemer,
        _output_index,
        _output,
      ) {
        True
      },
      input_collective_outputs_validator: fn(
        _input_index,
        _input,
        _redeemer,
        _outputs,
      ) {
        True
      },
      redeemer: redeemer,
      indices: redeemer,
      own_ref: own_ref,
      tx: tx,
    )
  }

  else(_) {
    fail
  }
}
