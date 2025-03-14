use aiken_design_patterns/singular_utxo_indexer
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
    let Transaction { inputs, outputs, .. } = tx

    singular_utxo_indexer.one_to_many(
      input_output_validator: fn(
        _input_index,
        _input,
        _redeemer,
        _output_index,
        _output,
      ) {
        singular_utxo_indexer.IndexerValidations {
          double_satisfaction_prevented: True,
          rest_of_the_validations: True,
        }
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
      input_index: redeemer.1st,
      output_indices: redeemer.2nd,
      own_ref: own_ref,
      inputs: inputs,
      outputs: outputs,
    )
  }

  else(_) {
    fail
  }
}
