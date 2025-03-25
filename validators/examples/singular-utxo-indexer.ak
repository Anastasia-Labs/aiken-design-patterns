use aiken_design_patterns/singular_utxo_indexer
use aiken_design_patterns/utils.{authentic_input_is_reproduced_unchanged}
use cardano/assets
use cardano/transaction.{OutputReference, Transaction}

validator one_to_one(state_token_symbol: assets.PolicyId) {
  spend(
    _datum,
    redeemer: Pair<Int, Int>,
    own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    let Transaction { inputs, outputs, .. } = tx

    singular_utxo_indexer.one_to_one(
      validation_logic: fn(input, output) {
        authentic_input_is_reproduced_unchanged(
          state_token_symbol,
          None,
          input.output,
          output,
        )
      },
      input_index: redeemer.1st,
      output_index: redeemer.2nd,
      own_ref: own_out_ref,
      inputs: inputs,
      outputs: outputs,
      double_satisfaction_prevented: True,
    )
  }

  else(_) {
    fail
  }
}

validator one_to_many(
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
      input_output_validator: fn(_input, _output_index, _output) { True },
      input_collective_outputs_validator: fn(_input, _outputs) { True },
      input_index: redeemer.1st,
      output_indices: redeemer.2nd,
      own_ref: own_ref,
      inputs: inputs,
      outputs: outputs,
      double_satisfaction_prevented: True,
    )
  }

  else(_) {
    fail
  }
}
