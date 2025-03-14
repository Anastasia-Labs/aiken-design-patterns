use aiken_design_patterns/singular_utxo_indexer
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
    let Transaction { inputs, outputs, .. } = tx

    singular_utxo_indexer.one_to_one(
      validation_logic: fn(
        _input_index,
        input,
        _redeemer,
        _output_index,
        output,
      ) {
        singular_utxo_indexer.IndexerValidations {
          double_satisfaction_prevented: True,
          rest_of_the_validations: authentic_input_is_reproduced_unchanged(
            state_token_symbol,
            None,
            input.output,
            output,
          ),
        }
      },
      redeemer: redeemer,
      input_index: redeemer.1st,
      output_index: redeemer.2nd,
      own_ref: own_out_ref,
      inputs: inputs,
      outputs: outputs,
    )
  }

  else(_) {
    fail
  }
}
