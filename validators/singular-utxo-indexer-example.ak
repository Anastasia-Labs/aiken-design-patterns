use aiken/collection/dict
use aiken/interval
use aiken_design_patterns/singular_utxo_indexer as singular_utxo_indexer
use aiken_design_patterns/utils.{authentic_input_is_reproduced_unchanged}
use cardano/address.{Address, Script}
use cardano/assets
use cardano/transaction.{
  Input, NoDatum, Output, OutputReference, Spend, Transaction,
}

validator example(state_token_symbol: assets.PolicyId) {
  spend(
    _datum,
    redeemer: Pair<Int, Int>,
    own_out_ref: OutputReference,
    tx: Transaction,
  ) {
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
      own_out_ref,
      tx,
    )
  }

  else(_) {
    fail
  }
}
