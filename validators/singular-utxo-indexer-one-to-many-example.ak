use aiken/collection/dict
use aiken/interval
use aiken_design_patterns/singular_utxo_indexer_one_to_many as singular_utxo_indexer
use cardano/address.{Address}
use cardano/assets
use cardano/transaction.{
  Input, NoDatum, Output, OutputReference, Spend, Transaction, placeholder,
}

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
    singular_utxo_indexer.spend(
      fn(_input) { True },
      fn(_in_utxo, _out_utxo) { True },
      fn(_output_value, _output_count) { True },
      redeemer,
      own_ref,
      tx,
    )
  }

  else(_) {
    fail
  }
}
