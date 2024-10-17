use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken/fuzz
use aiken/interval
use aiken_design_patterns/multi_utxo_indexer_one_to_many as multi_utxo_indexer
use aiken_design_patterns/stake_validator as stake_validator
use cardano/address.{Address, Credential, Inline, Script}
use cardano/assets
use cardano/transaction.{
  Input, NoDatum, Output, OutputReference, Spend, Transaction, Withdraw,
}

validator example(
  _state_token_symbol: assets.PolicyId,
  _state_token_name: assets.AssetName,
) {
  spend(_datum, _redeemer, own_ref: OutputReference, tx: Transaction) {
    stake_validator.spend(own_ref, tx)
  }

  withdraw(
    redeemer: List<Pair<Int, List<Int>>>,
    stake_cred: Credential,
    tx: Transaction,
  ) {
    multi_utxo_indexer.withdraw(
      fn(_input) { True },
      fn(_in_utxo, _out_utxo) { True },
      fn(_output_value, _output_count) { True },
      redeemer,
      stake_cred,
      tx,
    )
  }

  else(_) {
    fail
  }
}
