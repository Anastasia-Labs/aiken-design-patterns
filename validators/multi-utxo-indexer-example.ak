use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken/fuzz
use aiken/interval
use aiken_design_patterns/multi_utxo_indexer as multi_utxo_indexer
use aiken_design_patterns/stake_validator as stake_validator
use aiken_design_patterns/utils.{authentic_input_is_reproduced_unchanged}
use cardano/address.{Address, Credential, Inline, Script}
use cardano/assets
use cardano/transaction.{
  Input, NoDatum, Output, OutputReference, Spend, Transaction, Withdraw,
}

validator example(
  state_token_symbol: assets.PolicyId,
  state_token_name: assets.AssetName,
) {
  spend(_datum, _redeemer, own_ref: OutputReference, tx: Transaction) {
    stake_validator.spend(own_ref, tx)
  }

  withdraw(
    redeemer: List<Pair<Int, Int>>,
    stake_cred: Credential,
    tx: Transaction,
  ) {
    multi_utxo_indexer.withdraw(
      fn(in_utxo, out_utxo) {
        authentic_input_is_reproduced_unchanged(
          state_token_symbol,
          Some(state_token_name),
          in_utxo,
          out_utxo,
        )
      },
      redeemer,
      stake_cred,
      tx,
    )
  }

  else(_) {
    fail
  }
}
