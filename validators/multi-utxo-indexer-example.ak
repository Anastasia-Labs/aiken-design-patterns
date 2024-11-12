use aiken_design_patterns/multi_utxo_indexer as multi_utxo_indexer
use aiken_design_patterns/stake_validator as stake_validator
use aiken_design_patterns/utils.{authentic_input_is_reproduced_unchanged}
use cardano/address.{Address, Credential, Script}
use cardano/assets
use cardano/transaction.{Output, OutputReference, Transaction}

validator example(
  state_token_symbol: assets.PolicyId,
  state_token_name: assets.AssetName,
) {
  spend(_datum, _redeemer, own_ref: OutputReference, tx: Transaction) {
    expect Output {
      address: Address { payment_credential: Script(own_hash), .. },
      ..
    } = utils.resolve_output_reference(tx.inputs, own_ref)
    stake_validator.spend(
      own_hash,
      fn(r, qty) {
        expect coerced: Pairs<Int, Int> = r
        when coerced is {
          [] -> False
          _ -> qty > 0
        }
      },
      tx,
    )
  }

  withdraw(
    redeemer: List<Pair<Int, Int>>,
    stake_cred: Credential,
    tx: Transaction,
  ) {
    multi_utxo_indexer.withdraw_no_redeemer(
      fn(_in_index, in_utxo, _out_index, out_utxo) {
        authentic_input_is_reproduced_unchanged(
          state_token_symbol,
          Some(state_token_name),
          in_utxo.output,
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
