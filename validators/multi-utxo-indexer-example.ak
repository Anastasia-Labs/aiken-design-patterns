use aiken_design_patterns/multi_utxo_indexer
use aiken_design_patterns/stake_validator
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
      withdraw_script_hash: own_hash,
      withdraw_redeemer_validator: fn(r, qty) {
        expect coerced: Pairs<Int, Int> = r
        when coerced is {
          [] -> False
          _ -> qty > 0
        }
      },
      tx: tx,
    )
  }

  withdraw(
    redeemer: List<Pair<Int, Int>>,
    stake_cred: Credential,
    tx: Transaction,
  ) {
    multi_utxo_indexer.withdraw_no_redeemer(
      validation_logic: fn(_input_index, input, _output_index, output) {
        authentic_input_is_reproduced_unchanged(
          state_token_symbol,
          Some(state_token_name),
          input.output,
          output,
        )
      },
      indices: redeemer,
      stake_cred: stake_cred,
      tx: tx,
    )
  }

  else(_) {
    fail
  }
}
