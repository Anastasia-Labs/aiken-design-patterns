//// @hidden

use aiken_design_patterns/multi_utxo_indexer
use aiken_design_patterns/stake_validator
use aiken_design_patterns/utils.{authentic_input_is_reproduced_unchanged}
use cardano/address.{Address, Credential, Script}
use cardano/assets
use cardano/transaction.{Output, OutputReference, Transaction}

pub type ExampleSpendRedeemer {
  withdraw_redeemer_index: Int,
  withdrawal_index: Int,
}

validator example(
  state_token_symbol: assets.PolicyId,
  state_token_name: assets.AssetName,
) {
  spend(
    _datum,
    redeemer: ExampleSpendRedeemer,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    let Transaction { inputs, redeemers, withdrawals, .. } = tx
    expect Output {
      address: Address { payment_credential: Script(own_hash), .. },
      ..
    } = utils.resolve_output_reference(inputs, own_ref)
    let
      r,
      qty,
    <-
      stake_validator.validate_withdraw_with_amount(
        own_hash,
        redeemers,
        redeemer.withdraw_redeemer_index,
        withdrawals,
        redeemer.withdrawal_index,
      )
    expect coerced: Pairs<Int, Int> = r
    when coerced is {
      [] -> False
      _ -> qty > 0
    }
  }

  withdraw(redeemer: Pairs<Int, Int>, stake_cred: Credential, tx: Transaction) {
    expect Script(own_script_hash) = stake_cred
    let Transaction { inputs, outputs, .. } = tx
    let
      _input_index,
      input,
      _output_index,
      output,
    <-
      multi_utxo_indexer.one_to_one_no_redeemer(
        redeemer,
        own_script_hash,
        inputs,
        outputs,
      )
    authentic_input_is_reproduced_unchanged(
      state_token_symbol,
      Some(state_token_name),
      input.output,
      output,
    )
  }

  else(_) {
    fail
  }
}
