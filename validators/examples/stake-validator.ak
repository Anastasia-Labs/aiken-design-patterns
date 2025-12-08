//// @hidden

use aiken/crypto.{ScriptHash}
use aiken_design_patterns/stake_validator
use cardano/address.{Credential}
use cardano/transaction.{OutputReference, Transaction}

pub type ExampleSpendRedeemer {
  withdraw_redeemer_index: Int,
  withdrawal_index: Int,
}

/// Example for a validator that requires a withdrawal from a given staking
/// script hash.
validator spend(withdraw_script_hash: ScriptHash) {
  spend(
    _datum,
    redeemer: ExampleSpendRedeemer,
    own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    // Extract needed values from `tx`
    let Transaction { withdrawals, redeemers, .. } = tx

    // Validate the required staking script is present in transaction, and grab
    // its redeemer data and withdraw quantity in Lovelace.
    let
      redeemer_data,
      withdraw_amount,
    <-
      stake_validator.validate_withdraw_with_amount(
        withdraw_script_hash,
        redeemers,
        redeemer.withdraw_redeemer_index,
        withdrawals,
        redeemer.withdrawal_index,
      )

    // Example validation, ensuring the staking script has been invoked with
    // access to the output reference of the UTxO being spent.
    expect out_ref_passed_to_staking_script: OutputReference = redeemer_data
    expect out_ref_passed_to_staking_script == own_out_ref

    // Another example validation, only allowing withdrawals from the staking
    // script as long as no rewards had been accumulated for said script.
    withdraw_amount == 0
  }

  else(_) {
    fail
  }
}

/// A very minimal example just to show how an accompanying staking script can
/// be defined.
validator witdhraw {
  withdraw(
    redeemer: OutputReference,
    _own_credential: Credential,
    _tx: Transaction,
  ) {
    let OutputReference { output_index, .. } = redeemer
    // A contrived check. Only UTxOs that have an output index of 0 pass this
    // script's validation.
    output_index == 0
  }

  else(_) {
    fail
  }
}
