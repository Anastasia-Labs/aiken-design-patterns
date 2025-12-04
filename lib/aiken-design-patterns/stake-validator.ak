//// This pattern allows for delegating some computations to a given staking
//// script.
//// 
//// The primary application for this is the so-called "withdraw zero trick,"
//// which is most effective for validators that need to go over multiple
//// inputs.
//// 
//// With a minimal spending logic (which is executed for each UTxO), and an
//// arbitrary withdrawal logic (which is executed only once), a much more
//// optimized script can be implemented.

use aiken/collection/list
use aiken/crypto.{ScriptHash}
use cardano/address.{Credential, Script}
use cardano/assets.{Lovelace}
use cardano/transaction.{Redeemer, ScriptPurpose, Withdraw}

/// Helper function for implementing validation for spending UTxOs, essentially
/// delegating their requirements to the given withdrawal validator.
///
/// In simpler terms, it says: As long as there is a redeemer with a withdrawal
/// purpose, for the given script in transaction, this UTxO can be spent.
///
/// Allows you to validate based on the withdrawal's redeemer, which ismostly
/// useful for ensuring specific endpoints are invoked.
pub fn validate_withdraw(
  withdraw_script_hash: ScriptHash,
  redeemers: Pairs<ScriptPurpose, Redeemer>,
  withdraw_redeemer_index: Int,
  withdraw_redeemer_validator: fn(Redeemer) -> Bool,
) -> Bool {
  expect Some(withdraw_redeemer_pair) =
    redeemers |> list.at(withdraw_redeemer_index)

  expect withdraw_redeemer_pair.1st == Withdraw(Script(withdraw_script_hash))

  withdraw_redeemer_validator(withdraw_redeemer_pair.2nd)
}

/// Similar to [`validate_withdraw`](#validate_withdraw), but with the
/// additional steps for extracting the withdrawal amount from the withdrawals
/// field.
pub fn validate_withdraw_with_amount(
  withdraw_script_hash: ScriptHash,
  redeemers: Pairs<ScriptPurpose, Redeemer>,
  withdraw_redeemer_index: Int,
  withdrawals: Pairs<Credential, Lovelace>,
  withdrawal_index: Int,
  withdraw_redeemer_validator: fn(Redeemer, Lovelace) -> Bool,
) -> Bool {
  let withdrawal_credential: Credential = Script(withdraw_script_hash)

  expect Some(withdraw_redeemer_pair) =
    redeemers |> list.at(withdraw_redeemer_index)

  expect withdraw_redeemer_pair.1st == Withdraw(withdrawal_credential)

  expect Some(withdrawal_pair) = withdrawals |> list.at(withdrawal_index)

  expect withdrawal_pair.1st == withdrawal_credential

  withdraw_redeemer_validator(withdraw_redeemer_pair.2nd, withdrawal_pair.2nd)
}

/// A more minimal version of [`validate_withdraw`](#validate_withdraw), where
/// only the presence of a given staking script is checked, regardless of
/// withdraw amount or redeemer.
pub fn validate_withdraw_minimal(
  withdraw_script_hash: ScriptHash,
  withdrawals: Pairs<Credential, Lovelace>,
  withdrawal_index: Int,
) -> Bool {
  expect Some(withdrawal_pair) = withdrawals |> list.at(withdrawal_index)

  withdrawal_pair.1st == Script(withdraw_script_hash)
}
