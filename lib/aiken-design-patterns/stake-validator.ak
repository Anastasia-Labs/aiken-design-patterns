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

use aiken/collection/pairs
use aiken/crypto.{ScriptHash}
use cardano/address.{Credential, Script}
use cardano/assets.{Lovelace}
use cardano/transaction.{Redeemer, ScriptPurpose, Withdraw}

/// Helper function for implementing validation for spending UTxOs, essentially
/// delegating their requirements to the given withdrawal validator.
///
/// In simpler terms, it says: As long as there is a reward withdrawal of the
/// given script in transaction, this UTxO can be spent.
///
/// Allows you to validate based on both the withdrawal's redeemer (mostly
/// useful for ensuring specific endpoints are invoked), and the withdrawal
/// Lovelace count.
pub fn validate_withdraw(
  withdraw_script_hash: ScriptHash,
  withdrawals: Pairs<Credential, Lovelace>,
  redeemers: Pairs<ScriptPurpose, Redeemer>,
  withdraw_redeemer_validator: fn(Redeemer, Lovelace) -> Bool,
) -> Bool {
  let withdraw_script = Script(withdraw_script_hash)

  let withdraw_purpose = Withdraw(withdraw_script)

  let withdraw_redeemer: Redeemer =
    redeemers |> pairs.get_first(withdraw_purpose)

  expect Some(withdraw_amount) = withdrawals |> pairs.get_first(withdraw_script)

  withdraw_redeemer_validator(withdraw_redeemer, withdraw_amount)
}

/// A more minimal version of [`validate_withdraw`](#validate_withdraw), where
/// only the presence of a given staking script is checked, regardless of
/// withdraw amount or redeemer.
pub fn validate_withdraw_minimal(
  withdraw_script_hash: ScriptHash,
  withdrawals: Pairs<Credential, Lovelace>,
) -> Bool {
  let withdraw_script = Script(withdraw_script_hash)

  when withdrawals |> pairs.get_first(withdraw_script) is {
    Some(_) -> True
    _ -> False
  }
}
