//// This module offers two functions meant to be used within a validator for
//// implementing a "coupled" stake validator logic.
//// 
//// The primary application for this is the so-called "withdraw zero trick,"
//// which is most effective for validators that need to go over multiple
//// inputs.
//// 
//// With a minimal spending logic (which is executed for each UTxO), and an
//// arbitrary withdrawal logic (which is executed only once), a much more
//// optimized script can be implemented.

use aiken/builtin
use aiken/collection/pairs
use aiken/crypto.{ScriptHash, blake2b_224}
use aiken_design_patterns/utils as utils
use cardano/address.{Credential, Script}
use cardano/assets.{Lovelace}
use cardano/transaction.{Redeemer, Transaction, Withdraw, placeholder}

/// Helper function for implementing minimal validation for spending UTxOs,
/// essentially delegating their requirements to the given withdrawal validator.
///
/// In simpler terms, it says: As long as there is a reward withdrawal of the
/// given script in transaction, this UTxO can be spent.
///
/// Allows you to validate based on both the withdrawal's redeemer (mostly
/// useful for ensuring specific endpoints are invoked), and the withdrawal
/// Lovelace count.
pub fn spend(
  withdraw_script_hash: ScriptHash,
  withdraw_redeemer_validator: fn(Redeemer) -> Bool,
  withdraw_amount_validator: fn(Lovelace) -> Bool,
  tx: Transaction,
) -> Bool {
  let Transaction { redeemers, withdrawals, .. } = tx

  let withdraw_script = Script(withdraw_script_hash)

  let withdraw_purpose = Withdraw(withdraw_script)

  let withdraw_redeemer: Redeemer =
    redeemers |> pairs.get_first(withdraw_purpose)

  expect Some(withdraw_amount) = withdrawals |> pairs.get_first(withdraw_script)

  and {
    withdraw_redeemer_validator(withdraw_redeemer),
    withdraw_amount_validator(withdraw_amount),
  }
}

/// Function to be used under your withdrawal endpoint. The only convenience
/// this function provides is that it'll provide you with the `ScriptHash` of
/// your withdrawal script, so that you don't have to unwrap it yourself.
pub fn withdraw(
  withdrawal_logic: fn(a, ScriptHash, Transaction) -> Bool,
  redeemer: a,
  stake_cred: Credential,
  tx: Transaction,
) -> Bool {
  expect Script(own_validator) = stake_cred

  withdrawal_logic(redeemer, own_validator, tx)
}

test success_spend(
  spend_script_hash_and_inputs via utils.inputs_with_an_authentic_script_input_fuzzer(
    None,
  ),
) {
  let (spend_script_hash, _script_input, inputs) = spend_script_hash_and_inputs
  let tx =
    Transaction {
      ..placeholder,
      inputs,
      redeemers: [Pair(Withdraw(Script(spend_script_hash)), builtin.i_data(0))],
      withdrawals: [Pair(Script(spend_script_hash), 0)],
    }
  spend(spend_script_hash, fn(_r_data) { True }, fn(_qty) { True }, tx)
}

test fail_spend(
  spend_script_hash_and_inputs via utils.inputs_with_an_authentic_script_input_fuzzer(
    None,
  ),
) fail {
  let (spend_script_hash, _script_input, inputs) = spend_script_hash_and_inputs
  let spend_script = Script(spend_script_hash)
  let tx =
    Transaction {
      ..placeholder,
      inputs: inputs,
      redeemers: [Pair(Withdraw(spend_script), builtin.i_data(0))],
      withdrawals: [Pair(spend_script, 0)],
    }
  // Hashing to get a different script hash
  let expected_withdraw_script_hash = blake2b_224(spend_script_hash)
  spend(expected_withdraw_script_hash, fn(_r_data) { True }, fn(_qty) { True }, tx)
}
