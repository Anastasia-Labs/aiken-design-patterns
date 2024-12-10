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

use aiken/builtin
use aiken/collection/pairs
use aiken/crypto.{ScriptHash, blake2b_224}
use aiken/fuzz
use cardano/address.{Credential, Script}
use cardano/assets.{Lovelace}
use cardano/transaction.{Redeemer, Transaction, Withdraw, placeholder}

/// Helper function for implementing validation for spending UTxOs, essentially
/// delegating their requirements to the given withdrawal validator.
///
/// In simpler terms, it says: As long as there is a reward withdrawal of the
/// given script in transaction, this UTxO can be spent.
///
/// Allows you to validate based on both the withdrawal's redeemer (mostly
/// useful for ensuring specific endpoints are invoked), and the withdrawal
/// Lovelace count.
pub fn spend(
  withdraw_script_hash: ScriptHash,
  withdraw_redeemer_validator: fn(Redeemer, Lovelace) -> Bool,
  tx: Transaction,
) -> Bool {
  let Transaction { redeemers, withdrawals, .. } = tx

  let withdraw_script = Script(withdraw_script_hash)

  let withdraw_purpose = Withdraw(withdraw_script)

  let withdraw_redeemer: Redeemer =
    redeemers |> pairs.get_first(withdraw_purpose)

  expect Some(withdraw_amount) = withdrawals |> pairs.get_first(withdraw_script)

  withdraw_redeemer_validator(withdraw_redeemer, withdraw_amount)
}

/// A more minimal version of [`spend`](#spend), where only the `withdrawals`
/// field is traversed, and no other validations are performed.
pub fn spend_minimal(withdraw_script_hash: ScriptHash, tx: Transaction) -> Bool {
  let Transaction { withdrawals, .. } = tx

  let withdraw_script = Script(withdraw_script_hash)

  when withdrawals |> pairs.get_first(withdraw_script) is {
    Some(_) -> True
    _ -> False
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

test success_spend(script_hash via fuzz.bytearray_fixed(28)) {
  let tx =
    Transaction {
      ..placeholder,
      redeemers: [Pair(Withdraw(Script(script_hash)), builtin.i_data(0))],
      withdrawals: [Pair(Script(script_hash), 0)],
    }
  spend(script_hash, fn(_r_data, _qty) { True }, tx)
}

test fail_spend(script_hash via fuzz.bytearray_fixed(28)) fail {
  let spend_script = Script(script_hash)
  let tx =
    Transaction {
      ..placeholder,
      redeemers: [Pair(Withdraw(spend_script), builtin.i_data(0))],
      withdrawals: [Pair(spend_script, 0)],
    }
  // Hashing to get a different script hash
  let expected_withdraw_script_hash = blake2b_224(script_hash)
  spend(expected_withdraw_script_hash, fn(_r_data, _qty) { True }, tx)
}

test success_spend_minimal(script_hash via fuzz.bytearray_fixed(28)) {
  let tx =
    Transaction { ..placeholder, withdrawals: [Pair(Script(script_hash), 0)] }
  spend_minimal(script_hash, tx)
}

test fail_spend_minimal(script_hash via fuzz.bytearray_fixed(28)) fail {
  let spend_script = Script(script_hash)
  let tx = Transaction { ..placeholder, withdrawals: [Pair(spend_script, 0)] }
  // Hashing to get a different script hash
  let expected_withdraw_script_hash = blake2b_224(script_hash)
  spend_minimal(expected_withdraw_script_hash, tx)
}
