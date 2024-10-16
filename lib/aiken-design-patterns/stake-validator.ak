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

use aiken/collection/pairs
use aiken/crypto.{ScriptHash}
use aiken/fuzz
use aiken_design_patterns/utils.{resolve_output_reference}
use cardano/address.{Credential, Script}
use cardano/transaction.{placeholder, Output, OutputReference, Transaction}
use cardano/transaction/output_reference as output_reference

/// Helper function for implementing minimal validation for spending UTxOs,
/// essentially delegating their requirements to the given withdrawal validator.
///
/// In simpler terms, it says: As long as there is a reward withdrawal of this
/// script in the transaction, this UTxO can be spent.
pub fn spend(withdrawal_script_hash: ScriptHash, own_ref: OutputReference, tx: Transaction) -> Bool {
  let withdrawal_credential = Script(withdrawal_script_hash)

  // Arbitrary withdrawal from given script is required.
  pairs.has_key(tx.withdrawals, withdrawal_credential)
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
  spend_script_hash_and_inputs via utils.inputs_with_an_authentic_script_input_fuzzer(None),
) {
  let (spend_script_hash, script_input, inputs) = spend_script_hash_and_inputs
  let tx = Transaction {
    ..placeholder,
    inputs,
    withdrawals: [Pair(Script(spend_script_hash, 0))],
  }
  spend(spend_script_hash, script_input.output_reference, tx)
}

test failure_spend(
  spend_script_hash_and_inputs via utils.inputs_with_an_authentic_script_input_fuzzer(None),
  expected_withdraw_script_hash via fuzz.bytearray_fixed(28),
) fail {
  let (spend_script_hash, script_input, inputs) = spend_script_hash_and_inputs
  let tx = Transaction {
    ..placeholder,
    inputs,
    withdrawals: [Pair(Script(spend_script_hash, 0))],
  }
  spend(expected_withdraw_script_hash, script_input.output_reference, tx)
}
