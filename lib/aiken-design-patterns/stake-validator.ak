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
use aiken_design_patterns/utils.{resolve_output_reference}
use cardano/address.{Credential, Script}
use cardano/transaction.{Output, OutputReference, Transaction}

/// Helper function for implementing minimal validation for spending UTxOs,
/// essentially delegating their requirements to the withdrawal endpoint of the
/// same contract.
///
/// In simpler terms, it says: As long as there is a reward withdrawal of this
/// script in the transaction, this UTxO can be spent.
pub fn spend(own_ref: OutputReference, tx: Transaction) -> Bool {
  let Transaction { inputs, withdrawals, .. } = tx

  let Output { address: own_addr, .. } =
    resolve_output_reference(inputs, own_ref)

  // Implicit assumption that `own_ref` is properly passed, and therefore yields
  // a `Script` payment credential from `own_addr`.
  let own_withdrawal = own_addr.payment_credential

  // Arbitrary withdrawal from this script is required.
  pairs.has_key(withdrawals, own_withdrawal)
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
