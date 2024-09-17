use aiken/collection/pairs
use aiken/crypto.{ScriptHash}
use cardano/address.{Credential, Script}
use cardano/transaction.{
  Output, OutputReference, Transaction,
}
use aiken_design_patterns/utils.{resolve_output_reference}

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

pub fn withdraw(
  withdrawal_logic: fn(a, ScriptHash, Transaction) -> Bool,
  redeemer: a,
  stake_cred: Credential,
  tx: Transaction,
) -> Bool {
  expect Script(own_validator) = stake_cred

  withdrawal_logic(redeemer, own_validator, tx)
}
