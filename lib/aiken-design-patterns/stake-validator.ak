use aiken/hash.{Blake2b_224, Hash}
use aiken/pairs
use aiken/transaction.{
  Output, Redeemer, ScriptContext, Spend, Transaction, WithdrawFrom,
}
use aiken/transaction/credential.{Inline, Script, ScriptCredential}
use aiken_design_patterns/utils.{resolve_output_reference}

pub fn spend(ctx: ScriptContext) -> Bool {
  expect ScriptContext { transaction: tx, purpose: Spend(own_ref) } = ctx

  let Transaction { inputs, withdrawals, .. } = tx

  let Output { address: own_addr, .. } =
    resolve_output_reference(inputs, own_ref)

  let own_withdrawal = Inline(own_addr.payment_credential)

  // Arbitrary withdrawal from this script is required.
  pairs.has_key(withdrawals, own_withdrawal)
}

pub fn withdraw(
  withdrawal_logic: fn(Redeemer, Hash<Blake2b_224, Script>, Transaction) -> Bool,
  redeemer: Redeemer,
  ctx: ScriptContext,
) -> Bool {
  expect ScriptContext { transaction: tx, purpose: WithdrawFrom(stake_cred) } =
    ctx

  expect Inline(ScriptCredential(own_validator)) = stake_cred

  withdrawal_logic(redeemer, own_validator, tx)
}
