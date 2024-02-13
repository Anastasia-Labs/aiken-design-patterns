use aiken/dict
use aiken/hash.{
  Blake2b_224,
  Hash,
}
use aiken/transaction.{
  Input,
  Output,
  OutputReference,
  ScriptContext,
  Spend,
  WithdrawFrom,
  Transaction,
}
use aiken/transaction/credential.{
  Inline,
  Script,
  ScriptCredential,
}

fn withdrawal_logic(
  _redeemer: Data,
  _own_validator: Hash<Blake2b_224, Script>,
  _tx: Transaction
) -> Bool {
  True
}

validator {
  fn spend(_datum, _redeemer, ctx: ScriptContext) -> Bool {
    expect ScriptContext { transaction: tx, purpose: Spend(own_ref) } =
      ctx

    let Transaction { inputs, withdrawals, .. } =
      tx

    let Output { address: own_addr, .. } =
      resolve_output_reference(inputs, own_ref)

    let own_withdrawal =
      Inline(own_addr.payment_credential)

    // Arbitrary withdrawal from this script is required.
    dict.has_key(withdrawals, own_withdrawal)
  }
  fn withdraw(redeemer: Data, ctx: ScriptContext) -> Bool {
    expect ScriptContext { transaction: tx, purpose: WithdrawFrom(stake_cred) } =
      ctx

    expect Inline(ScriptCredential(own_validator)) =
      stake_cred

    withdrawal_logic(redeemer, own_validator, tx)
  }
}

// Copied from:
// https://github.com/aiken-lang/fortuna
fn resolve_output_reference(
  inputs: List<Input>,
  output_ref: OutputReference
) -> Output {
  expect [input, ..inputs] = inputs

  if input.output_reference == output_ref {
    input.output
  } else {
    resolve_output_reference(inputs, output_ref)
  }
}
