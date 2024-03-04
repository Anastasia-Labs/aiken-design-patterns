use aiken/hash.{Blake2b_224, Hash}
use aiken/list
use aiken/transaction.{
  Input, Mint, Output, Redeemer, ScriptContext, Spend, Transaction,
}
use aiken/transaction/credential.{Script, ScriptCredential}
use aiken/transaction/value.{AssetName}

pub fn spend(
  expected_mint_name: AssetName,
  redeemer: Int,
  ctx: ScriptContext,
) -> Bool {
  expect ScriptContext { transaction: tx, purpose: Spend(own_ref) } = ctx

  let Transaction { inputs, mint, .. } = tx

  expect Some(Input {
    output: Output { address: own_addr, .. },
    output_reference: in_ref,
  }) = inputs |> list.at(redeemer)

  // Make sure the redeemer index is picking the same UTxO as the spending one.
  expect (own_ref == in_ref)?

  expect ScriptCredential(own_validator_hash) = own_addr.payment_credential

  // Exactly one asset is expected to be minted.
  expect [(mint_policy, mint_name, mint_quantity)] =
    mint
      |> value.from_minted_value
      |> value.flatten

  and {
    // Minted token must have the same policy ID as the spending validator hash
    // (i.e. it is expected to be a multi-validator).
    mint_policy == own_validator_hash,
    // Minted token name must match the name specified as a parameter.
    mint_name == expected_mint_name,
    // Mint quantity must not be 0 to ensure invocation of the minting policy.
    // TODO: Is this redundant?
    mint_quantity < 0 || mint_quantity > 0,
  }
}

pub fn mint(
  mint_logic: fn(Redeemer, Hash<Blake2b_224, Script>, Transaction) -> Bool,
  redeemer: Redeemer,
  ctx: ScriptContext,
) -> Bool {
  expect ScriptContext { transaction: tx, purpose: Mint(own_policy) } = ctx

  mint_logic(redeemer, own_policy, tx)
}
