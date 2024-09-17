use aiken/collection/list
use aiken/crypto.{ScriptHash}
use cardano/address.{Script}
use cardano/assets.{AssetName}
use cardano/transaction.{
  Input, Mint, Output, Redeemer, OutputReference, Spend, Transaction,
}

pub fn spend(
  expected_mint_name: AssetName,
  mint_quantity_validator: fn(Int) -> Bool,
  redeemer: Int,
  own_ref: OutputReference,
  tx: Transaction,
) -> Bool {
  let Transaction { inputs, mint, .. } = tx

  expect Some(Input {
    output: Output { address: own_addr, .. },
    output_reference: in_ref,
  }) = inputs |> list.at(redeemer)

  // Make sure the redeemer index is picking the same UTxO as the spending one.
  expect (own_ref == in_ref)?

  expect Script(own_validator_hash) = own_addr.payment_credential

  // Exactly one asset is expected to be minted.
  expect [(mint_policy, mint_name, mint_quantity)] =
    mint
      |> assets.flatten

  and {
    // Minted token must have the same policy ID as the spending validator hash
    mint_policy == own_validator_hash,
    // Minted token name must match the name specified as a parameter.
    mint_name == expected_mint_name,
    // Perform provided custom validation on the mint quantity.
    mint_quantity_validator(mint_quantity),
  }
}
