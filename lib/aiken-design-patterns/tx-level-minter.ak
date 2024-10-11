//// This design pattern couples the spend and minting endpoints of a validator,
//// in order to have minimal spend costs, in exchange for a single execution of
//// the minting endpoint.
//// 
//// In other words, spend logic only ensures the minting endpoint executes. It
//// does so by looking at the mint field and making sure **only** a non-zero
//// amount of its asset (i.e. with a policy identical to the validator's hash,
//// where its name comes from `expected_mint_name`) are getting minted/burnt.
//// 
//// The arbitrary logic is passed to the minting policy so that it can be
//// executed a single time for a given transaction.

use aiken/collection/list
use cardano/address.{Script}
use cardano/assets.{AssetName, Value}
use cardano/transaction.{Input, Output, OutputReference, Redeemer, Transaction}

/// Function to be used under the spending endpoint of your validator.
/// - Uses `redeemer` as input index to pick the spending UTxO
/// - Validates its correctness by comparing its output reference with `own_ref`
/// - Extracts validator's script hash using the input UTxO
/// - Ensures `mint` contains only a non-zero asset with a policy ID equal to
///   the script's hash, and a token name of `expected_mint_name`
/// - Finally, mint quantity is passed to the provided `mint_quantity_validator`
pub fn spend(
  expected_mint_name: AssetName,
  mint_quantity_validator: fn(Int) -> Bool,
  redeemer: Int,
  own_ref: OutputReference,
  inputs: List<Input>,
  mint: Value,
) -> Bool {
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
