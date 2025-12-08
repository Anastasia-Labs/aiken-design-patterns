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

use aiken/collection/dict.{Dict}
use aiken/collection/list
use cardano/assets.{AssetName, PolicyId, Value}
use cardano/transaction.{Mint, Redeemer, ScriptPurpose}

/// Function primarily meant be used in your spending validator. It looks at
/// both the redeemers, and minted tokens to allow you validate agains the
/// policy's redeemer, and its tokens getting minted/burnt.
///
/// `mint_redeemer_index` is the positional index of the policy's redeemer in
/// the `redeemers` field of the transaction.
pub fn validate_mint(
  mint_script_hash: PolicyId,
  mint: Value,
  redeemers: Pairs<ScriptPurpose, Redeemer>,
  mint_redeemer_index: Int,
  mint_validator: fn(Redeemer, Dict<AssetName, Int>) -> Bool,
) -> Bool {
  let mint_purpose = Mint(mint_script_hash)

  expect Some(rdmr_pair) = redeemers |> list.at(mint_redeemer_index)

  expect rdmr_pair.1st == mint_purpose

  let tokens = mint |> assets.tokens(mint_script_hash)

  mint_validator(rdmr_pair.2nd, tokens)
}

/// A minimal version of [`spend`](#spend), where the only validation is
/// presence of at least one minting/burning action with the given policy ID.
pub fn validate_mint_minimal(mint_script_hash: PolicyId, mint: Value) -> Bool {
  !(mint |> assets.tokens(mint_script_hash) |> dict.is_empty)
}
