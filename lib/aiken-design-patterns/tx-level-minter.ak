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
use aiken/collection/pairs
use cardano/assets.{AssetName, PolicyId}
use cardano/transaction.{Mint, Redeemer, Transaction}

/// Function to be used under the spending endpoint of your validator. It looks
/// at both the redeemers, and minted tokens to allow you validate both its
/// redeemer, and its tokens getting minted/burnt.
pub fn spend(
  mint_script_hash: PolicyId,
  mint_redeemer_validator: fn(Redeemer) -> Bool,
  mint_tokens_validator: fn(Dict<AssetName, Int>) -> Bool,
  tx: Transaction,
) -> Bool {
  let Transaction { mint, redeemers, .. } = tx

  let mint_purpose = Mint(mint_script_hash)

  let mint_redeemer: Redeemer = redeemers |> pairs.get_first(mint_purpose)

  let tokens = mint |> assets.tokens(mint_script_hash)

  and {
    mint_redeemer_validator(mint_redeemer),
    mint_tokens_validator(tokens),
  }
}

/// A minimal version of [`spend`](#spend), where the only validation is
/// presence of at least one minting/burning action with the given policy ID.
pub fn spend_minimal(mint_script_hash: PolicyId, tx: Transaction) -> Bool {
  !(tx.mint |> assets.tokens(mint_script_hash) |> dict.is_empty)
}
