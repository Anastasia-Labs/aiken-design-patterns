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

use aiken/builtin
use aiken/collection/dict.{Dict}
use aiken/collection/list
use aiken/collection/pairs
use aiken/crypto.{blake2b_224}
use aiken/fuzz
use aiken_design_patterns/utils as utils
use cardano/assets.{AssetName, PolicyId, Value}
use cardano/transaction.{Mint, Redeemer, Transaction, placeholder}

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

fn grab_a_policy_from_mint(m: Value) -> Fuzzer<(PolicyId, Value)> {
  let policies = m |> assets.policies
  fuzz.map(
    fuzz.int_between(0, list.length(policies) - 1),
    fn(i) {
      trace list.length(policies)
      trace i
      expect Some(p) = list.at(policies, i)
      (p, m)
    },
  )
}

test success_spend(
  random_policy_and_mint via fuzz.and_then(
    utils.mint_fuzzer(),
    grab_a_policy_from_mint,
  ),
) {
  let (random_policy, random_mint) = random_policy_and_mint
  let tx =
    Transaction {
      ..placeholder,
      mint: random_mint,
      redeemers: [Pair(Mint(random_policy), builtin.i_data(0))],
    }
  spend(random_policy, fn(_r_data) { True }, fn(_tn_qty_dict) { True }, tx)
}

test fail_spend(
  random_policy_and_mint via fuzz.and_then(
    utils.mint_fuzzer(),
    grab_a_policy_from_mint,
  ),
) {
  let (random_policy, random_mint) = random_policy_and_mint
  let tx =
    Transaction {
      ..placeholder,
      mint: random_mint,
      redeemers: [Pair(Mint(random_policy), builtin.i_data(0))],
    }
  // Hashing to get a different policy
  let hashed_policy = blake2b_224(random_policy)
  spend(hashed_policy, fn(_r_data) { True }, fn(_tn_qty_dict) { True }, tx)
}

test success_spend_minimal(script_hash via fuzz.bytearray_fixed(28)) {
  let tx =
    Transaction { ..placeholder, mint: assets.from_asset(script_hash, #"", 1) }
  spend_minimal(script_hash, tx)
}

test fail_spend_minimal(script_hash via fuzz.bytearray_fixed(28)) fail {
  let tx =
    Transaction { ..placeholder, mint: assets.from_asset(script_hash, #"", 1) }
  // Hashing to get a different script hash
  let expected_mint_script_hash = blake2b_224(script_hash)
  spend_minimal(expected_mint_script_hash, tx)
}
