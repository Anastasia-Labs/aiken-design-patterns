//// @hidden
//// This module contains logic shared by the linked list modules. It is not
//// meant to be used directly.

use aiken/collection/dict
use aiken/crypto.{ScriptHash}
use aiken/primitive/bytearray
use aiken_design_patterns/utils.{get_lovelace_and_single_nft_name}
use cardano/address.{Address}
use cardano/assets.{AssetName, Lovelace, PolicyId, Value}
use cardano/transaction.{InlineDatum, Output}

/// Authenticate an inline-datum singleton list-element UTxO.
///
/// The output must contain exactly ADA plus one NFT under `nft_policy_id`.
/// The NFT quantity must be one. The datum must be inline. On success, the
/// continuation receives:
/// - the output address,
/// - the Lovelace quantity,
/// - the NFT asset name, which is the element key at the caller layer,
/// - the raw inline datum data,
/// - and the optional reference script hash.
///
/// This helper authenticates the `Output` value it receives; it does not prove
/// that the value was selected from `ScriptContext.transaction.outputs`.
/// Public linked-list mint helpers rely on callers to pass outputs selected
/// from the transaction body, using whatever selection method suits the
/// surrounding validator.
pub fn authenticate_element_utxo_and_get_info_helper(
  element_utxo: Output,
  nft_policy_id: PolicyId,
  return: fn(Address, Lovelace, AssetName, Data, Option<ScriptHash>) -> result,
) -> result {
  expect  
      Output {
        address: output_address,
        value,
        datum: InlineDatum(utxo_datum_data),
        reference_script,
      }
    = element_utxo

  let lovelace_count, nft_name <- get_lovelace_and_single_nft_name(
    value,
    nft_policy_id,
  )

  return(
    output_address,
    lovelace_count,
    nft_name,
    utxo_datum_data,
    reference_script,
  )
}

/// Validate that the given asset is the only asset minted or burned under its
/// policy, with the expected quantity.
///
/// This is used by strict mint helpers such as root initialization,
/// deinitialization, and the default node insert/remove operations. Advanced
/// structural operations use
/// `validate_list_nft_and_get_remaining_same_policy_asset_changes`
/// instead when they intentionally permit additional same-policy assets that
/// are outside the reserved root key and node namespace.
pub fn is_only_mint_under_policy(
  tx_mint: Value,
  policy_id: PolicyId,
  asset_name: AssetName,
  expected_quantity: Int,
) -> Bool {
  expect Some(actual_minted_assets) = assets.to_dict(tx_mint)
    |> dict.get(policy_id)
  expect [Pair(actual_asset_name, actual_quantity)] = dict.to_pairs(
    actual_minted_assets,
  )

  // 1. Exactly the expected asset name changes under this policy.
  expect actual_asset_name == asset_name

  // 2. Its quantity must match the expected mint/burn amount.
  expect actual_quantity == expected_quantity

  // Done.
  True
}

/// Validate that `new_key` fits between optional neighboring keys.
///
/// For `Less`, the checked neighbors must satisfy `previous < new` and
/// `new < next`; for `Greater`, they must satisfy `previous > new` and
/// `new > next`. Missing neighbors are accepted and represent list boundaries.
/// The comparison is bytearray lexicographic ordering, so callers that encode
/// numeric keys must use a fixed-width representation when numeric ordering is
/// intended.
pub fn key_fits_between(
  required_ordering: Ordering,
  previous_key: Option<ByteArray>,
  new_key: ByteArray,
  next_key: Option<ByteArray>,
) -> Bool {
  // 1. If a previous key exists, it must be ordered before/after the new key.
  expect
    when previous_key is {
      None -> True
      Some(key) -> bytearray.compare(key, new_key) == required_ordering
    }

  // 2. If a next key exists, the new key must be ordered before/after it.
  expect
    when next_key is {
      None -> True
      Some(key) -> bytearray.compare(new_key, key) == required_ordering
    }

  True
}
