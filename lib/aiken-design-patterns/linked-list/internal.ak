//// @hidden
//// This module contains datatypes and logic shared by the linked list modules.
//// These are not meant to be used directly.

use aiken/builtin
use aiken/collection/dict.{Dict}
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken/primitive/bytearray
use aiken_design_patterns/utils.{get_lovelace_and_single_nft_name}
use cardano/address.{Address, Credential}
use cardano/assets.{AssetName, Lovelace, PolicyId, Value}
use cardano/transaction.{Datum, InlineDatum, Input, Output, OutputReference}

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
  expect Output {
    address: output_address,
    value,
    datum: InlineDatum(utxo_datum_data),
    reference_script,
  } = element_utxo

  let
    lovelace_count,
    nft_name,
  <- get_lovelace_and_single_nft_name(value, nft_policy_id)

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
/// structural operations use `validate_list_nft_and_get_other_list_assets`
/// instead when they intentionally permit additional same-policy assets that are
/// outside the reserved root key and node namespace.
pub fn is_only_mint_under_policy(
  tx_mint: Value,
  policy_id: PolicyId,
  asset_name: AssetName,
  expected_quantity: Int,
) -> Bool {
  expect Some(actual_minted_assets) =
    assets.to_dict(tx_mint)
      |> dict.get(policy_id)
  expect [Pair(actual_asset_name, actual_quantity)] =
    dict.to_pairs(actual_minted_assets)

  // 1. Exactly the expected asset name changes under this policy.
  expect actual_asset_name == asset_name

  // 2. Its quantity must match the expected mint/burn amount.
  expect actual_quantity == expected_quantity
  True
}

/// Validate the expected structural NFT mint/burn and return other assets under
/// the same policy.
///
/// The returned dictionary is the same-policy remainder after removing
/// `expected_nft_name`. Callers must still decide whether those additional
/// changes are allowed. Advanced linked-list helpers immediately reject any
/// returned asset whose name is reserved for the root or falls inside the
/// node-key namespace, then pass the remainder to application callbacks.
pub fn validate_list_nft_and_get_other_list_assets(
  v: Value,
  expected_nft_policy: PolicyId,
  expected_nft_name: AssetName,
  expected_nft_qty: Int,
) -> Dict<AssetName, Int> {
  let (name_qty_dict, _rest_of_policies) =
    v
      |> assets.to_dict
      |> dict.expect_pop(expected_nft_policy)
  let (nft_qty, rest_of_names) =
    name_qty_dict
      |> dict.expect_pop(expected_nft_name)
  expect nft_qty == expected_nft_qty
  rest_of_names
}

/// Same-policy asset quantities left after removing the structural node NFT
/// from transaction mint/burn validation.
///
/// Positive quantities are mints and negative quantities are burns.
pub type OtherListAssets =
  Dict<AssetName, Int>

/// Validates that additional same-policy asset changes do not use reserved list
/// asset names. Applies to both mints and burns.
///
/// A remaining same-policy asset whose name starts with `node_key_prefix` would
/// collide with the list node namespace. A remaining asset whose name equals
/// `root_key` would collide with the list root NFT. Rejecting both here lets
/// advanced callers allow unrelated same-policy assets without weakening the
/// structural root/node-key invariants.
pub fn validate_no_reserved_list_asset_changes(
  other_list_asset_changes: OtherListAssets,
  root_key: AssetName,
  node_key_prefix: AssetName,
  node_key_prefix_length: Int,
) -> Bool {
  other_list_asset_changes
    |> dict.foldr(
        True,
        fn(asset_name, _qty, so_far) {
          // 1. Extra same-policy changes must not mint or burn the root NFT.
          expect asset_name != root_key

          // 2. Extra same-policy changes must stay outside the node namespace.
          expect
            bytearray.take(asset_name, node_key_prefix_length) != node_key_prefix
          so_far
        },
      )
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

type InternalInputInfo =
  fn(Input, Lovelace, AssetName, Data) -> Bool

/// Goes through the input list and performs the given validation at the first
/// authentic linked-list element input. After that, it rejects any later input
/// that has the candidate linked-list element shape and uses the same list NFT
/// policy.
///
/// The narrow shape check is intentional. A valid linked-list element UTxO is
/// guaranteed to contain only ADA plus its single element NFT; `Value` entries
/// coming from inputs and outputs are also guaranteed to list ADA first. So once
/// the authentic input has been found, a later input can only be another
/// authentic element candidate if its value is exactly ADA plus one non-ADA
/// policy. Inputs with any other value shape are not linked-list element UTxOs
/// under this API's invariants, and this helper must not pay to classify them
/// with a broader policy scan.
pub fn validate_singular_authentic_input_helper(
  inputs: List<Input>,
  nft_policy_id: PolicyId,
  return: InternalInputInfo,
) -> Bool {
  let nft_policy_id_data: Data = builtin.b_data(nft_policy_id)
  let i, input_found <- list.foldr(inputs, False)

  let i_output = i.output
  let i_value = i_output.value

  if input_found {
    let value_unmapped: List<Pair<Data, Data>> = builtin.un_map_data(i_value)

    let input_non_ada_assets_pairs = value_unmapped |> builtin.tail_list

    when input_non_ada_assets_pairs is {
      [policy_name_pair] -> {
        // If the singular list element has been found already and the input has
        // only one other asset apart from ADA, the only requirement is that
        // it must not be of the same policy ID as the linked list's.
        expect policy_name_pair.1st != nft_policy_id_data
        input_found
      }
      _ ->
        // Any other shape for the input value is acceptable since we are
        // assuming linked list UTxOs cannot carry assets other than ADA and
        // their NFTs.
        input_found
    }
  } else {
    validate_input_for_nft(
      nft_policy_id_data,
      i,
      i_output,
      i_value,
      input_found,
      return,
    )
  }
}

/// Break down a list-shaped input value through its `Data` encoding.
fn validate_input_for_nft(
  nft_policy_id_data: Data,
  current_input: Input,
  current_output: Output,
  current_value: Value,
  fold_acc: Bool,
  return: InternalInputInfo,
) -> Bool {
  let current_value_pairs: List<Pair<Data, Data>> =
    builtin.un_map_data(current_value)

  let current_non_ada_asset_pairs = current_value_pairs |> builtin.tail_list

  when current_non_ada_asset_pairs is {
    [policy_asset_names_pair] ->
      if policy_asset_names_pair.1st == nft_policy_id_data {
        let
          current_lovelace,
          nft_name,
          datum_data,
        <-
          internal_input_processor_validator(
            current_output.datum,
            current_value_pairs,
            policy_asset_names_pair.2nd,
          )

        // Using `expect` to enforce the encountered authentic input validate
        // caller provided logic.
        expect return(current_input, current_lovelace, nft_name, datum_data)

        True
      } else {
        fold_acc
      }
    _ -> fold_acc
  }
}

/// Validate the NFT quantity pair and extract Lovelace plus inline datum data.
fn internal_input_processor_validator(
  current_datum: Datum,
  current_value_pairs: List<Pair<Data, Data>>,
  names_qty_pairs_data: Data,
  return: fn(Lovelace, AssetName, Data) -> res,
) -> res {
  expect [nft_name_qty_pair] = builtin.un_map_data(names_qty_pairs_data)

  let nft_name = nft_name_qty_pair.1st |> builtin.un_b_data()

  expect nft_name_qty_pair.2nd == builtin.i_data(1)

  let current_lovelace_pair =
    builtin.head_list(current_value_pairs).2nd
      |> builtin.un_map_data
      |> builtin.head_list

  let current_lovelace = current_lovelace_pair.2nd |> builtin.un_i_data()

  expect InlineDatum(current_datum_data) = current_datum

  return(current_lovelace, nft_name, current_datum_data)
}

// Authentic input fold state:
// zero: none found
// one: input, payment credential, lovelace, asset name, datum
// two: dedicated list payment credential for the accepted pair
// The public API requires the list payment credential to be dedicated to list
// UTxOs, so unrelated same-credential inputs are invalid transaction
// construction rather than inputs this state machine must classify. Once one
// authentic input has established the credential, a same-credential second input
// must be the matching list input, and after two are accepted any further input
// at that credential is invalid.
type AuthenticInputFoldState =
  fn(
    fn() -> Bool,
    fn(Input, Credential, Lovelace, AssetName, Data) -> Bool,
    fn(Credential) -> Bool,
  ) ->
    Bool

/// Validate exactly two authentic list inputs using a compact fold state.
///
/// This is an internal building block exported only so the linked-list variant
/// modules can share one implementation. Contract validators should strongly
/// prefer the public helpers in `linked_list`, `linked_list/advanced`, or
/// `linked_list/nested`; calling this directly means taking responsibility for
/// all surrounding list-credential and mint-policy invariants.
///
/// The list payment credential must be dedicated to list inputs. That means the
/// surrounding transaction must not spend unrelated same-credential inputs at
/// all, even if they do not carry the list NFT. After one authentic list input
/// has been found, a later input at the same payment credential is treated as
/// the required second list input and must authenticate as such. After the pair
/// is accepted, any additional input at that credential is rejected. This helper
/// does not scan arbitrary other payment credentials for extra same-policy list
/// NFTs; sharing a list policy across spend credentials is outside the supported
/// API model.
///
/// `anchor_input_outref` selects which of the two found authentic inputs is the
/// anchor. The callback receives the selected anchor first and the other
/// authentic input second. If neither found input has that output reference,
/// validation fails.
pub fn validate_dual_authentic_inputs_helper(
  anchor_input_outref: OutputReference,
  inputs: List<Input>,
  nft_policy_id: PolicyId,
  with: fn(Input, Lovelace, AssetName, Data, Input, Lovelace, AssetName, Data) ->
    Bool,
) -> Bool {
  let nft_policy_id_data = builtin.b_data(nft_policy_id)

  let final_inputs_found: AuthenticInputFoldState =
    list.foldr(
      inputs,
      fn(when_none_found, _when_one_found, _when_two_found) {
        when_none_found()
      },
      fn(current_input, inputs_found) {
        fn(when_none_found, when_one_found, when_two_found) {
          let Input {
            output: current_output,
            output_reference: current_output_reference,
          } = current_input
          let Output {
            address: current_address,
            value: current_value,
            datum: current_datum,
            ..
          } = current_output
          let Address { payment_credential: current_payment_credential, .. } =
            current_address

          // Fold state branches: none found, one found, two found.
          inputs_found(
            fn() {
              let value_unmapped: List<Pair<Data, Data>> =
                builtin.un_map_data(current_value)

              let non_ada_assets_pairs = value_unmapped |> builtin.tail_list

              when non_ada_assets_pairs is {
                [policy_name_pair] ->
                  if policy_name_pair.1st == nft_policy_id_data {
                    let
                      i_lovelace,
                      i_nft_name,
                      i_datum_data,
                    <-
                      internal_input_processor_validator(
                        current_datum,
                        value_unmapped,
                        policy_name_pair.2nd,
                      )

                    when_one_found(
                      current_input,
                      current_payment_credential,
                      i_lovelace,
                      i_nft_name,
                      i_datum_data,
                    )
                  } else {
                    when_none_found()
                  }
                _ -> when_none_found()
              }
            },
            fn(
              first_seen_input: Input,
              first_seen_payment_cred: Credential,
              first_seen_lovelace: Lovelace,
              first_seen_nft_name: AssetName,
              first_seen_datum_data: Data,
            ) {
              if first_seen_payment_cred == current_payment_credential {
                let current_value_unmapped: List<Pair<Data, Data>> =
                  builtin.un_map_data(current_value)

                expect [current_policy_name_pair] =
                  current_value_unmapped
                    |> builtin.tail_list

                expect current_policy_name_pair.1st == nft_policy_id_data

                let
                  current_lovelace,
                  current_nft_name,
                  current_datum_data,
                <-
                  internal_input_processor_validator(
                    current_datum,
                    current_value_unmapped,
                    current_policy_name_pair.2nd,
                  )

                // Select the found input whose output reference matches
                // `anchor_input_outref` as the anchor. The callback receives that
                // anchor first and the other authentic input second.
                let Input { output_reference: first_seen_output_reference, .. } =
                  first_seen_input

                expect
                  if first_seen_output_reference == anchor_input_outref {
                    with(
                      first_seen_input,
                      first_seen_lovelace,
                      first_seen_nft_name,
                      first_seen_datum_data,
                      current_input,
                      current_lovelace,
                      current_nft_name,
                      current_datum_data,
                    )
                  } else {
                    expect current_output_reference == anchor_input_outref
                    with(
                      current_input,
                      current_lovelace,
                      current_nft_name,
                      current_datum_data,
                      first_seen_input,
                      first_seen_lovelace,
                      first_seen_nft_name,
                      first_seen_datum_data,
                    )
                  }

                when_two_found(first_seen_payment_cred)
              } else {
                when_one_found(
                  first_seen_input,
                  first_seen_payment_cred,
                  first_seen_lovelace,
                  first_seen_nft_name,
                  first_seen_datum_data,
                )
              }
            },
            fn(list_payment_credential) {
              expect current_payment_credential != list_payment_credential
              when_two_found(list_payment_credential)
            },
          )
        }
      },
    )

  final_inputs_found(
    fn() { False },
    fn(_, _, _, _, _) { False },
    fn(_) { True },
  )
}
