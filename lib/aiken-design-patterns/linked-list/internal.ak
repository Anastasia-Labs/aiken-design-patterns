//// @hidden
//// This module contains datatypes and logic shared by the linked list modules.
//// These are not meant to be used directly.

use aiken/builtin
use aiken/collection/dict.{Dict}
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use cardano/address.{Address, Credential}
use cardano/assets.{AssetName, Lovelace, PolicyId, Value}
use cardano/transaction.{Datum, InlineDatum, Input, Output, OutputReference}

/// Given a UTxO (`Output`), this function authenticates it by checking it
/// contains only one NFT (apart from ADA) whose policy ID matches the provided
/// one, and its quantity equals one
///
/// Upon successful authentication, it returns the following information about
/// the element:
/// - Its address
/// - Its Lovelace count
/// - Its NFT's asset name (i.e. element's key)
/// - Its inline datum data
/// - Its reference script (if any)
pub fn authenticate_element_utxo_and_get_info_helper(
  element_utxo: Output,
  nft_policy_id: PolicyId,
  return: fn(Address, Lovelace, AssetName, Data, Option<ScriptHash>) -> result,
) -> result {
  // 1. Its datum must be inlined; its reference script is returned if present.
  expect Output {
    address: output_address,
    value,
    datum: InlineDatum(utxo_datum_data),
    reference_script,
  } = element_utxo

  // 2. Apart from ADA, only one NFT must be included in the UTxO, such that its
  //    policy ID matches the provided one, and its quantity equals one.
  expect [(_, _, lovelace_count),
    (nft_symbol, nft_name, nft_qty)] = assets.flatten(value)
  expect and {
      nft_symbol == nft_policy_id,
      nft_qty == 1,
    }

  return(
    output_address,
    lovelace_count,
    nft_name,
    utxo_datum_data,
    reference_script,
  )
}

/// Validates that the given asset is the only asset minted or burnt under its
/// policy, with the expected quantity.
pub fn is_only_mint_under_policy(
  tx_mint: Value,
  policy_id: PolicyId,
  asset_name: AssetName,
  expected_quantity: Int,
) -> Bool {
  expect Some(actual_minted_assets) =
    assets.to_dict(tx_mint) |> dict.get(policy_id)
  expect [Pair(actual_asset_name, actual_quantity)] =
    dict.to_pairs(actual_minted_assets)
  and {
    actual_asset_name == asset_name,
    actual_quantity == expected_quantity,
  }
}

/// Validates the expected structural NFT mint/burn and returns other assets
/// under the same policy.
pub fn validate_list_nft_and_get_other_list_assets(
  v: Value,
  expected_nft_policy: PolicyId,
  expected_nft_name: AssetName,
  expected_nft_qty: Int,
) -> Dict<AssetName, Int> {
  let (name_qty_dict, _rest_of_policies) =
    v |> assets.to_dict |> dict.expect_pop(expected_nft_policy)
  let (nft_qty, rest_of_names) =
    name_qty_dict |> dict.expect_pop(expected_nft_name)
  expect nft_qty == expected_nft_qty
  rest_of_names
}

type InternalInputInfo<result> =
  fn(Input, Lovelace, AssetName, Data) -> result

/// Goes through the input list and performs the given validation at its first
/// encounter with the authentic input. After that, if it encounters any other UTxO
/// with a linked list NFT policy ID, it fails.
///
/// An important assumption here is that no authentic linked list element UTxO
/// can carry tokens other than ADA and its NFT. So it only checks for absence
/// of list NFT if the input's value has the same shape (namely, only ADA with
/// one other policy ID).
pub fn validate_singular_authentic_input_helper(
  inputs: List<Input>,
  nft_policy_id: PolicyId,
  return: InternalInputInfo<Bool>,
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
    process_input_for_nft(
      nft_policy_id_data,
      i,
      i_output,
      i_value,
      input_found,
      return,
    )
  }
}

/// An internal helper for breaking down a `Value` through `Data` encoding and
/// builtin functions.
fn process_input_for_nft(
  nft_policy_id_data: Data,
  i: Input,
  i_output: Output,
  i_value: Value,
  fold_acc: acc,
  return: InternalInputInfo<acc>,
) -> acc {
  let v_unmapped: List<Pair<Data, Data>> = builtin.un_map_data(i_value)

  let v_non_ada_assets_pairs = v_unmapped |> builtin.tail_list

  when v_non_ada_assets_pairs is {
    [policy_name_pair] ->
      if policy_name_pair.1st == nft_policy_id_data {
        let
          i_lovelace,
          nft_name,
          datum_data,
        <-
          internal_input_processor_validator(
            i_output.datum,
            v_unmapped,
            policy_name_pair.2nd,
          )

        return(i, i_lovelace, nft_name, datum_data)
      } else {
        fold_acc
      }
    _ -> fold_acc
  }
}

/// Shared internal logic for singular and dual input validators. This is used
/// for validating a given list of "asset name - quantity" pairs (as `Data`)
/// matches correctly to expected shape for list elements.
///
/// It also requires the prior unmapped version of the original `Value` so that
/// it can extract the Lovelace count as well.
fn internal_input_processor_validator(
  i_datum: Datum,
  v_unmapped: List<Pair<Data, Data>>,
  names_qty_pairs_data: Data,
  return: fn(Lovelace, AssetName, Data) -> res,
) -> res {
  expect [nft_name_qty_pair] = builtin.un_map_data(names_qty_pairs_data)

  let nft_name = nft_name_qty_pair.1st |> builtin.un_b_data()

  // Element NFT quantity must equal one.
  expect nft_name_qty_pair.2nd == builtin.i_data(1)

  let i_lovelace_pair =
    builtin.head_list(v_unmapped).2nd
      |> builtin.un_map_data
      |> builtin.head_list

  let i_lovelace = i_lovelace_pair.2nd |> builtin.un_i_data()

  expect InlineDatum(i_datum_data) = i_datum

  return(i_lovelace, nft_name, i_datum_data)
}

type InputsFoundScott =
  fn(
    fn() -> Bool,
    fn(Input, Credential, Lovelace, AssetName, Data) -> Bool,
    fn() -> Bool,
  ) ->
    Bool

/// Validate exactly two authentic list inputs using a Scott-encoded fold state.
/// This assumes the list payment credential is dedicated to list inputs; any
/// additional same-payment input is invalid even if it does not carry a list
/// NFT.
///
/// Implementation note: the fold is intentionally asymmetric for budget reasons.
/// After one authentic list input has been found, a later input at the same
/// payment credential is treated as the expected second list input and must
/// authenticate as such. Therefore, non-authentic same-payment inputs can cause
/// order-dependent rejection. This is desirable: callers must not include them.
///
/// The fold accumulator is an eliminator for the three possible states:
/// - no authentic input found
/// - one authentic input found
/// - two authentic inputs found
pub fn validate_dual_authentic_inputs_helper(
  anchor_input_outref: OutputReference,
  inputs: List<Input>,
  nft_policy_id: PolicyId,
  with: fn(Input, Lovelace, AssetName, Data, Input, Lovelace, AssetName, Data) ->
    Bool,
) -> Bool {
  let nft_policy_id_data = builtin.b_data(nft_policy_id)

  let final_inputs_found: InputsFoundScott =
    list.foldr(
      inputs,
      fn(on_none, _on_one, _on_two) { on_none() },
      fn(i, inputs_found) {
        fn(on_none, on_one, on_two) {
          let i_output = i.output

          inputs_found(
            fn() {
              let value_unmapped: List<Pair<Data, Data>> =
                builtin.un_map_data(i_output.value)

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
                        i_output.datum,
                        value_unmapped,
                        policy_name_pair.2nd,
                      )

                    on_one(
                      i,
                      i_output.address.payment_credential,
                      i_lovelace,
                      i_nft_name,
                      i_datum_data,
                    )
                  } else {
                    on_none()
                  }
                _ -> on_none()
              }
            },
            fn(
              i0_input: Input,
              i0_payment_cred: Credential,
              i0_lovelace: Lovelace,
              i0_nft_name: AssetName,
              i0_datum_data: Data,
            ) {
              let Output { address: i_address, value: i_value, .. } = i_output

              if i0_payment_cred == i_address.payment_credential {
                let i1_value_unmapped: List<Pair<Data, Data>> =
                  builtin.un_map_data(i_value)

                expect [i1_policy_name_pair] =
                  i1_value_unmapped |> builtin.tail_list

                expect i1_policy_name_pair.1st == nft_policy_id_data

                let
                  i1_lovelace,
                  i1_nft_name,
                  i1_datum_data,
                <-
                  internal_input_processor_validator(
                    i_output.datum,
                    i1_value_unmapped,
                    i1_policy_name_pair.2nd,
                  )

                expect
                  if i0_input.output_reference == anchor_input_outref {
                    with(
                      i0_input,
                      i0_lovelace,
                      i0_nft_name,
                      i0_datum_data,
                      i,
                      i1_lovelace,
                      i1_nft_name,
                      i1_datum_data,
                    )
                  } else {
                    expect i.output_reference == anchor_input_outref
                    with(
                      i,
                      i1_lovelace,
                      i1_nft_name,
                      i1_datum_data,
                      i0_input,
                      i0_lovelace,
                      i0_nft_name,
                      i0_datum_data,
                    )
                  }

                on_two()
              } else {
                on_one(
                  i0_input,
                  i0_payment_cred,
                  i0_lovelace,
                  i0_nft_name,
                  i0_datum_data,
                )
              }
            },
            fn() {
              let value_unmapped = builtin.un_map_data(i_output.value)

              let input_non_ada_assets_pairs =
                value_unmapped |> builtin.tail_list

              when input_non_ada_assets_pairs is {
                [policy_name_pair] -> {
                  expect policy_name_pair.1st != nft_policy_id_data
                  on_two()
                }
                _ -> on_two()
              }
            },
          )
        }
      },
    )

  final_inputs_found(fn() { False }, fn(_, _, _, _, _) { False }, fn() { True })
}
