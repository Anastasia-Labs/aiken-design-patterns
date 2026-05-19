use aiken/builtin
use aiken/collection/dict.{Dict}
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list/internal.{
  Eval, Link, LovelaceChange, NodeData, NodeKey, NodeKeyPrefix,
  NodeKeyPrefixLength, RootData, RootEval, RootKey,
  authenticate_element_utxo_and_get_info_helper,
  validate_singular_authentic_input_helper,
}
use aiken_design_patterns/singular_utxo_indexer
use cardano/address.{Address, Credential}
use cardano/assets.{AssetName, Lovelace, PolicyId, Value}
use cardano/transaction.{Datum, InlineDatum, Input, Output, OutputReference}

pub type Element<root_data, inner_root_data, node_data> {
  data: ElementData<root_data, inner_root_data, node_data>,
  link: Link,
}

pub type ElementData<root_data, inner_root_data, node_data> {
  Root { data: root_data }
  InnerRoot { data: inner_root_data, child_link: Link }
  Node { data: node_data }
}

type GenericElement =
  Element<Data, Data, Data>

type GenericElementData =
  ElementData<Data, Data, Data>

pub fn init(
  nonce_validated: Bool,
  produced_element_output: Output,
  tx_mint: Value,
  root_validator: fn(Lovelace, Dict<AssetName, Int>, Data, Option<ScriptHash>) ->
    Bool,
) -> RootEval<Bool> {
  // 1. Helper guardrail to remind nonce validation logic.
  expect nonce_validated

  fn(list_nft_policy_id: PolicyId, root_key: RootKey) -> Bool {
    // 2. The produced UTxO must only contain the authentication/key NFT.
    // 3. Its datum must be properly structured.
    let
      _element_address,
      element_lovelace,
      element_asset_name,
      element_data,
      element_link,
      element_ref_script,
    <-
      authenticate_element_utxo_and_get_info(
        produced_element_output,
        list_nft_policy_id,
      )

    // 4. Contained data must be `Root`.
    expect Root { data: root_data } = element_data

    // 5. The authentication NFT must have the root's hardcoded name.
    expect element_asset_name == root_key

    // 6. Root NFT must be minted.
    let other_minted_list_assets =
      validate_list_nft_and_get_other_list_assets(
        tx_mint,
        list_nft_policy_id,
        element_asset_name,
        1,
      )

    // 7. Produced root must not have a link.
    expect element_link == None

    // 4. Custom validation must pass.
    expect
      root_validator(
        element_lovelace,
        other_minted_list_assets,
        root_data,
        element_ref_script,
      )

    // Done.
    True
  }
}

pub fn deinit(
  inputs: List<Input>,
  tx_mint: Value,
  root_validator: fn(
    Input,
    Lovelace,
    Dict<AssetName, Int>,
    Data,
    Option<ScriptHash>,
  ) ->
    Bool,
) -> RootEval<Bool> {
  fn(list_nft_policy_id: PolicyId, root_key: RootKey) -> Bool {
    // 1. There must be exactly one input with the list's NFT.
    let
      element_input,
      element_lovelace,
      element_asset_name,
      element_data,
      element_link,
      element_ref_script,
    <- validate_singular_authentic_input(inputs, list_nft_policy_id)

    // 2. Contained data must be `Root`.
    expect Root { data: root_data }: GenericElementData = element_data

    // 3. Root NFT must be the only asset burnt under its policy.
    let other_minted_list_assets =
      validate_list_nft_and_get_other_list_assets(
        tx_mint,
        list_nft_policy_id,
        element_asset_name,
        -1,
      )

    // 4. The authentication NFT must have the root's hardcoded name.
    expect element_asset_name == root_key

    // 5. Spent root must have no links/children.
    expect element_link == None

    // 6. Custom validation must pass.
    expect
      root_validator(
        element_input,
        element_lovelace,
        other_minted_list_assets,
        root_data,
        element_ref_script,
      )

    // Done.
    True
  }
}

fn authenticate_element_utxo_and_get_info(
  element_utxo: Output,
  nft_policy_id: PolicyId,
  return: fn(
    Address,
    Lovelace,
    AssetName,
    GenericElementData,
    Link,
    Option<ScriptHash>,
  ) ->
    result,
) -> result {
  let
    output_address,
    lovelace_count,
    nft_name,
    utxo_datum_data,
    output_ref_script,
  <- authenticate_element_utxo_and_get_info_helper(element_utxo, nft_policy_id)

  // 1. UTxO's datum must be properly structured.
  expect Element { data, link }: GenericElement = utxo_datum_data

  return(
    output_address,
    lovelace_count,
    nft_name,
    data,
    link,
    output_ref_script,
  )
}

fn validate_singular_authentic_input(
  inputs: List<Input>,
  nft_policy_id: PolicyId,
  return: fn(
    Input,
    Lovelace,
    AssetName,
    GenericElementData,
    Link,
    Option<ScriptHash>,
  ) ->
    Bool,
) -> Bool {
  validate_singular_authentic_input_helper(
    inputs,
    nft_policy_id,
    fn(element_input, element_lovelace, element_asset_name, element_datum_data) {
      expect Element { data, link }: GenericElement = element_datum_data
      return(
        element_input,
        element_lovelace,
        element_asset_name,
        data,
        link,
        element_input.output.reference_script,
      )
    },
  )
}

fn validate_list_nft_and_get_other_list_assets(
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
