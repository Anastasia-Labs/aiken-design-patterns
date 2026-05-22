use aiken/collection/dict
use aiken/crypto.{ScriptHash}
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list.{
  Link, LovelaceChange, NodeKey, NodeKeyPrefix, NodeKeyPrefixLength, RootEval,
  RootKey,
}
use aiken_design_patterns/linked_list/advanced.{
  OtherListAssets, validate_no_other_node_key_prefixes_minted,
}
use aiken_design_patterns/linked_list/internal.{
  authenticate_element_utxo_and_get_info_helper,
  validate_list_nft_and_get_other_list_assets,
  validate_singular_authentic_input_helper,
}
use aiken_scott_utils/list as scott_list
use cardano/address.{Address, PaymentCredential}
use cardano/assets.{AssetName, Lovelace, PolicyId, Value}
use cardano/transaction.{Input, Output}

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
  root_validator: fn(Lovelace, OtherListAssets, Data, Option<ScriptHash>) ->
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
  root_validator: fn(Input, Lovelace, OtherListAssets, Data, Option<ScriptHash>) ->
    Bool,
) -> RootEval<Bool> {
  fn(list_nft_policy_id: PolicyId, root_key: RootKey) -> Bool {
    // 1. There must be exactly one input with the list's NFT.
    let
      element_input,
      _element_address,
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
    Address,
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
      let Input {
        output: Output {
          address: element_address,
          reference_script: element_ref_script,
          ..
        },
        ..
      } = element_input

      expect Element { data, link }: GenericElement = element_datum_data
      return(
        element_input,
        element_address,
        element_lovelace,
        element_asset_name,
        data,
        link,
        element_ref_script,
      )
    },
  )
}

fn with_anchor_element_info(
  anchor_element_data: GenericElementData,
  anchor_element_asset_name: AssetName,
  root_key: RootKey,
  node_key_prefix: NodeKeyPrefix,
  node_key_prefix_length: NodeKeyPrefixLength,
  return: fn(Option<NodeKey>, Data) -> result,
) -> result {
  when anchor_element_data is {
    Root { data: root_data } -> {
      // 1. Root anchors must use the hardcoded root key.
      expect anchor_element_asset_name == root_key
      return(None, root_data)
    }
    InnerRoot { data: inner_root_data, .. } -> {
      // 2. Inner-root anchors must live under the node namespace.
      expect
        bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix
      return(
        Some(bytearray.drop(anchor_element_asset_name, node_key_prefix_length)),
        inner_root_data,
      )
    }
    // 3. Outer list cannot have `Node` elements.
    Node { .. } -> fail @"Anchor must be either Root or InnerRoot"
  }
}

fn validate_inner_node_outputs(
  list_nft_policy_id: PolicyId,
  anchor_payment_credential: PaymentCredential,
  ordering_of_inner_node_keys: ListOrdering,
  node_key_prefix: NodeKeyPrefix,
  node_key_prefix_length: NodeKeyPrefixLength,
  inner_root_child_link: Link,
  inner_node_outputs: List<Output>,
  remaining_minted_list_assets: OtherListAssets,
  node_validator: fn(Int, Lovelace, NodeKey, Data, Link, Option<ScriptHash>) ->
    Bool,
  return: fn(OtherListAssets, Int, Option<NodeKey>) -> result,
) -> result {
  when inner_root_child_link is {
    None -> {
      // 1. If the inner root has no first child, no child outputs are expected.
      expect [] = inner_node_outputs
      return(remaining_minted_list_assets, 0, None)
    }
    Some(inner_roots_first_child) -> {
      // 2. Fold through all provided children once, carrying mint leftovers,
      //    expected link, count, and last key.
      let
        remaining_minted_list_assets,
        final_expected_link,
        inner_node_count,
        last_inner_node_key,
      <-
        scott_list.foldl4(
          inner_node_outputs,
          remaining_minted_list_assets,
          Some(inner_roots_first_child),
          0,
          None,
          fn(
            node_output,
            remaining_minted_list_assets,
            expected_link,
            inner_node_count,
            last_inner_node_key,
            return,
          ) {
            let
              node_address,
              node_lovelace,
              node_asset_name,
              node_element_data,
              node_link,
              node_ref_script,
            <-
              authenticate_element_utxo_and_get_info(
                node_output,
                list_nft_policy_id,
              )

            // 3. Each child must share the anchor payment credential.
            expect anchor_payment_credential == node_address.payment_credential

            // 4. Each child's asset name must be under the node namespace.
            expect
              bytearray.take(node_asset_name, node_key_prefix_length) == node_key_prefix

            let node_key =
              bytearray.drop(node_asset_name, node_key_prefix_length)

            // 5. Children must point to one another in the provided output order.
            expect expected_link == Some(node_key)

            // 6. Child keys follow the requested order unless `Equal` opts out.
            expect
              when last_inner_node_key is {
                None -> True
                Some(previous_node_key) ->
                  when ordering_of_inner_node_keys is {
                    Ascending ->
                      bytearray.compare(previous_node_key, node_key) == Less
                    Descending ->
                      bytearray.compare(previous_node_key, node_key) == Greater
                    Unordered -> True
                  }
              }

            // 7. Each child output must carry a `Node` datum.
            expect Node { data: node_data } = node_element_data

            // 8. Each child output must have a corresponding mint entry.
            let (node_mint_qty, remaining_minted_list_assets) =
              remaining_minted_list_assets |> dict.expect_pop(node_asset_name)

            expect node_mint_qty == 1

            // 9. Custom per-node validation must pass.
            expect
              node_validator(
                inner_node_count,
                node_lovelace,
                node_key,
                node_data,
                node_link,
                node_ref_script,
              )

            // 10. Pass the next expected link, last key, and count.
            return(
              remaining_minted_list_assets,
              node_link,
              inner_node_count + 1,
              Some(node_key),
            )
          },
        )

      // 11. The last child must terminate the inner list.
      expect final_expected_link == None
      return(
        remaining_minted_list_assets,
        inner_node_count,
        last_inner_node_key,
      )
    }
  }
}

pub type ListOrdering {
  Ascending
  Descending
  Unordered
}

fn ordered_insert_of_inner_list_helper(
  list_nft_policy_id: PolicyId,
  root_key: RootKey,
  node_key_prefix: NodeKeyPrefix,
  node_key_prefix_length: NodeKeyPrefixLength,
  ordering_of_new_key_vs_anchors_link: Ordering,
  ordering_of_inner_node_keys: ListOrdering,
  continued_anchor_element_output: Output,
  new_inner_root_output: Output,
  inputs: List<Input>,
  inner_node_outputs: List<Output>,
  tx_mint: Value,
  node_validator: fn(Int, Lovelace, NodeKey, Data, Link, Option<ScriptHash>) ->
    Bool,
  callback: fn(
    Input,
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Link,
    Lovelace,
    NodeKey,
    Data,
    Link,
    Option<ScriptHash>,
    Int,
    Option<NodeKey>,
    OtherListAssets,
  ) ->
    Bool,
) -> Bool {
  // 1. Inputs list must carry exactly one UTxO with the list NFT.
  let
    anchor_element_input,
    anchor_element_address,
    anchor_element_lovelace,
    anchor_element_asset_name,
    anchor_element_data,
    anchor_element_link,
    anchor_element_ref_script,
  <- validate_singular_authentic_input(inputs, list_nft_policy_id)

  let Address { payment_credential: anchor_payment_credential, .. } =
    anchor_element_address

  // 2. Provided output for the continued anchor must be authentic.
  let
    cont_anchor_element_address,
    cont_anchor_element_lovelace,
    cont_anchor_element_asset_name,
    cont_anchor_element_data,
    cont_anchor_element_link,
    cont_anchor_element_ref_script,
  <-
    authenticate_element_utxo_and_get_info(
      continued_anchor_element_output,
      list_nft_policy_id,
    )

  // 3. Provided output for the new inner root must be authentic.
  let
    new_inner_root_address,
    new_inner_root_lovelace,
    new_inner_root_asset_name,
    new_inner_root_element_data,
    new_inner_root_link,
    new_inner_root_ref_script,
  <-
    authenticate_element_utxo_and_get_info(
      new_inner_root_output,
      list_nft_policy_id,
    )

  // 4. Anchor element must be continued at the same address.
  expect anchor_element_address == cont_anchor_element_address

  // 5. New inner root must share payment credential with the anchor element.
  expect anchor_payment_credential == new_inner_root_address.payment_credential

  // 6. Anchor element's NFT and data must be preserved.
  expect anchor_element_asset_name == cont_anchor_element_asset_name
  expect anchor_element_data == cont_anchor_element_data
  expect anchor_element_ref_script == cont_anchor_element_ref_script

  let
    anchor_key,
    anchor_data,
  <-
    with_anchor_element_info(
      anchor_element_data,
      anchor_element_asset_name,
      root_key,
      node_key_prefix,
      node_key_prefix_length,
    )

  let anchor_element_lovelace_change =
    cont_anchor_element_lovelace - anchor_element_lovelace

  // 7. New inner root's asset name must be under the node namespace.
  expect
    bytearray.take(new_inner_root_asset_name, node_key_prefix_length) == node_key_prefix

  let new_inner_root_key =
    bytearray.drop(new_inner_root_asset_name, node_key_prefix_length)

  // 8. New inner root's key must be positioned correctly after the anchor and
  //    before the anchor's previous link.
  expect
    when anchor_key is {
      None ->
        when anchor_element_link is {
          None -> True
          Some(anchor_element_link_key) ->
            bytearray.compare(new_inner_root_key, anchor_element_link_key) == ordering_of_new_key_vs_anchors_link
        }
      Some(anchor_inner_root_key) ->
        when anchor_element_link is {
          None ->
            bytearray.compare(anchor_inner_root_key, new_inner_root_key) == ordering_of_new_key_vs_anchors_link
          Some(anchor_element_link_key) -> and {
              bytearray.compare(anchor_inner_root_key, new_inner_root_key) == ordering_of_new_key_vs_anchors_link,
              bytearray.compare(new_inner_root_key, anchor_element_link_key) == ordering_of_new_key_vs_anchors_link,
            }
        }
    }

  // 9. Reproduced anchor element must point to the new inner root.
  expect cont_anchor_element_link == Some(new_inner_root_key)

  // 10. The new inner root must point to what the anchor element used to link to.
  expect new_inner_root_link == anchor_element_link

  // 11. Produced inner-root element must have `InnerRoot` data.
  expect InnerRoot { data: inner_root_data, child_link: inner_root_child_link } =
    new_inner_root_element_data

  // 12. The new inner root's NFT must be minted.
  let remaining_minted_list_assets =
    validate_list_nft_and_get_other_list_assets(
      tx_mint,
      list_nft_policy_id,
      new_inner_root_asset_name,
      1,
    )

  let
    final_remaining_minted_list_assets,
    inner_node_count,
    last_inner_node_key,
  <-
    validate_inner_node_outputs(
      list_nft_policy_id,
      anchor_payment_credential,
      ordering_of_inner_node_keys,
      node_key_prefix,
      node_key_prefix_length,
      inner_root_child_link,
      inner_node_outputs,
      remaining_minted_list_assets,
      node_validator,
    )

  expect
    validate_no_other_node_key_prefixes_minted(
      final_remaining_minted_list_assets,
      node_key_prefix,
      node_key_prefix_length,
    )

  callback(
    anchor_element_input,
    anchor_element_lovelace_change,
    anchor_key,
    anchor_data,
    anchor_element_link,
    new_inner_root_lovelace,
    new_inner_root_key,
    inner_root_data,
    inner_root_child_link,
    new_inner_root_ref_script,
    inner_node_count,
    last_inner_node_key,
    final_remaining_minted_list_assets,
  )
}
