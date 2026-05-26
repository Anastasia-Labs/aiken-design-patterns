//// This module extends `aiken_design_patterns/linked_list` for two-level
//// linked lists.
////
//// A nested list uses one list NFT policy and one spend script, but its datum
//// can represent three element kinds:
////
//// 1. `Root` anchors the outer list.
//// 2. `InnerRoot` is a node in the outer list and the root of one inner list.
//// 3. `Node` belongs to an inner list beneath an `InnerRoot`.
////
//// Use the default module's documentation for the base linked-list model,
//// authentication rules, and namespace requirements. This module differs in
//// the following ways:
////
//// 1. `InnerRoot` and `Node` NFTs both live in the node-key namespace; their
////    datum constructors determine their roles.
//// 2. Element UTxOs may carry reference scripts. Continued structural anchors
////    preserve their reference scripts, and callbacks receive produced
////    reference scripts where the produced UTxO itself is not supplied.
//// 3. Mint helpers may expose additional same-policy assets as
////    `OtherListAssets`, while node insertion helpers reserve the node-key
////    namespace for structural list NFTs.
//// 4. The outer list can be ordered by `InnerRoot` keys, and each inner list can
////    independently be ascending, descending, or unordered.

use aiken/collection/dict
use aiken/crypto.{ScriptHash}
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list.{
  ElementEval, Link, LovelaceChange, NodeEval, NodeKey, NodeKeyPrefix,
  NodeKeyPrefixLength, RootEval, RootKey,
}
use aiken_design_patterns/linked_list/advanced.{
  OtherListAssets, validate_no_other_node_key_prefixes_minted,
}
use aiken_design_patterns/linked_list/internal.{
  authenticate_element_utxo_and_get_info_helper, is_only_mint_under_policy,
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

pub type GenericElement =
  Element<Data, Data, Data>

pub type GenericElementData =
  ElementData<Data, Data, Data>

pub fn init(
  nonce_validated: Bool,
  produced_element_output: Output,
  tx_mint: Value,
  root_validator: fn(Lovelace, Data, Option<ScriptHash>) -> Bool,
) -> RootEval<Bool> {
  // 1. Helper guardrail for caller-provided nonce validation.
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

    // 5. Asset name of the authentication NFT must match root key.
    expect element_asset_name == root_key

    // 6. Root NFT must be the only asset minted under the list policy.
    expect
      is_only_mint_under_policy(
        tx_mint,
        list_nft_policy_id,
        element_asset_name,
        1,
      )

    // 7. Produced root must not have a link.
    expect element_link == None

    // 8. Custom validation must pass.
    expect root_validator(element_lovelace, root_data, element_ref_script)

    // Done.
    True
  }
}

pub fn deinit(
  inputs: List<Input>,
  tx_mint: Value,
  root_validator: fn(Input, Lovelace, Data) -> Bool,
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
      _element_ref_script,
    <- validate_singular_authentic_input(inputs, list_nft_policy_id)

    // 2. Contained data must be `Root`.
    expect Root { data: root_data }: GenericElementData = element_data

    // 3. Root NFT must be burnt, with no other mints/burns other list policy.
    expect
      is_only_mint_under_policy(
        tx_mint,
        list_nft_policy_id,
        element_asset_name,
        -1,
      )

    // 4. The authentication NFT must use the root key.
    expect element_asset_name == root_key

    // 5. Spent root must have no links/children.
    expect element_link == None

    // 6. Custom validation must pass.
    expect root_validator(element_input, element_lovelace, root_data)

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
      // 1. Root anchors must use the root key.
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

/// Folds through the given list of outputs, expecting them to be in correct
/// order (within the linked list structure), and for each node, validates the
/// provided `node_validator` callback, and "pops" the expected NFT from
/// `remaining_minted_list_assets`. Finally returns the remaining list minted
/// assets, number of outputs, last node's key (`None` if the list was empty),
/// and final caller-provided state.
fn validate_inner_node_outputs(
  list_nft_policy_id: PolicyId,
  node_key_prefix: NodeKeyPrefix,
  node_key_prefix_length: NodeKeyPrefixLength,
  anchor_payment_credential: PaymentCredential,
  ordering_of_inner_node_keys: ListOrdering,
  inner_root_child_link: Link,
  inner_node_outputs: List<Output>,
  remaining_minted_list_assets: OtherListAssets,
  initial_state: state,
  node_validator: fn(
    state,
    Int,
    Lovelace,
    NodeKey,
    Data,
    Link,
    Option<ScriptHash>,
  ) ->
    state,
  return: fn(OtherListAssets, Int, Option<NodeKey>, state) -> result,
) -> result {
  // 1. Fold through all provided children once, carrying mint leftovers,
  //    expected link, count, last key, and caller-provided state.
  let
    remaining_minted_list_assets,
    final_expected_link,
    inner_node_count,
    last_inner_node_key,
    final_state,
  <-
    scott_list.foldl5(
      inner_node_outputs,
      remaining_minted_list_assets,
      inner_root_child_link,
      0,
      None,
      initial_state,
      fn(
        node_output,
        remaining_minted_list_assets,
        expected_link,
        inner_node_count,
        last_inner_node_key,
        state,
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

        // 2. Each child must share the anchor payment credential.
        expect anchor_payment_credential == node_address.payment_credential

        // 3. Each child's asset name must be under the node namespace.
        expect
          bytearray.take(node_asset_name, node_key_prefix_length) == node_key_prefix

        let node_key = bytearray.drop(node_asset_name, node_key_prefix_length)

        // 4. Children must point to one another in the provided output order.
        expect expected_link == Some(node_key)

        // 5. Child keys follow the requested order unless unordered.
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

        // 6. Each child output must carry a `Node` datum.
        expect Node { data: node_data } = node_element_data

        // 7. Each child output must have a corresponding mint entry.
        let (node_mint_qty, remaining_minted_list_assets) =
          remaining_minted_list_assets |> dict.expect_pop(node_asset_name)

        expect node_mint_qty == 1

        // 8. Custom per-node validation updates the caller-provided state.
        // 9. Pass the next expected link, last key, count, and state.
        return(
          remaining_minted_list_assets,
          node_link,
          inner_node_count + 1,
          Some(node_key),
          node_validator(
            state,
            inner_node_count,
            node_lovelace,
            node_key,
            node_data,
            node_link,
            node_ref_script,
          ),
        )
      },
    )

  // 10. The last child must terminate the inner list.
  expect final_expected_link == None
  return(
    remaining_minted_list_assets,
    inner_node_count,
    last_inner_node_key,
    final_state,
  )
}

pub type ListOrdering {
  Ascending
  Descending
  Unordered
}

/// Branch selector for callbacks that need anchor-specific information during
/// inner-list insertion. The first handler receives `InnerRoot` anchor info
/// (key, data); the second receives `Node` anchor info (key, data). The
/// previous inner-list link is provided separately as the new node's link.
pub type InnerListAnchor<result> =
  fn(fn(NodeKey, Data, Link) -> result, fn(NodeKey, Data) -> result) -> result

/// Helper to be used in a minting endpoint. For insertions into an inner list
/// only.
///
/// The `additional_validations` callback is provided with:
/// 1. `Input` of the anchor element (`InnerRoot` or `Node`)
/// 2. Change in Lovelace count from anchor input to continued anchor output
/// 3. Branch selector for anchor-specific data. Its first handler receives the
///    inner-root key, data and outer link. Its second handler receives the node
///    key and data.
/// 4. Lovelace count of the new node UTxO
/// 5. Key (i.e. asset name without the prefix) of the new node
/// 6. Underlying data of the new node
/// 7. `Link` of the new node. This is the anchor's previous inner-list link:
///    the inner root's previous `child_link`, or the anchor node's previous
///    `link`.
/// 8. Reference script of the new node, if present
/// 9. Same-policy mints outside the node-key namespace
pub fn insert_into_inner_list(
  ordering_of_inner_node_keys: ListOrdering,
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: fn(
    Input,
    LovelaceChange,
    InnerListAnchor<Bool>,
    Lovelace,
    NodeKey,
    Data,
    Link,
    Option<ScriptHash>,
    OtherListAssets,
  ) ->
    Bool,
) -> NodeEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
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

    // 3. Provided output for the new node must be authentic.
    let
      new_node_address,
      new_node_lovelace,
      new_node_asset_name,
      new_node_element_data,
      new_node_link,
      new_node_ref_script,
    <-
      authenticate_element_utxo_and_get_info(
        new_node_output,
        list_nft_policy_id,
      )

    // 4. Anchor element must be continued at the same address.
    expect anchor_element_address == cont_anchor_element_address

    // 5. Inserted node must share payment credential with the anchor element.
    expect
      anchor_element_address.payment_credential == new_node_address.payment_credential

    // 6. Anchor element's NFT and reference script must be preserved.
    expect anchor_element_asset_name == cont_anchor_element_asset_name
    expect anchor_element_ref_script == cont_anchor_element_ref_script

    // 7. The new node's asset name must be under the node namespace.
    expect
      bytearray.take(new_node_asset_name, node_key_prefix_length) == node_key_prefix

    let new_node_key =
      bytearray.drop(new_node_asset_name, node_key_prefix_length)

    let anchor_element_lovelace_change =
      cont_anchor_element_lovelace - anchor_element_lovelace

    // 8. Produced node element must have `Node` data.
    expect Node { data: new_node_data } = new_node_element_data

    // 9. The new node's NFT must be minted.
    let other_minted_list_assets =
      validate_list_nft_and_get_other_list_assets(
        tx_mint,
        list_nft_policy_id,
        new_node_asset_name,
        1,
      )

    // 10. Additional same-policy mints must not be in the node-key namespace.
    expect
      validate_no_other_node_key_prefixes_minted(
        other_minted_list_assets,
        node_key_prefix,
        node_key_prefix_length,
      )

    when anchor_element_data is {
      Root { .. } -> fail @"Root cannot anchor an inner-list insertion"
      InnerRoot { data: inner_root_data, child_link } -> {
        // 11a. Inner-root anchors must live under the node namespace.
        expect
          bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix

        let inner_root_key =
          bytearray.drop(anchor_element_asset_name, node_key_prefix_length)

        // 12a. Continuing the inner root must only update its child link.
        expect
          cont_anchor_element_data == InnerRoot {
            data: inner_root_data,
            child_link: Some(new_node_key),
          }
        expect cont_anchor_element_link == anchor_element_link

        // 13a. The new node must point to the inner root's previous first child.
        expect new_node_link == child_link

        // 14a. New node's key must be positioned correctly inside the inner list.
        expect
          when ordering_of_inner_node_keys is {
            Unordered -> True
            Ascending ->
              when child_link is {
                None -> True
                Some(child_link_key) ->
                  bytearray.compare(new_node_key, child_link_key) == Less
              }
            Descending ->
              when child_link is {
                None -> True
                Some(child_link_key) ->
                  bytearray.compare(new_node_key, child_link_key) == Greater
              }
          }

        // 15a. Custom validation must pass.
        additional_validations(
          anchor_element_input,
          anchor_element_lovelace_change,
          fn(on_inner_root, _on_node) {
            on_inner_root(inner_root_key, inner_root_data, anchor_element_link)
          },
          new_node_lovelace,
          new_node_key,
          new_node_data,
          new_node_link,
          new_node_ref_script,
          other_minted_list_assets,
        )
      }
      Node { data: anchor_node_data } -> {
        // 11b. Node anchors must live under the node namespace.
        expect
          bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix

        let anchor_node_key =
          bytearray.drop(anchor_element_asset_name, node_key_prefix_length)

        // 12b. Continuing a node anchor must preserve data and point to the new node.
        expect cont_anchor_element_data == anchor_element_data
        expect cont_anchor_element_link == Some(new_node_key)

        // 13b. The new node must point to what the anchor used to link to.
        expect new_node_link == anchor_element_link

        // 14b. New node's key must be positioned correctly inside the inner list.
        expect
          when ordering_of_inner_node_keys is {
            Unordered -> True
            Ascending ->
              when anchor_element_link is {
                None -> bytearray.compare(anchor_node_key, new_node_key) == Less
                Some(anchor_element_link_key) -> and {
                    bytearray.compare(anchor_node_key, new_node_key) == Less,
                    bytearray.compare(new_node_key, anchor_element_link_key) == Less,
                  }
              }
            Descending ->
              when anchor_element_link is {
                None ->
                  bytearray.compare(anchor_node_key, new_node_key) == Greater
                Some(anchor_element_link_key) -> and {
                    bytearray.compare(anchor_node_key, new_node_key) == Greater,
                    bytearray.compare(new_node_key, anchor_element_link_key) == Greater,
                  }
              }
          }

        // 15b. Custom validation must pass.
        additional_validations(
          anchor_element_input,
          anchor_element_lovelace_change,
          fn(_on_inner_root, on_node) {
            on_node(anchor_node_key, anchor_node_data)
          },
          new_node_lovelace,
          new_node_key,
          new_node_data,
          new_node_link,
          new_node_ref_script,
          other_minted_list_assets,
        )
      }
    }
  }
}

/// Mint a whole inner list while inserting its `InnerRoot` into the outer list
/// in ascending order. The spent anchor can only be the outer `Root` or an
/// existing `InnerRoot`.
///
/// The ordering of the inserted inner list's `Node`s is controlled by
/// `ordering_of_inner_node_keys`.
///
/// `node_validator` runs for each provided inner-node output and receives:
/// 1. Current caller-provided state
/// 2. Index of the node output in `inner_node_outputs`
/// 3. Lovelace count of the node output
/// 4. Node key
/// 5. Underlying node data
/// 6. Node link
/// 7. Node reference script, if present
///
/// It returns the next state to pass to the following node. If there are no
/// inner-node outputs, `additional_validations` receives `initial_state`.
///
/// `additional_validations` receives:
/// 1. Anchor element input
/// 2. Change in Lovelace count from anchor input to continued anchor output
/// 3. Anchor key (`None` when the anchor is `Root`)
/// 4. Underlying anchor data
/// 5. Anchor link, which becomes the new inner root's outer link
/// 6. Lovelace count of the inserted inner root output
/// 7. Key of the inserted inner root
/// 8. Underlying data of the inserted inner root
/// 9. Child link of the inserted inner root
/// 10. Inserted inner root reference script, if present
/// 11. Number of nodes in the inserted inner list
/// 12. Key of the inserted inner list's last node, or `None` if it is empty
/// 13. Final state returned by the node fold
/// 14. Remaining same-policy mints outside the node-key namespace
pub fn ascending_insert_of_inner_list(
  ordering_of_inner_node_keys: ListOrdering,
  continued_anchor_element_output: Output,
  new_inner_root_output: Output,
  inputs: List<Input>,
  inner_node_outputs: List<Output>,
  tx_mint: Value,
  initial_state: state,
  node_validator: fn(
    state,
    Int,
    Lovelace,
    NodeKey,
    Data,
    Link,
    Option<ScriptHash>,
  ) ->
    state,
  additional_validations: fn(
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
    state,
    OtherListAssets,
  ) ->
    Bool,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    ordered_insert_of_inner_list_helper(
      list_nft_policy_id,
      root_key,
      node_key_prefix,
      node_key_prefix_length,
      Less,
      ordering_of_inner_node_keys,
      continued_anchor_element_output,
      new_inner_root_output,
      inputs,
      inner_node_outputs,
      tx_mint,
      initial_state,
      node_validator,
      additional_validations,
    )
  }
}

/// Like [`ascending_insert_of_inner_list`](#ascending_insert_of_inner_list), but
/// inserts the new `InnerRoot` into a descending outer list.
pub fn descending_insert_of_inner_list(
  ordering_of_inner_node_keys: ListOrdering,
  continued_anchor_element_output: Output,
  new_inner_root_output: Output,
  inputs: List<Input>,
  inner_node_outputs: List<Output>,
  tx_mint: Value,
  initial_state: state,
  node_validator: fn(
    state,
    Int,
    Lovelace,
    NodeKey,
    Data,
    Link,
    Option<ScriptHash>,
  ) ->
    state,
  additional_validations: fn(
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
    state,
    OtherListAssets,
  ) ->
    Bool,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    ordered_insert_of_inner_list_helper(
      list_nft_policy_id,
      root_key,
      node_key_prefix,
      node_key_prefix_length,
      Greater,
      ordering_of_inner_node_keys,
      continued_anchor_element_output,
      new_inner_root_output,
      inputs,
      inner_node_outputs,
      tx_mint,
      initial_state,
      node_validator,
      additional_validations,
    )
  }
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
  initial_state: state,
  node_validator: fn(
    state,
    Int,
    Lovelace,
    NodeKey,
    Data,
    Link,
    Option<ScriptHash>,
  ) ->
    state,
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
    state,
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

  // 6. Anchor element's NFT, data, and reference script must be preserved.
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

  // 12. The new inner root's NFT must be minted. Remaining same-policy mints
  //     are carried into inner-node validation.
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
    final_state,
  <-
    validate_inner_node_outputs(
      list_nft_policy_id,
      node_key_prefix,
      node_key_prefix_length,
      anchor_payment_credential,
      ordering_of_inner_node_keys,
      inner_root_child_link,
      inner_node_outputs,
      remaining_minted_list_assets,
      initial_state,
      node_validator,
    )

  // 13. Additional same-policy mints must not be in the node-key namespace.
  expect
    validate_no_other_node_key_prefixes_minted(
      final_remaining_minted_list_assets,
      node_key_prefix,
      node_key_prefix_length,
    )

  // 14. Custom validation must pass.
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
    final_state,
    final_remaining_minted_list_assets,
  )
}
