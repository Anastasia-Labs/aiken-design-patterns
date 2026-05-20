//// This module extends `aiken_design_patterns/linked_list` while reusing its
//// element type, key aliases, reader aliases, runner functions, and structural
//// invariants.
////
//// Use the default module's documentation for the base linked-list model. This
//// module differs in two ways:
////
//// 1. Elements may carry reference scripts. Continued structural anchors must
////    preserve their reference scripts. Callbacks receive reference scripts
////    only when the corresponding UTxO itself is not already provided.
//// 2. Structural mint/burn operations may include additional assets under the
////    list NFT policy. The required structural NFT is still validated, and the
////    remaining same-policy asset changes are passed to custom validators as
////    `OtherListAssets`.
////
//// For nested-list semantics, use the dedicated nested module rather than this
//// generic advanced surface.

use aiken/collection/dict.{Dict}
use aiken/crypto.{ScriptHash}
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list.{
  ElementEval, GenericElementData, Link, LovelaceChange, Node, NodeData,
  NodeEval, NodeKey, NodeKeyPrefix, NodeKeyPrefixLength, Root, RootData,
  RootEval, RootKey, authenticate_element_utxo_and_get_info,
  validate_dual_authentic_inputs, validate_singular_authentic_input,
}
use aiken_design_patterns/linked_list/internal.{
  validate_list_nft_and_get_other_list_assets,
}
use aiken_design_patterns/singular_utxo_indexer
use cardano/assets.{AssetName, Lovelace, PolicyId, Value}
use cardano/transaction.{Input, Output, OutputReference}

/// Same-policy assets left after removing the structural list NFT from
/// transaction mint/burn validation.
pub type OtherListAssets =
  Dict<AssetName, Int>

// ## Initialization and De-initialization

/// Like the default module's `init`, but the custom validator also receives
/// any non-structural same-policy mints and the produced root's reference
/// script.
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

    // 6. Root NFT must be minted under its policy. Any remaining same-policy
    //    mint is exposed to the custom validator.
    let other_minted_list_assets =
      validate_list_nft_and_get_other_list_assets(
        tx_mint,
        list_nft_policy_id,
        element_asset_name,
        1,
      )

    // 7. Produced root must not have a link.
    expect element_link == None

    // 8. Custom validation must pass.
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

/// Like the default module's `deinit`, but the custom validator also receives
/// any non-structural same-policy mint/burns.
pub fn deinit(
  inputs: List<Input>,
  tx_mint: Value,
  root_validator: fn(Input, Lovelace, OtherListAssets, Data) -> Bool,
) -> RootEval<Bool> {
  fn(list_nft_policy_id: PolicyId, root_key: RootKey) -> Bool {
    // 1. There must be exactly one input with the list's NFT.
    let
      element_input,
      element_lovelace,
      element_asset_name,
      element_data,
      element_link,
    <- validate_singular_authentic_input(inputs, list_nft_policy_id)

    // 2. Contained data must be `Root`.
    expect Root { data: root_data } = element_data

    // 3. Root NFT must be burnt under its policy. Any remaining same-policy
    //    mint/burn is exposed to the custom validator.
    let other_minted_list_assets =
      validate_list_nft_and_get_other_list_assets(
        tx_mint,
        list_nft_policy_id,
        element_asset_name,
        -1,
      )

    // 4. Custom validation must pass.
    expect
      root_validator(
        element_input,
        element_lovelace,
        other_minted_list_assets,
        root_data,
      )

    // 5. The authentication NFT must have the root's hardcoded name.
    expect element_asset_name == root_key

    // 6. Spent root must have no links/children.
    expect element_link == None

    // Done.
    True
  }
}

// ## Element Addition and Removal

/// Like the default module's `insert_ascending`, but the callback also receives
/// the new node reference script and non-structural same-policy mints.
pub fn insert_ascending(
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: fn(
    Input,
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
    Option<ScriptHash>,
    OtherListAssets,
  ) ->
    Bool,
) -> ElementEval<Bool> {
  insert_ordered(
    Less,
    continued_anchor_element_output,
    new_node_output,
    inputs,
    tx_mint,
    additional_validations,
  )
}

/// Like the default module's `insert_descending`, but with the same extra
/// callback values as [`insert_ascending`](#insert_ascending).
pub fn insert_descending(
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: fn(
    Input,
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
    Option<ScriptHash>,
    OtherListAssets,
  ) ->
    Bool,
) -> ElementEval<Bool> {
  insert_ordered(
    Greater,
    continued_anchor_element_output,
    new_node_output,
    inputs,
    tx_mint,
    additional_validations,
  )
}

/// Like the default module's `append_unordered`, but the callback also receives
/// the new node reference script and non-structural same-policy mints.
pub fn append_unordered(
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: fn(
    Input,
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Lovelace,
    NodeKey,
    NodeData,
    Option<ScriptHash>,
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
    let
      anchor_element_input,
      anchor_element_lovelace_change,
      anchor_element_asset_name,
      anchor_element_data,
      anchor_element_link,
      new_node_lovelace,
      _new_node_asset_name,
      new_node_key,
      new_node_data,
      _new_node_link,
      new_node_ref_script,
      other_minted_list_assets,
    <-
      common_insertion_validations(
        list_nft_policy_id,
        node_key_prefix,
        node_key_prefix_length,
        continued_anchor_element_output,
        new_node_output,
        inputs,
        tx_mint,
      )

    // 1. Input anchor element and the new node must both be the last elements
    //    of the list (equality is already checked).
    expect anchor_element_link == None

    when anchor_element_data is {
      Root { data: root_data } -> {
        // 2a. Token name of the anchor element must be identical to the
        //     constant `root_key`.
        expect anchor_element_asset_name == root_key

        // 3a. Custom validation against the spent anchor element and the new
        //     node must pass.
        expect
          additional_validations(
            anchor_element_input,
            anchor_element_lovelace_change,
            None,
            root_data,
            new_node_lovelace,
            new_node_key,
            new_node_data,
            new_node_ref_script,
            other_minted_list_assets,
          )

        // Done.
        True
      }
      Node { data: anchor_node_data } -> {
        // 2b. The anchor node's key must start with the provided label.
        expect
          bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix

        // 3b. Custom validation against the spent anchor element and the new
        //     node must pass.
        expect
          additional_validations(
            anchor_element_input,
            anchor_element_lovelace_change,
            Some(
              bytearray.drop(anchor_element_asset_name, node_key_prefix_length),
            ),
            anchor_node_data,
            new_node_lovelace,
            new_node_key,
            new_node_data,
            new_node_ref_script,
            other_minted_list_assets,
          )

        // Done.
        True
      }
    }
  }
}

/// Like the default module's `prepend_unordered`, but the callback also
/// receives the new node reference script and non-structural same-policy mints.
pub fn prepend_unordered(
  continued_root_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: fn(
    Input,
    LovelaceChange,
    RootData,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
    Option<ScriptHash>,
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
    let
      root_element_input,
      root_lovelace_change,
      root_element_asset_name,
      root_element_data,
      _root_element_link,
      new_node_lovelace,
      _new_node_asset_name,
      new_node_key,
      new_node_data,
      new_node_link,
      new_node_ref_script,
      other_minted_list_assets,
    <-
      common_insertion_validations(
        list_nft_policy_id,
        node_key_prefix,
        node_key_prefix_length,
        continued_root_element_output,
        new_node_output,
        inputs,
        tx_mint,
      )

    // 1. Anchor element's data must be `Root`.
    expect Root { data: root_data } = root_element_data

    // 2. Asset name of the root element must be identical to the constant
    //    `root_key`.
    expect root_element_asset_name == root_key

    // 3. Custom validation against the spent root element and the new node
    //    must pass.
    expect
      additional_validations(
        root_element_input,
        root_lovelace_change,
        root_data,
        new_node_lovelace,
        new_node_key,
        new_node_data,
        new_node_link,
        new_node_ref_script,
        other_minted_list_assets,
      )

    // Done.
    True
  }
}

/// Like the default module's `remove`, but the callback also receives
/// non-structural same-policy mint/burns. Reference scripts for spent elements
/// are available through the provided `Input`s.
pub fn remove(
  anchor_input_outref: OutputReference,
  continued_anchor_element_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: fn(
    Input,
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Input,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
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
    let
      anchor_input,
      anchor_lovelace,
      anchor_asset_name,
      anchor_element_data,
      anchor_link,
      removing_node_input,
      removing_node_lovelace,
      removing_node_asset_name,
      removing_node_element_data,
      removing_node_link,
    <-
      validate_dual_authentic_inputs(
        anchor_input_outref,
        inputs,
        list_nft_policy_id,
      )

    let
      cont_anchor_address,
      cont_anchor_lovelace,
      cont_anchor_asset_name,
      cont_anchor_element_data,
      cont_anchor_link,
      cont_anchor_ref_script,
    <-
      authenticate_element_utxo_and_get_info(
        continued_anchor_element_output,
        list_nft_policy_id,
      )

    let anchor_element_lovelace_change = cont_anchor_lovelace - anchor_lovelace

    let removing_node_key =
      bytearray.drop(removing_node_asset_name, node_key_prefix_length)

    // 3. Anchor continuation must be proper and preserve list's structure.
    expect cont_anchor_address == anchor_input.output.address
    expect cont_anchor_asset_name == anchor_asset_name
    expect cont_anchor_element_data == anchor_element_data
    expect cont_anchor_ref_script == anchor_input.output.reference_script

    // 4. Removing element's `ElementData` must be `Node`.
    expect Node { data: removing_node_data } = removing_node_element_data

    // 5. The removing node's NFT must be burnt under its policy. Any remaining
    //    same-policy mint/burn is exposed to the custom validator.
    let other_minted_list_assets =
      validate_list_nft_and_get_other_list_assets(
        tx_mint,
        list_nft_policy_id,
        removing_node_asset_name,
        -1,
      )

    // 6. Anchor element must point to the node being removed.
    expect anchor_link == Some(removing_node_key)

    // 7. Reproduced anchor element must point to what the removed node pointed
    //    to.
    expect cont_anchor_link == removing_node_link

    // 8. Asset name of the removing node must have the expected label.
    expect
      bytearray.take(removing_node_asset_name, node_key_prefix_length) == node_key_prefix

    when anchor_element_data is {
      Root { data: root_data } -> {
        // 9a. Token name of the anchor element must be identical to the
        //     constant `root_key`.
        expect anchor_asset_name == root_key

        // 10a. Custom validation against the spent anchor element and the
        //      removing node must pass.
        expect
          additional_validations(
            anchor_input,
            anchor_element_lovelace_change,
            None,
            root_data,
            removing_node_input,
            removing_node_lovelace,
            removing_node_key,
            removing_node_data,
            removing_node_link,
            other_minted_list_assets,
          )

        // Done.
        True
      }
      Node { data: anchor_node_data } -> {
        // 9b. The anchor node's key must start with the provided label.
        expect
          bytearray.take(anchor_asset_name, node_key_prefix_length) == node_key_prefix

        // 10b. Custom validation against the spent anchor element and the
        //      removing node must pass.
        expect
          additional_validations(
            anchor_input,
            anchor_element_lovelace_change,
            Some(bytearray.drop(anchor_asset_name, node_key_prefix_length)),
            anchor_node_data,
            removing_node_input,
            removing_node_lovelace,
            removing_node_key,
            removing_node_data,
            removing_node_link,
            other_minted_list_assets,
          )

        // Done.
        True
      }
    }
  }
}

// ## Fold Functions

/// Like the default module's `fold_from_root`, but the callback also receives
/// non-structural same-policy mint/burns. Reference scripts for spent elements
/// are available through the provided `Input`s.
pub fn fold_from_root(
  anchor_root_input_outref: OutputReference,
  continued_anchor_root_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: fn(
    Input,
    LovelaceChange,
    RootData,
    Input,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
    RootData,
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
    let
      anchor_root_input,
      anchor_root_lovelace,
      anchor_root_asset_name,
      anchor_root_element_data,
      anchor_root_link,
      folding_node_input,
      folding_node_lovelace,
      folding_node_asset_name,
      folding_node_element_data,
      folding_node_link,
    <-
      validate_dual_authentic_inputs(
        anchor_root_input_outref,
        inputs,
        list_nft_policy_id,
      )

    // 1. The anchor element has to be a `Root`.
    expect Root { data: anchor_root_data } = anchor_root_element_data

    let
      cont_anchor_root_address,
      cont_anchor_root_lovelace,
      cont_anchor_root_asset_name,
      cont_anchor_root_element_data,
      cont_anchor_root_link,
      cont_anchor_root_ref_script,
    <-
      authenticate_element_utxo_and_get_info(
        continued_anchor_root_output,
        list_nft_policy_id,
      )

    let folding_node_key =
      folding_node_asset_name |> bytearray.drop(node_key_prefix_length)

    // 2. The folding element has to be a `Node`.
    expect Node { data: folding_node_data } = folding_node_element_data

    // 3. Continued anchor data must remain a `Root`.
    expect Root { data: cont_anchor_root_data } = cont_anchor_root_element_data

    // 4. Folding node's NFT must be burnt under its policy. Any remaining
    //    same-policy mint/burn is exposed to the custom validator.
    let other_minted_list_assets =
      validate_list_nft_and_get_other_list_assets(
        tx_mint,
        list_nft_policy_id,
        folding_node_asset_name,
        -1,
      )

    // 5. Anchor root is reproduced properly.
    expect anchor_root_input.output.address == cont_anchor_root_address
    expect anchor_root_asset_name == cont_anchor_root_asset_name
    expect
      anchor_root_input.output.reference_script == cont_anchor_root_ref_script

    // 6. Folding node is the anchor root's link.
    expect anchor_root_link == Some(folding_node_key)

    // 7. Reproduced root points to the link folding node pointed to.
    expect cont_anchor_root_link == folding_node_link

    // 8. Asset name of the anchor root must match the `root_key`.
    expect anchor_root_asset_name == root_key

    // 9. Asset name of the folding node must have the expected label.
    expect
      bytearray.take(folding_node_asset_name, node_key_prefix_length) == node_key_prefix

    // 10. Custom validation passes.
    expect
      additional_validations(
        anchor_root_input,
        cont_anchor_root_lovelace - anchor_root_lovelace,
        anchor_root_data,
        folding_node_input,
        folding_node_lovelace,
        folding_node_key,
        folding_node_data,
        folding_node_link,
        cont_anchor_root_data,
        other_minted_list_assets,
      )

    // Done.
    True
  }
}

// ## Spending Script Helpers

/// Like the default module's `spend_for_updating_elements_data`, but the
/// callback receives the input and output reference scripts. As with the
/// default helper, no list-policy mint/burn is allowed for a pure data update.
pub fn spend_for_updating_elements_data(
  element_input_index: Int,
  continued_element_output_index: Int,
  element_input_outref: OutputReference,
  inputs: List<Input>,
  outputs: List<Output>,
  tx_mint: Value,
  additional_validations: fn(
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Option<ScriptHash>,
    Data,
    Option<ScriptHash>,
    Link,
  ) ->
    Bool,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    let
      element_input,
      continued_element_output,
    <-
      singular_utxo_indexer.one_to_one(
        element_input_index,
        continued_element_output_index,
        element_input_outref,
        inputs,
        outputs,
        // Preventing double satisfaction by ensuring no tokens are minted/burnt
        // with the same policy as the linked list's NFT.
        dict.is_empty(tx_mint |> assets.tokens(list_nft_policy_id)),
      )
    let
      elem_address,
      elem_lovelace,
      elem_asset_name,
      elem_data,
      elem_link,
      elem_ref_script,
    <-
      authenticate_element_utxo_and_get_info(
        element_input.output,
        list_nft_policy_id,
      )
    let
      cont_elem_address,
      cont_elem_lovelace,
      cont_elem_asset_name,
      cont_elem_data,
      cont_elem_link,
      cont_elem_ref_script,
    <-
      authenticate_element_utxo_and_get_info(
        continued_element_output,
        list_nft_policy_id,
      )
    expect and {
        // 1. Element must be reproduced at the same address.
        elem_address == cont_elem_address,
        // 2. Element must preserve its NFT.
        elem_asset_name == cont_elem_asset_name,
        // 3. Element's link must remain unchanged.
        elem_link == cont_elem_link,
      }
    let lovelace_change = cont_elem_lovelace - elem_lovelace
    when elem_data is {
      Root { data } -> {
        // 4a. Element's data must remain as `Root`.
        expect Root { data: continued_data } = cont_elem_data
        and {
          // 5a. Root key must match properly.
          elem_asset_name == root_key,
          // 6a. User's custom validation must pass.
          additional_validations(
            lovelace_change,
            None,
            data,
            elem_ref_script,
            continued_data,
            cont_elem_ref_script,
            elem_link,
          ),
        }
      }
      Node { data } -> {
        // 4b. Element's data must remain as `Node`.
        expect Node { data: continued_data } = cont_elem_data
        and {
          // 5b. Element's key prefix must match properly.
          bytearray.take(elem_asset_name, node_key_prefix_length) == node_key_prefix,
          // 6b. User's custom validation must pass.
          additional_validations(
            lovelace_change,
            Some(bytearray.drop(elem_asset_name, node_key_prefix_length)),
            data,
            elem_ref_script,
            continued_data,
            cont_elem_ref_script,
            elem_link,
          ),
        }
      }
    }
  }
}

// ## Exposed Helpers

/// Advanced counterpart to the default element-info continuation. The final
/// argument is the element's reference script, if present.
pub type ElementInfo<a> =
  fn(Lovelace, Option<NodeKey>, Data, Link, Option<ScriptHash>) -> a

/// Advanced counterpart to the default root-info continuation. The final
/// argument is the root element's reference script, if present.
pub type RootElementInfo<a> =
  fn(Lovelace, RootData, Link, Option<ScriptHash>) -> a

/// Advanced counterpart to the default node-info continuation. The final
/// argument is the node element's reference script, if present.
pub type NodeElementInfo<a> =
  fn(Lovelace, NodeKey, NodeData, Link, Option<ScriptHash>) -> a

/// Like the default module's `get_element_info`, but the callback also receives
/// the element reference script.
pub fn get_element_info(
  element_utxo: Output,
  info_validations: ElementInfo<a>,
) -> ElementEval<a> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> a {
    let
      _element_address,
      element_lovelace,
      element_asset_name,
      element_data,
      element_link,
      element_ref_script,
    <- authenticate_element_utxo_and_get_info(element_utxo, list_nft_policy_id)

    when element_data is {
      Root { data: root_data } -> {
        expect element_asset_name == root_key
        info_validations(
          element_lovelace,
          None,
          root_data,
          element_link,
          element_ref_script,
        )
      }
      Node { data: node_data } -> {
        expect
          bytearray.take(element_asset_name, node_key_prefix_length) == node_key_prefix
        info_validations(
          element_lovelace,
          Some(bytearray.drop(element_asset_name, node_key_prefix_length)),
          node_data,
          element_link,
          element_ref_script,
        )
      }
    }
  }
}

/// Like the default module's `get_root_element_info`, but the callback also
/// receives the root reference script.
pub fn get_root_element_info(
  element_utxo: Output,
  info_validations: RootElementInfo<a>,
) -> RootEval<a> {
  fn(list_nft_policy_id: PolicyId, root_key: RootKey) -> a {
    let
      _element_address,
      element_lovelace,
      element_asset_name,
      element_data,
      element_link,
      element_ref_script,
    <- authenticate_element_utxo_and_get_info(element_utxo, list_nft_policy_id)

    expect element_asset_name == root_key
    expect Root { data: root_data } = element_data

    info_validations(
      element_lovelace,
      root_data,
      element_link,
      element_ref_script,
    )
  }
}

/// Like the default module's `get_node_element_info`, but the callback also
/// receives the node reference script.
pub fn get_node_element_info(
  element_utxo: Output,
  info_validations: NodeElementInfo<a>,
) -> NodeEval<a> {
  fn(
    list_nft_policy_id: PolicyId,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> a {
    let
      _element_address,
      element_lovelace,
      element_asset_name,
      element_data,
      element_link,
      element_ref_script,
    <- authenticate_element_utxo_and_get_info(element_utxo, list_nft_policy_id)

    expect
      bytearray.take(element_asset_name, node_key_prefix_length) == node_key_prefix
    let node_key = bytearray.drop(element_asset_name, node_key_prefix_length)
    expect Node { data: node_data } = element_data

    info_validations(
      element_lovelace,
      node_key,
      node_data,
      element_link,
      element_ref_script,
    )
  }
}

// ## Internal Helpers

/// Use `Less` for ascending and `Greater` for descending for the value of
/// `ordering_of_new_key_vs_anchors_link`.
fn insert_ordered(
  ordering_of_new_key_vs_anchors_link: Ordering,
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: fn(
    Input,
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
    Option<ScriptHash>,
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
    let
      anchor_element_input,
      anchor_element_lovelace_change,
      anchor_element_asset_name,
      anchor_element_data,
      anchor_element_link,
      new_node_lovelace,
      new_node_asset_name,
      new_node_key,
      new_node_data,
      new_node_link,
      new_node_ref_script,
      other_minted_list_assets,
    <-
      common_insertion_validations(
        list_nft_policy_id,
        node_key_prefix,
        node_key_prefix_length,
        continued_anchor_element_output,
        new_node_output,
        inputs,
        tx_mint,
      )

    when anchor_element_data is {
      Root { data: root_data } -> {
        // 1a. Token name of the anchor element must be identical to the
        //     constant `root_key`.
        expect anchor_element_asset_name == root_key

        // 2a. If the root is already pointing to a first node, the new node
        //     must have a key such that it is less (or greater for descending)
        //     than the previous link's.
        expect
          when anchor_element_link is {
            None -> True
            Some(anchor_element_link_key) ->
              bytearray.compare(new_node_key, anchor_element_link_key) == ordering_of_new_key_vs_anchors_link
          }

        // 3a. Custom validation against the spent anchor element and the new
        //     node must pass.
        expect
          additional_validations(
            anchor_element_input,
            anchor_element_lovelace_change,
            None,
            root_data,
            new_node_lovelace,
            new_node_key,
            new_node_data,
            new_node_link,
            new_node_ref_script,
            other_minted_list_assets,
          )

        // Done.
        True
      }
      Node { data: anchor_node_data } -> {
        // 1b. The anchor node's key must start with the provided label.
        expect
          bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix

        // 2b. The new node must have a key that is greater (or less for
        //     descending) than the anchor node's.
        // 3b. If the anchor node is already pointing to a link, the new node's
        //     key (i.e. asset name) must be less than this link's.
        expect
          when anchor_element_link is {
            None ->
              bytearray.compare(anchor_element_asset_name, new_node_asset_name) == ordering_of_new_key_vs_anchors_link
            Some(anchor_element_link_key) -> and {
                bytearray.compare(
                  anchor_element_asset_name,
                  new_node_asset_name,
                ) == ordering_of_new_key_vs_anchors_link,
                bytearray.compare(new_node_key, anchor_element_link_key) == ordering_of_new_key_vs_anchors_link,
              }
          }

        // 4b. Custom validation against the spent anchor element and the new
        //     node must pass.
        expect
          additional_validations(
            anchor_element_input,
            anchor_element_lovelace_change,
            Some(
              bytearray.drop(anchor_element_asset_name, node_key_prefix_length),
            ),
            anchor_node_data,
            new_node_lovelace,
            new_node_key,
            new_node_data,
            new_node_link,
            new_node_ref_script,
            other_minted_list_assets,
          )

        // Done.
        True
      }
    }
  }
}

fn common_insertion_validations(
  list_nft_policy_id: PolicyId,
  node_key_prefix: NodeKeyPrefix,
  node_key_prefix_length: NodeKeyPrefixLength,
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  callback: fn(
    Input,
    LovelaceChange,
    AssetName,
    GenericElementData,
    Link,
    Lovelace,
    AssetName,
    NodeKey,
    NodeData,
    Link,
    Option<ScriptHash>,
    OtherListAssets,
  ) ->
    Bool,
) -> Bool {
  // 1. Inputs list must carry exactly one UTxO with the list NFT.
  let
    anchor_element_input,
    anchor_element_lovelace,
    anchor_element_asset_name,
    anchor_element_data,
    anchor_element_link,
  <- validate_singular_authentic_input(inputs, list_nft_policy_id)

  let anchor_element_address = anchor_element_input.output.address

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
  <- authenticate_element_utxo_and_get_info(new_node_output, list_nft_policy_id)

  // 4. Anchor element must be continued at the same address.
  expect anchor_element_address == cont_anchor_element_address

  // 5. Inserted node must share payment credential with the anchor element.
  expect
    anchor_element_address.payment_credential == new_node_address.payment_credential

  // 6. Anchor element's NFT must be preserved.
  expect anchor_element_asset_name == cont_anchor_element_asset_name

  // 7. Underlying data of anchor element must not change.
  expect anchor_element_data == cont_anchor_element_data
  expect
    anchor_element_input.output.reference_script == cont_anchor_element_ref_script

  let anchor_element_lovelace_change =
    cont_anchor_element_lovelace - anchor_element_lovelace

  let new_node_key = bytearray.drop(new_node_asset_name, node_key_prefix_length)

  // 8. New node's NFT must be minted under its policy. Any remaining
  //    same-policy mint is exposed to the custom validator.
  let other_minted_list_assets =
    validate_list_nft_and_get_other_list_assets(
      tx_mint,
      list_nft_policy_id,
      new_node_asset_name,
      1,
    )

  // 9. Reproduced anchor element must point to the new node.
  expect cont_anchor_element_link == Some(new_node_key)

  // 10. The new element must point to what the anchor element used to link to.
  expect new_node_link == anchor_element_link

  // 11. The new node's asset name must start with the provided label.
  expect
    bytearray.take(new_node_asset_name, node_key_prefix_length) == node_key_prefix

  // 12. New node's `ElementData` must be `Node`.
  expect Node { data: new_node_data } = new_node_element_data

  // 13. Further validations must pass.
  callback(
    anchor_element_input,
    anchor_element_lovelace_change,
    anchor_element_asset_name,
    anchor_element_data,
    anchor_element_link,
    new_node_lovelace,
    new_node_asset_name,
    new_node_key,
    new_node_data,
    new_node_link,
    new_node_ref_script,
    other_minted_list_assets,
  )
}
