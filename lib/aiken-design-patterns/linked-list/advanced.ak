//// Advanced linked-list helpers reuse the default module's element type,
//// aliases, runners, spend helper, and structural invariants.
////
//// Key differences from default:
//// 1. Reference-script-aware callbacks are available for init, structural node
////    operations, reads, and updates. Continued structural anchors preserve
////    their reference scripts.
//// 2. Structural node mint/burn helpers may accept additional same-policy
////    mint/burn outside the root key and node-key namespace and expose it as
////    `OtherListAssets`. List element UTxOs remain exactly ADA plus one list
////    NFT, and root init/deinit plus non-structural continuations remain strict.
//// 3. Insert/remove callbacks receive both spent and continued anchor data;
////    caller callbacks decide valid data changes while structural identity and
////    links are enforced.
//// 4. Advanced structural mint/burn helpers still pair with the base
////    spend-side helper
////    `aiken_design_patterns/linked_list.spend_for_adding_or_removing_an_element`.
//// 5. Every `Output` passed to an advanced mint helper must come from
////    `ScriptContext.transaction.outputs`. The helpers validate the selected
////    outputs as linked-list UTxOs, but the caller chooses how to select them:
////    indexes, filtering, `list.find`, or another contract-specific method are
////    all valid as long as the `Output` is not redeemer data or a locally
////    constructed value.
////
//// Insert/remove callbacks share an anchor prefix:
//// `(anchor input, anchor Lovelace change, anchor key, spent anchor data,
//// continued anchor data)`. `anchor key` is `None` for root data and
//// `Some(key)` for node data.

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
  is_only_mint_under_policy, key_fits_between,
  validate_list_nft_and_get_other_list_assets,
  validate_no_reserved_list_asset_changes,
}
use aiken_design_patterns/singular_utxo_indexer
use cardano/address.{Address}
use cardano/assets.{AssetName, Lovelace, PolicyId, Value}
use cardano/transaction.{Input, Output, OutputReference}

/// Same-policy transaction mint/burn changes left after removing the structural
/// node NFT. These are not assets carried by list element UTxOs.
///
/// Positive quantities are mints; negative quantities are burns.
pub type OtherListAssets =
  Dict<AssetName, Int>

/// Callback for ordered insertion.
///
/// The shared advanced anchor prefix is:
/// `(anchor input, anchor Lovelace change, anchor key, spent anchor data,
/// continued anchor data)`, where `anchor key` is `None` for root anchors and
/// `Some(key)` for node anchors.
///
/// After that prefix, this callback receives the authenticated new node
/// Lovelace, key, data, link, reference script, and permitted same-policy asset
/// changes. Structural identity, link wiring, reference-script preservation on
/// the continued anchor, minting, and key ordering have already been checked.
/// The produced node address is not repeated in this callback; callers that
/// need full-address checks can capture the `new_node_output` they passed to
/// the insertion helper.
pub type OrderedInsertValidation =
  fn(
    Input,
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Data,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
    Option<ScriptHash>,
    OtherListAssets,
  ) ->
    Bool

/// Callback for appending an unordered node.
///
/// The shared advanced anchor prefix is followed by the new terminal node's
/// Lovelace, key, data, reference script, and permitted same-policy asset
/// changes. The library has already checked that the anchor was terminal, the
/// new node is terminal, and the continued anchor points to the new node.
/// Because this is unordered, application-specific key uniqueness must be
/// enforced by the callback if it matters.
/// The produced node address is available from the `new_node_output` supplied
/// to the helper.
pub type AppendValidation =
  fn(
    Input,
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Data,
    Lovelace,
    NodeKey,
    NodeData,
    Option<ScriptHash>,
    OtherListAssets,
  ) ->
    Bool

/// Callback for prepending an unordered node.
///
/// The anchor has already been authenticated as the root, the continued root
/// has been checked to point to the new node, and the new node has been checked
/// to point to the root's previous first node.
/// The produced node address is available from the `new_node_output` supplied
/// to the helper.
///
/// Args: root input, root Lovelace change, spent root data, continued root data,
/// new node Lovelace, new node key, new node data, new node link, new node
/// reference script, other same-policy asset changes.
pub type PrependValidation =
  fn(
    Input,
    LovelaceChange,
    RootData,
    RootData,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
    Option<ScriptHash>,
    OtherListAssets,
  ) ->
    Bool

/// Callback for removal.
///
/// The shared advanced anchor prefix is followed by the authenticated removing
/// node input, Lovelace, key, data, link, and permitted same-policy asset
/// changes. The library has already selected the anchor by output reference,
/// proved that the anchor points to the removed node, preserved the continued
/// anchor address/NFT/reference script, and checked that the continued link
/// skips over the removed node.
pub type RemoveValidation =
  fn(
    Input,
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Data,
    Input,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
    OtherListAssets,
  ) ->
    Bool

/// Callback for folding from the root.
///
/// The library has already selected the root by output reference, authenticated
/// the folded node, proved that the root points to that node, preserved the
/// continued root address/NFT/reference script, and moved the folded node's old
/// link onto the continued root.
///
/// Args: root input, root Lovelace change, spent root data, folding node input,
/// folding node Lovelace, folding node key, folding node data, folding node
/// link, continued root data, other same-policy asset changes.
pub type FoldValidation =
  fn(
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
    Bool

/// Callback for non-structural element continuations.
///
/// The updater preserves address, NFT, constructor, and link; this callback
/// controls the Lovelace change, data transition, and reference-script
/// transition.
///
/// Args: preserved element address, Lovelace change, element key (`None` for
/// root), old data, old reference script, new data, new reference script,
/// preserved link.
pub type UpdateValidation =
  fn(
    Address,
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Option<ScriptHash>,
    Data,
    Option<ScriptHash>,
    Link,
  ) ->
    Bool

// ## Initialization and De-initialization

/// Initialize the root while passing its reference script to the callback. No
/// extra mint/burn changes under the list NFT policy are allowed.
///
/// `nonce_validated` must prove a unique consumed nonce or equivalent one-time
/// authorization. Passing literal `True` is only appropriate in tests and
/// fixtures.
///
/// `root_validator` receives the produced address, Lovelace quantity, raw root
/// data, and optional reference script. The address is passed explicitly even
/// though callers could inspect `produced_element_output`, so callbacks can
/// validate the destination without destructuring the output again.
///
/// `produced_element_output` must be selected from
/// `ScriptContext.transaction.outputs`. This helper authenticates that selected
/// output as the produced root; it deliberately leaves index/filter selection
/// to the surrounding validator.
///
/// It is up to callers to ensure this address has a script payment credential
/// controlled by a script that only uses the spend helpers from this library. In
/// other words, the destination script must ensure list NFTs never leave its
/// custody.
pub fn init(
  nonce_validated: Bool,
  produced_element_output: Output,
  tx_mint: Value,
  root_validator: fn(Address, Lovelace, Data, Option<ScriptHash>) -> Bool,
) -> RootEval<Bool> {
  // 1. The caller must prove the one-time initialization authorization.
  expect nonce_validated

  fn(list_nft_policy_id: PolicyId, root_key: RootKey) -> Bool {
    // 2. The produced output must be an authentic singleton list element.
    let
      element_address,
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

    // 3. The produced datum must be a root datum.
    expect Root { data: root_data } = element_data

    // 4. The singleton NFT must use the configured root key.
    expect element_asset_name == root_key

    // 5. Initialization must mint exactly that root NFT.
    expect
      is_only_mint_under_policy(
        tx_mint,
        list_nft_policy_id,
        element_asset_name,
        1,
      )

    // 6. A new list starts empty.
    expect element_link == None

    // 7. Delegate application-specific root checks to the caller.
    expect
      root_validator(
        element_address,
        element_lovelace,
        root_data,
        element_ref_script,
      )

    // Done.
    True
  }
}

/// Deinitialize the root with no extra burns or mints under the list NFT policy.
/// The callback has the base shape `fn(Input, Lovelace, Data) -> Bool`; callers
/// that need the spent root reference script can read
/// `root_input.output.reference_script` from that input argument.
pub const deinit = linked_list.deinit

// ## Element Addition and Removal

/// Insert a node into an ascending ordered list.
///
/// This is the advanced variant of the base module's `insert_ascending`. It
/// preserves the anchor address, NFT, reference script, constructor, and
/// structural links, but passes both spent and continued anchor payload data to
/// `additional_validations`. That lets the caller validate an application data
/// transition while the library still enforces the linked-list structure.
///
/// Ordering rule:
/// - root anchor: `new < old_first`
/// - node anchor: `anchor < new < old_next`
///
/// The required new node NFT must be minted under the list policy. Additional
/// same-policy mint changes are allowed only outside the root key and node-key
/// namespace, then passed to the callback as `OtherListAssets`.
///
/// `continued_anchor_element_output` and `new_node_output` must both be
/// selected from `ScriptContext.transaction.outputs`. This helper validates the
/// selected outputs and intentionally leaves their selection strategy to the
/// caller.
pub fn insert_ascending(
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: OrderedInsertValidation,
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

/// Insert a node into a descending ordered list.
///
/// Same contract as [`insert_ascending`](#insert_ascending), except the
/// bytearray ordering is reversed:
/// - root anchor: `new > old_first`
/// - node anchor: `anchor > new > old_next`
///
/// `continued_anchor_element_output` and `new_node_output` must both come from
/// `ScriptContext.transaction.outputs`; callers may select them by index,
/// filtering, or another surrounding-validator convention.
pub fn insert_descending(
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: OrderedInsertValidation,
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

/// Append a node to the terminal anchor of an unordered list.
///
/// The single authentic input is the current terminal anchor. The continued
/// anchor links to the new node, and the produced node must be terminal. No key
/// ordering is checked in this unordered operation; callers must enforce any
/// application-specific uniqueness or indexing rule in `additional_validations`.
///
/// The advanced callback receives spent and continued anchor data, the new
/// node's reference script, and any permitted same-policy asset changes outside
/// the node namespace.
///
/// `continued_anchor_element_output` and `new_node_output` must both be
/// selected from `ScriptContext.transaction.outputs`. Output selection remains
/// caller-controlled.
pub fn append_unordered(
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: AppendValidation,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    // 1. Run the shared advanced insertion checks.
    let
      anchor_element_input,
      anchor_element_lovelace_change,
      anchor_element_asset_name,
      anchor_element_data,
      cont_anchor_element_data,
      anchor_element_link,
      new_node_lovelace,
      new_node_key,
      new_node_data,
      new_node_link,
      new_node_ref_script,
      other_list_asset_changes,
    <-
      common_insertion_validations(
        list_nft_policy_id,
        root_key,
        node_key_prefix,
        node_key_prefix_length,
        continued_anchor_element_output,
        new_node_output,
        inputs,
        tx_mint,
      )

    // 2. The anchor must be terminal.
    expect anchor_element_link == None

    // 3. The appended node must also be terminal.
    expect new_node_link == None

    when anchor_element_data is {
      Root { data: root_data } -> {
        // 4a. The continued anchor datum must remain a root.
        expect Root { data: cont_root_data } = cont_anchor_element_data

        // 5a. A root anchor must use the configured root key.
        expect anchor_element_asset_name == root_key

        // 6a. Delegate application-specific append checks.
        expect
          additional_validations(
            anchor_element_input,
            anchor_element_lovelace_change,
            None,
            root_data,
            cont_root_data,
            new_node_lovelace,
            new_node_key,
            new_node_data,
            new_node_ref_script,
            other_list_asset_changes,
          )

        // Done.
        True
      }
      Node { data: anchor_node_data } -> {
        // 4b. The continued anchor datum must remain a node.
        expect Node { data: cont_anchor_node_data } = cont_anchor_element_data

        // 5b. A node anchor must stay inside the node namespace.
        expect
          bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix

        // 6b. Delegate application-specific append checks.
        expect
          additional_validations(
            anchor_element_input,
            anchor_element_lovelace_change,
            Some(
              bytearray.drop(anchor_element_asset_name, node_key_prefix_length),
            ),
            anchor_node_data,
            cont_anchor_node_data,
            new_node_lovelace,
            new_node_key,
            new_node_data,
            new_node_ref_script,
            other_list_asset_changes,
          )

        // Done.
        True
      }
    }
  }
}

/// Prepend a node immediately after the root in an unordered list.
///
/// The single authentic input must be the root. The continued root points to
/// the new node, and the new node points to the root's previous first node. No
/// key ordering is checked because this is an unordered operation.
///
/// The advanced callback receives spent and continued root data, the new node's
/// reference script, and permitted same-policy asset changes outside the node
/// namespace.
///
/// `continued_root_element_output` and `new_node_output` must both be selected
/// from `ScriptContext.transaction.outputs`; this helper authenticates the
/// selected outputs rather than proving the selection method.
pub fn prepend_unordered(
  continued_root_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: PrependValidation,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    // 1. Run the shared advanced insertion checks.
    let
      root_element_input,
      root_lovelace_change,
      root_element_asset_name,
      root_element_data,
      cont_root_element_data,
      _root_element_link,
      new_node_lovelace,
      new_node_key,
      new_node_data,
      new_node_link,
      new_node_ref_script,
      other_list_asset_changes,
    <-
      common_insertion_validations(
        list_nft_policy_id,
        root_key,
        node_key_prefix,
        node_key_prefix_length,
        continued_root_element_output,
        new_node_output,
        inputs,
        tx_mint,
      )

    // 2. The anchor must be the root.
    expect Root { data: root_data } = root_element_data

    // 3. The continued anchor datum must remain a root.
    expect Root { data: cont_root_data } = cont_root_element_data

    // 4. The root NFT asset name must match the configured root key.
    expect root_element_asset_name == root_key

    // 5. Delegate application-specific prepend checks.
    expect
      additional_validations(
        root_element_input,
        root_lovelace_change,
        root_data,
        cont_root_data,
        new_node_lovelace,
        new_node_key,
        new_node_data,
        new_node_link,
        new_node_ref_script,
        other_list_asset_changes,
      )

    // Done.
    True
  }
}

/// Remove the node linked by the selected anchor.
///
/// `anchor_input_outref` identifies which of the two authentic list inputs is
/// the anchor. The other authentic input must be the node referenced by the
/// anchor's current link. The continued anchor preserves address, NFT, and
/// reference script, and its new link must skip over the removed node.
///
/// The removed node NFT must be burned. Additional same-policy burn/mint
/// changes are allowed only outside the root key and node-key namespace, then
/// passed to `additional_validations` for caller-specific checks.
pub fn remove(
  anchor_input_outref: OutputReference,
  continued_anchor_element_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: RemoveValidation,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    // 1. Locate the selected anchor input and the node linked from it.
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

    let Input {
      output: Output {
        address: anchor_address,
        reference_script: anchor_ref_script,
        ..
      },
      ..
    } = anchor_input

    // 2. Authenticate the continued anchor output.
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

    // 3. The removed asset must live in the node namespace.
    expect
      bytearray.take(removing_node_asset_name, node_key_prefix_length) == node_key_prefix

    let removing_node_key =
      bytearray.drop(removing_node_asset_name, node_key_prefix_length)

    // 4. The continued anchor must preserve address, NFT, and reference script.
    expect cont_anchor_address == anchor_address
    expect cont_anchor_asset_name == anchor_asset_name
    expect cont_anchor_ref_script == anchor_ref_script

    // 5. The second authentic input must be a node.
    expect Node { data: removing_node_data } = removing_node_element_data

    // 6. Removal must burn the removed node NFT and return other list assets.
    let other_list_asset_changes =
      validate_list_nft_and_get_other_list_assets(
        tx_mint,
        list_nft_policy_id,
        removing_node_asset_name,
        -1,
      )

    // 7. Extra same-policy changes must not use reserved list asset names.
    expect
      validate_no_reserved_list_asset_changes(
        other_list_asset_changes,
        root_key,
        node_key_prefix,
        node_key_prefix_length,
      )

    // 8. The anchor must currently point to the removed node.
    expect anchor_link == Some(removing_node_key)

    // 9. The continued anchor must skip over the removed node.
    expect cont_anchor_link == removing_node_link

    when anchor_element_data is {
      Root { data: root_data } -> {
        // 10a. The continued anchor datum must remain a root.
        expect Root { data: cont_root_data } = cont_anchor_element_data

        // 11a. A root anchor must use the configured root key.
        expect anchor_asset_name == root_key

        // 12a. Delegate application-specific remove checks.
        expect
          additional_validations(
            anchor_input,
            anchor_element_lovelace_change,
            None,
            root_data,
            cont_root_data,
            removing_node_input,
            removing_node_lovelace,
            removing_node_key,
            removing_node_data,
            removing_node_link,
            other_list_asset_changes,
          )

        // Done.
        True
      }
      Node { data: anchor_node_data } -> {
        // 10b. The continued anchor datum must remain a node.
        expect Node { data: cont_anchor_node_data } = cont_anchor_element_data

        // 11b. A node anchor must stay inside the node namespace.
        expect
          bytearray.take(anchor_asset_name, node_key_prefix_length) == node_key_prefix

        // 12b. Delegate application-specific remove checks.
        expect
          additional_validations(
            anchor_input,
            anchor_element_lovelace_change,
            Some(bytearray.drop(anchor_asset_name, node_key_prefix_length)),
            anchor_node_data,
            cont_anchor_node_data,
            removing_node_input,
            removing_node_lovelace,
            removing_node_key,
            removing_node_data,
            removing_node_link,
            other_list_asset_changes,
          )

        // Done.
        True
      }
    }
  }
}

// ## Fold Functions

/// Fold the root's first node into the root.
///
/// `anchor_root_input_outref` must identify the root input. The second
/// authentic input must be the node currently linked from the root. The
/// continued root preserves address, NFT, and reference script, remains a
/// `Root`, and adopts the folded node's old link.
///
/// The folded node NFT must be burned. Additional same-policy burn/mint changes
/// outside the root key and node-key namespace are passed to
/// `additional_validations`.
pub fn fold_from_root(
  anchor_root_input_outref: OutputReference,
  continued_anchor_root_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: FoldValidation,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    // 1. Locate the root input and the node linked from it.
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

    let Input {
      output: Output {
        address: anchor_root_address,
        reference_script: anchor_root_ref_script,
        ..
      },
      ..
    } = anchor_root_input

    // 2. The anchor input must be a root.
    expect Root { data: anchor_root_data } = anchor_root_element_data

    // 3. Authenticate the continued root output.
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

    // 4. The folded asset must live in the node namespace.
    expect
      bytearray.take(folding_node_asset_name, node_key_prefix_length) == node_key_prefix

    let folding_node_key =
      folding_node_asset_name
        |> bytearray.drop(node_key_prefix_length)

    // 5. The second authentic input must be a node.
    expect Node { data: folding_node_data } = folding_node_element_data

    // 6. The continued anchor must remain a root.
    expect Root { data: cont_anchor_root_data } = cont_anchor_root_element_data

    // 7. Folding must burn the folded node NFT and return other list assets.
    let other_list_asset_changes =
      validate_list_nft_and_get_other_list_assets(
        tx_mint,
        list_nft_policy_id,
        folding_node_asset_name,
        -1,
      )

    // 8. Extra same-policy changes must not use reserved list asset names.
    expect
      validate_no_reserved_list_asset_changes(
        other_list_asset_changes,
        root_key,
        node_key_prefix,
        node_key_prefix_length,
      )

    // 9. The continued root must preserve address, NFT, and reference script.
    expect anchor_root_address == cont_anchor_root_address
    expect anchor_root_asset_name == cont_anchor_root_asset_name
    expect anchor_root_ref_script == cont_anchor_root_ref_script

    // 10. The root must currently point to the folded node.
    expect anchor_root_link == Some(folding_node_key)

    // 11. The continued root must adopt the folded node's old link.
    expect cont_anchor_root_link == folding_node_link

    // 12. The root NFT asset name must match the configured root key.
    expect anchor_root_asset_name == root_key

    // 13. Delegate application-specific fold checks.
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
        other_list_asset_changes,
      )

    // Done.
    True
  }
}

// ## Spending Script Helpers

/// Re-export of the base structural spend gate.
///
/// The same precondition applies here: this is not standalone authorization.
/// It must be paired with an advanced/base list minting policy that accepts
/// structural mint/burns only through the matching linked-list mint helpers.
pub const spend_for_adding_or_removing_an_element =
  linked_list.spend_for_adding_or_removing_an_element

/// Continue one element without changing list structure.
///
/// This is the advanced variant of the base data-update helper. No list-policy
/// mint/burn is allowed. The continuation must preserve address, NFT,
/// constructor, and link. Unlike the base helper, the callback receives both
/// the spent and continued reference scripts, so callers can decide whether a
/// reference script is preserved, added, removed, or changed.
///
/// `additional_validations` receives:
/// 1. preserved element address
/// 2. Lovelace change
/// 3. element key (`None` for root, `Some(key)` for node)
/// 4. old data
/// 5. old reference script
/// 6. new data
/// 7. new reference script
/// 8. preserved link
pub fn spend_for_updating_elements_data(
  element_input_index: Int,
  continued_element_output_index: Int,
  element_input_outref: OutputReference,
  inputs: List<Input>,
  outputs: List<Output>,
  tx_mint: Value,
  additional_validations: UpdateValidation,
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

    // 1. The continuation must preserve address, NFT, and link.
    expect elem_address == cont_elem_address
    expect elem_asset_name == cont_elem_asset_name
    expect elem_link == cont_elem_link

    let lovelace_change = cont_elem_lovelace - elem_lovelace
    when elem_data is {
      Root { data } -> {
        // 2a. The continued datum must remain a root.
        expect Root { data: continued_data } = cont_elem_data

        // 3a. A root update must use the configured root key.
        expect elem_asset_name == root_key

        // 4a. Delegate application-specific update checks.
        expect
          additional_validations(
            elem_address,
            lovelace_change,
            None,
            data,
            elem_ref_script,
            continued_data,
            cont_elem_ref_script,
            elem_link,
          )

        // Done.
        True
      }
      Node { data } -> {
        // 2b. The continued datum must remain a node.
        expect Node { data: continued_data } = cont_elem_data

        // 3b. A node update must stay inside the node namespace.
        expect
          bytearray.take(elem_asset_name, node_key_prefix_length) == node_key_prefix

        // 4b. Delegate application-specific update checks.
        expect
          additional_validations(
            elem_address,
            lovelace_change,
            Some(bytearray.drop(elem_asset_name, node_key_prefix_length)),
            data,
            elem_ref_script,
            continued_data,
            cont_elem_ref_script,
            elem_link,
          )

        // Done.
        True
      }
    }
  }
}

// ## Exposed Helpers

/// Element-info continuation, including any reference script.
///
/// Args: Address, Lovelace, element key (`None` for root, `Some(key)` for node),
/// data, link, reference script.
pub type ElementInfo<a> =
  fn(Address, Lovelace, Option<NodeKey>, Data, Link, Option<ScriptHash>) -> a

/// Root-info continuation, including any reference script.
///
/// Args: Address, Lovelace, root data, link, reference script.
pub type RootElementInfo<a> =
  fn(Address, Lovelace, RootData, Link, Option<ScriptHash>) -> a

/// Node-info continuation, including any reference script.
///
/// Args: Address, Lovelace, node key, node data, link, reference script.
pub type NodeElementInfo<a> =
  fn(Address, Lovelace, NodeKey, NodeData, Link, Option<ScriptHash>) -> a

/// Read root or node info through `ElementInfo`.
///
/// The UTxO must be an authenticated singleton list element. The callback
/// receives the element address, Lovelace quantity, `None` for root keys or
/// `Some(node_key)` for node keys, with the node prefix stripped, plus the
/// element payload, link, and optional reference script.
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
      element_address,
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
          element_address,
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
          element_address,
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

/// Read root info through `RootElementInfo`.
///
/// The UTxO must carry the configured root NFT and a `Root` datum. The callback
/// receives address, Lovelace, raw root payload data, the root link, and the
/// reference script attached to the UTxO, if any.
pub fn get_root_element_info(
  element_utxo: Output,
  info_validations: RootElementInfo<a>,
) -> RootEval<a> {
  fn(list_nft_policy_id: PolicyId, root_key: RootKey) -> a {
    let
      element_address,
      element_lovelace,
      element_asset_name,
      element_data,
      element_link,
      element_ref_script,
    <- authenticate_element_utxo_and_get_info(element_utxo, list_nft_policy_id)

    expect element_asset_name == root_key
    expect Root { data: root_data } = element_data

    info_validations(
      element_address,
      element_lovelace,
      root_data,
      element_link,
      element_ref_script,
    )
  }
}

/// Read node info through `NodeElementInfo`.
///
/// The UTxO must carry a list NFT whose asset name starts with
/// `node_key_prefix` and must contain a `Node` datum. The callback receives
/// address, Lovelace, the node key with the prefix stripped, raw node payload
/// data, the node link, and the reference script attached to the UTxO, if any.
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
      element_address,
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
      element_address,
      element_lovelace,
      node_key,
      node_data,
      element_link,
      element_ref_script,
    )
  }
}

// ## Internal Helpers

fn insert_ordered(
  required_neighbor_ordering: Ordering,
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: OrderedInsertValidation,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    // 1. Run the shared advanced insertion checks.
    let
      anchor_element_input,
      anchor_element_lovelace_change,
      anchor_element_asset_name,
      anchor_element_data,
      cont_anchor_element_data,
      anchor_element_link,
      new_node_lovelace,
      new_node_key,
      new_node_data,
      new_node_link,
      new_node_ref_script,
      other_list_asset_changes,
    <-
      common_insertion_validations(
        list_nft_policy_id,
        root_key,
        node_key_prefix,
        node_key_prefix_length,
        continued_anchor_element_output,
        new_node_output,
        inputs,
        tx_mint,
      )

    when anchor_element_data is {
      Root { data: root_data } -> {
        // 2a. The continued anchor datum must remain a root.
        expect Root { data: cont_root_data } = cont_anchor_element_data

        // 3a. A root anchor must use the configured root key.
        expect anchor_element_asset_name == root_key

        // 4a. The new key must fit before/after the old first node.
        expect
          key_fits_between(
            required_neighbor_ordering,
            None,
            new_node_key,
            anchor_element_link,
          )

        // 5a. Delegate application-specific ordered-insert checks.
        expect
          additional_validations(
            anchor_element_input,
            anchor_element_lovelace_change,
            None,
            root_data,
            cont_root_data,
            new_node_lovelace,
            new_node_key,
            new_node_data,
            new_node_link,
            new_node_ref_script,
            other_list_asset_changes,
          )

        // Done.
        True
      }
      Node { data: anchor_node_data } -> {
        // 2b. The continued anchor datum must remain a node.
        expect Node { data: cont_anchor_node_data } = cont_anchor_element_data

        // 3b. A node anchor must stay inside the node namespace.
        expect
          bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix

        let anchor_node_key =
          bytearray.drop(anchor_element_asset_name, node_key_prefix_length)

        // 4b. The new key must fit between the anchor and its old successor.
        expect
          key_fits_between(
            required_neighbor_ordering,
            Some(anchor_node_key),
            new_node_key,
            anchor_element_link,
          )

        // 5b. Delegate application-specific ordered-insert checks.
        expect
          additional_validations(
            anchor_element_input,
            anchor_element_lovelace_change,
            Some(anchor_node_key),
            anchor_node_data,
            cont_anchor_node_data,
            new_node_lovelace,
            new_node_key,
            new_node_data,
            new_node_link,
            new_node_ref_script,
            other_list_asset_changes,
          )

        // Done.
        True
      }
    }
  }
}

// Shared insertion precheck: authenticate the anchor continuation and new node,
// preserve anchor identity/reference script, wire anchor -> new node -> previous
// link, and reject extra same-policy changes using reserved list asset names.
fn common_insertion_validations(
  list_nft_policy_id: PolicyId,
  root_key: RootKey,
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
    GenericElementData,
    Link,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
    Option<ScriptHash>,
    OtherListAssets,
  ) ->
    Bool,
) -> Bool {
  // 1. The transaction must spend exactly one authentic anchor input.
  let
    anchor_element_input,
    anchor_element_lovelace,
    anchor_element_asset_name,
    anchor_element_data,
    anchor_element_link,
  <- validate_singular_authentic_input(inputs, list_nft_policy_id)

  let Input {
    output: Output {
      address: anchor_element_address,
      reference_script: anchor_element_ref_script,
      ..
    },
    ..
  } = anchor_element_input
  let Address { payment_credential: anchor_payment_credential, .. } =
    anchor_element_address

  // 2. The continued anchor output must be authentic.
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

  // 3. The new node output must be authentic.
  let
    new_node_address,
    new_node_lovelace,
    new_node_asset_name,
    new_node_element_data,
    new_node_link,
    new_node_ref_script,
  <- authenticate_element_utxo_and_get_info(new_node_output, list_nft_policy_id)
  let Address { payment_credential: new_node_payment_credential, .. } =
    new_node_address

  // 4. The continued anchor must preserve the full address.
  expect anchor_element_address == cont_anchor_element_address

  // 5. The new node must share the anchor payment credential.
  expect anchor_payment_credential == new_node_payment_credential

  // 6. The continued anchor must preserve the anchor NFT.
  expect anchor_element_asset_name == cont_anchor_element_asset_name

  // 7. The advanced module preserves anchor reference scripts during insertion.
  expect anchor_element_ref_script == cont_anchor_element_ref_script

  let anchor_element_lovelace_change =
    cont_anchor_element_lovelace - anchor_element_lovelace

  // 8. The new node asset must live in the node namespace.
  expect
    bytearray.take(new_node_asset_name, node_key_prefix_length) == node_key_prefix

  let new_node_key = bytearray.drop(new_node_asset_name, node_key_prefix_length)

  // 9. Insertion must mint the new node NFT and return other list assets.
  let other_list_asset_changes =
    validate_list_nft_and_get_other_list_assets(
      tx_mint,
      list_nft_policy_id,
      new_node_asset_name,
      1,
    )

  // 10. Extra same-policy changes must not use reserved list asset names.
  expect
    validate_no_reserved_list_asset_changes(
      other_list_asset_changes,
      root_key,
      node_key_prefix,
      node_key_prefix_length,
    )

  // 11. The continued anchor must point to the new node.
  expect cont_anchor_element_link == Some(new_node_key)

  // 12. The new node must point to the anchor's previous successor.
  expect new_node_link == anchor_element_link

  // 13. The produced node datum must be a `Node`.
  expect Node { data: new_node_data } = new_node_element_data

  // 14. Delegate operation-specific insertion checks.
  expect
    callback(
      anchor_element_input,
      anchor_element_lovelace_change,
      anchor_element_asset_name,
      anchor_element_data,
      cont_anchor_element_data,
      anchor_element_link,
      new_node_lovelace,
      new_node_key,
      new_node_data,
      new_node_link,
      new_node_ref_script,
      other_list_asset_changes,
    )

  // Done.
  True
}
