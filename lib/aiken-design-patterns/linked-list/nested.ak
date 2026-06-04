//// Two-level linked lists using one list NFT policy and one spend script.
//// Datums represent three element kinds:
////
//// 1. `Root` anchors the outer list.
//// 2. `InnerRoot` is a node in the outer list and the root of one inner list.
//// 3. `Node` belongs to an inner list beneath an `InnerRoot` or another `Node`.
////
//// Base linked-list authentication, NFT namespace, dedicated list spend
//// script/payment credential, and mint-policy invariants still apply.
//// Continued anchors are checked by full address equality; newly minted nested
//// elements share the anchor payment credential. `InnerRoot` and `Node` NFTs
//// share one node-key namespace: constructors distinguish datum roles, but
//// keys must still be unique within that policy/prefix namespace and cannot be
//// duplicated across roles.
////
//// Every `Output` passed to a nested mint helper must come from
//// `ScriptContext.transaction.outputs`. The helpers validate selected outputs
//// as nested linked-list UTxOs, but intentionally leave selection to callers so
//// validators can use indexes, filtering, `list.find`, or another
//// contract-specific method. Do not pass redeemer-provided or locally
//// constructed outputs to these helpers.
////
//// Supported operations are init/deinit, insertion helpers, and non-structural
//// data updates. Nested remove/read spend logic must be custom.

use aiken/collection/dict
use aiken/crypto.{ScriptHash}
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list.{
  ElementEval, Link, LovelaceChange, NodeEval, NodeKey, NodeKeyPrefix,
  NodeKeyPrefixLength, RootEval, RootKey,
}
use aiken_design_patterns/linked_list/advanced.{OtherListAssets}
use aiken_design_patterns/linked_list/internal.{
  authenticate_element_utxo_and_get_info_helper, is_only_mint_under_policy,
  key_fits_between, validate_list_nft_and_get_other_list_assets,
  validate_no_reserved_list_asset_changes,
  validate_singular_authentic_input_helper,
}
use aiken_design_patterns/singular_utxo_indexer
use aiken_scott_utils/list as scott_list
use cardano/address.{Address, PaymentCredential}
use cardano/assets.{AssetName, Lovelace, PolicyId, Value}
use cardano/transaction.{Input, Output, OutputReference}

/// Nested element datum.
///
/// `Root` and `InnerRoot` participate in the outer list, so `Element.link`
/// points to the next outer element. `Node` participates in the inner list
/// beneath an `InnerRoot`, so `Element.link` points to the next inner child.
/// The constructor in `ElementData` determines which interpretation applies.
pub type Element<root_data, inner_root_data, node_data> {
  data: ElementData<root_data, inner_root_data, node_data>,
  link: Link,
}

/// Payload constructors for nested elements.
///
/// `Root` anchors the outer list. `InnerRoot` is both an outer-list element and
/// the root of one inner list; its `child_link` points to the first child
/// `Node` in that inner list. `Node` is an inner-list element and uses the
/// enclosing `Element.link` as its next-child link.
pub type ElementData<root_data, inner_root_data, node_data> {
  Root { data: root_data }
  InnerRoot { data: inner_root_data, child_link: Link }
  Node { data: node_data }
}

/// Raw `Data` nested-element alias used by authentication helpers.
///
/// This is not an application datum type. It lets the library authenticate and
/// distinguish `Root`, `InnerRoot`, and `Node` before passing raw payload data
/// to callbacks for application-specific decoding.
pub type GenericElement =
  Element<Data, Data, Data>

/// Raw `Data` nested element-data alias used by authentication helpers.
///
/// The constructor identifies the structural role of the authenticated UTxO;
/// the inner `Data` remains caller-defined and should be decoded inside
/// callbacks.
pub type GenericElementData =
  ElementData<Data, Data, Data>

/// Ordering mode for produced node keys.
///
/// `Ascending` and `Descending` use lexicographic bytearray ordering over
/// `NodeKey` bytes. `Unordered` skips key comparison but still enforces that
/// produced links match the declared chain.
pub type ListOrdering {
  Ascending
  Descending
  Unordered
}

/// Handler for an `InnerRoot` anchor during inner-list insertion.
///
/// Arguments are the inner-root key, spent inner-root data, continued
/// inner-root data, and the spent inner root's previous first-child link. The
/// continued child link and produced node wiring are already structurally
/// checked before this handler runs.
pub type OnInnerRootAnchor<result> =
  fn(NodeKey, Data, Data, Link) -> result

/// Handler for a `Node` anchor during inner-list insertion.
///
/// Arguments are the node key, spent node data, and continued node data. The
/// old child successor and new successor wiring are passed separately through
/// the main insertion callback.
pub type OnNodeAnchor<result> =
  fn(NodeKey, Data, Data) -> result

/// Branch selector for callbacks that need anchor-specific information during
/// inner-list insertion. Call `anchor(on_inner_root, on_node)`; exactly one
/// handler is invoked.
///
/// `Root` cannot anchor `insert_into_inner_list`; the previous inner-list link
/// is provided separately as the new node's link.
pub type InnerListAnchor<result> =
  fn(OnInnerRootAnchor<result>, OnNodeAnchor<result>) -> result

/// Callback for inserting one `Node` into an existing inner list.
///
/// The produced node address is not repeated in this callback; callers that
/// need full-address checks can capture the `new_node_output` they passed to
/// `insert_into_inner_list`.
///
/// Args: anchor input, anchor Lovelace change, anchor branch selector, new node
/// Lovelace, new node key, new node data, new node link already checked to
/// equal the anchor's previous inner-list link, new node reference script, and
/// non-structural same-policy asset changes.
pub type InnerListInsertValidation =
  fn(
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
    Bool

/// Initial state builder for minting a whole inner list.
///
/// The produced inner-root address is available from the
/// `new_inner_root_output` supplied to `insert_inner_list_ascending` or
/// `insert_inner_list_descending`.
///
/// Args: inner-root Lovelace, inner-root key, inner-root data, first-child link,
/// and inner-root reference script.
pub type InnerRootStatePreparation<state> =
  fn(Lovelace, NodeKey, Data, Link, Option<ScriptHash>) -> state

/// Per-node fold callback for minting a whole inner list.
///
/// Args: current state, zero-based node position within `inner_node_outputs`,
/// node address, node Lovelace, node key, node data, node link, and node
/// reference script.
///
/// Return the next fold state. Use `expect` or `fail` inside the callback to
/// reject an invalid node.
pub type InnerNodeValidation<state> =
  fn(state, Int, Address, Lovelace, NodeKey, Data, Link, Option<ScriptHash>) ->
    state

/// Final callback after minting a whole inner list.
///
/// Args: anchor input, anchor Lovelace change, anchor key, spent anchor data,
/// continued anchor data, spent anchor's old outer link, final folded state,
/// and non-structural same-policy asset changes. `None` key means root data;
/// `Some(key)` means inner-root data.
pub type InnerListFinalValidation<state> =
  fn(
    Input,
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Data,
    Link,
    state,
    OtherListAssets,
  ) ->
    Bool

/// Church-style branch selector for callbacks that need constructor-specific
/// information during a nested-list data update.
///
/// Address and `Element.link` are common to every constructor and are passed
/// outside this selector by `spend_for_updating_elements_data`. Only
/// `InnerRoot` receives a link here, because only `InnerRoot` has a second,
/// constructor-specific `child_link`.
///
/// The handlers receive:
/// 1. `Root`: spent data and continued data.
/// 2. `InnerRoot`: key, spent data, continued data, and preserved child link.
/// 3. `Node`: key, spent data, and continued data.
pub type ElementUpdate<result> =
  fn(
    fn(Data, Data) -> result,
    fn(NodeKey, Data, Data, Link) -> result,
    fn(NodeKey, Data, Data) -> result,
  ) ->
    result

/// Initialize a nested list root. `nonce_validated` must prove a unique
/// consumed nonce or equivalent one-time authorization; the produced root may
/// carry a reference script passed to `root_validator`, and the transaction
/// mint must be exactly one root NFT under the list policy. Passing literal
/// `True` is only appropriate in tests and fixtures.
///
/// `produced_element_output` must be selected from
/// `ScriptContext.transaction.outputs`. This helper authenticates the selected
/// output as the produced root while leaving index/filter selection to the
/// caller.
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

    // 6. A new nested list starts empty.
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

/// De-initialize an empty nested list.
///
/// The unique authentic input must be the root with no outer link, and the
/// transaction mint must be exactly a burn of that root NFT. Deinit has no
/// continuation; `root_validator` receives the spent input and can inspect
/// `element_input.output.reference_script`.
pub fn deinit(
  inputs: List<Input>,
  tx_mint: Value,
  root_validator: fn(Input, Lovelace, Data) -> Bool,
) -> RootEval<Bool> {
  fn(list_nft_policy_id: PolicyId, root_key: RootKey) -> Bool {
    // 1. The transaction must spend exactly one authentic list element.
    let
      element_input,
      _element_address,
      element_lovelace,
      element_asset_name,
      element_data,
      element_link,
      _element_ref_script,
    <- validate_singular_authentic_input(inputs, list_nft_policy_id)

    // 2. The spent element must be the root.
    expect Root { data: root_data }: GenericElementData = element_data

    // 3. Deinitialization must burn exactly the root NFT.
    expect
      is_only_mint_under_policy(
        tx_mint,
        list_nft_policy_id,
        element_asset_name,
        -1,
      )

    // 4. The root NFT asset name must match the configured root key.
    expect element_asset_name == root_key

    // 5. The root must have no outer successor.
    expect element_link == None

    // 6. Delegate application-specific root checks to the caller.
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
  cont_anchor_element_data: GenericElementData,
  anchor_element_asset_name: AssetName,
  root_key: RootKey,
  node_key_prefix: NodeKeyPrefix,
  node_key_prefix_length: NodeKeyPrefixLength,
  return: fn(Option<NodeKey>, Data, Data) -> result,
) -> result {
  // InnerRoot anchors must preserve `child_link`; Node anchors are rejected.
  when anchor_element_data is {
    Root { data: root_data } -> {
      expect anchor_element_asset_name == root_key
      expect Root { data: cont_root_data } = cont_anchor_element_data
      return(None, root_data, cont_root_data)
    }
    InnerRoot { data: inner_root_data, child_link } -> {
      expect
        bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix
      expect InnerRoot {
        data: cont_inner_root_data,
        child_link: cont_child_link,
      } = cont_anchor_element_data
      expect cont_child_link == child_link
      return(
        Some(bytearray.drop(anchor_element_asset_name, node_key_prefix_length)),
        inner_root_data,
        cont_inner_root_data,
      )
    }
    Node { .. } -> fail @"Anchor must be either Root or InnerRoot"
  }
}

/// Validate a produced inner-node chain. Starting at
/// `inner_root_child_link`, each node asset name must match the current
/// expected link, each node link becomes the next expected link, and the final
/// expected link must be `None`.
fn validate_inner_node_outputs(
  list_nft_policy_id: PolicyId,
  node_key_prefix: NodeKeyPrefix,
  node_key_prefix_length: NodeKeyPrefixLength,
  anchor_payment_credential: PaymentCredential,
  ordering_of_inner_node_keys: ListOrdering,
  inner_root_child_link: Link,
  inner_node_outputs: List<Output>,
  pending_list_asset_changes: OtherListAssets,
  initial_state: state,
  node_validator: InnerNodeValidation<state>,
  return: fn(OtherListAssets, state) -> result,
) -> result {
  let
    asset_changes_after_all_nodes,
    final_expected_link,
    _inner_node_count,
    _last_inner_node_key,
    final_state,
  <-
    scott_list.foldl5(
      inner_node_outputs,
      pending_list_asset_changes,
      inner_root_child_link,
      0,
      None,
      initial_state,
      fn(
        node_output,
        asset_changes_before_node,
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
        let Address { payment_credential: node_payment_credential, .. } =
          node_address

        // 1. Each produced inner node must share the anchor payment credential.
        expect anchor_payment_credential == node_payment_credential

        // 2. Each produced inner node asset must live in the node namespace.
        expect
          bytearray.take(node_asset_name, node_key_prefix_length) == node_key_prefix

        let node_key = bytearray.drop(node_asset_name, node_key_prefix_length)

        // 3. The current node key must match the expected link.
        expect expected_link == Some(node_key)

        // 4. Ordered inner lists must respect the requested key ordering.
        expect
          when ordering_of_inner_node_keys is {
            Ascending ->
              key_fits_between(Less, last_inner_node_key, node_key, None)
            Descending ->
              key_fits_between(Greater, last_inner_node_key, node_key, None)
            Unordered -> True
          }

        // 5. Each produced inner-node datum must be a `Node`.
        expect Node { data: node_data } = node_element_data

        // 6. Each produced inner node must have a minted asset counterpart.
        let (node_mint_qty, asset_changes_after_node) =
          asset_changes_before_node
            |> dict.expect_pop(node_asset_name)

        expect node_mint_qty == 1

        // 7. Delegate application-specific node checks to the caller.
        return(
          asset_changes_after_node,
          node_link,
          inner_node_count + 1,
          Some(node_key),
          node_validator(
            state,
            inner_node_count,
            node_address,
            node_lovelace,
            node_key,
            node_data,
            node_link,
            node_ref_script,
          ),
        )
      },
    )

  expect final_expected_link == None

  return(asset_changes_after_all_nodes, final_state)
}

/// Insert a single `Node` into an existing inner list.
///
/// The anchor may be the `InnerRoot` for the first child or a `Node` for later
/// positions. Finalize with base `linked_list.run_element_with`; mint a whole
/// inner list separately and insert its `InnerRoot` into the outer list with
/// `insert_inner_list_ascending` or `insert_inner_list_descending`.
/// `run_element_with` is required so this helper can reject extra same-policy
/// mints/burns of the reserved root key as well as the node namespace.
///
/// `continued_anchor_element_output` and `new_node_output` must both be
/// selected from `ScriptContext.transaction.outputs`; this helper validates the
/// selected outputs, not the caller's selection method.
pub fn insert_into_inner_list(
  ordering_of_inner_node_keys: ListOrdering,
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: InnerListInsertValidation,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    // 1. The transaction must spend exactly one authentic inner-list anchor.
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
    <-
      authenticate_element_utxo_and_get_info(
        new_node_output,
        list_nft_policy_id,
      )
    let Address { payment_credential: new_node_payment_credential, .. } =
      new_node_address

    // 4. The continued anchor must preserve the full address.
    expect anchor_element_address == cont_anchor_element_address

    // 5. The new node must share the anchor payment credential.
    expect anchor_payment_credential == new_node_payment_credential

    // 6. The continued anchor must preserve the anchor NFT and reference script.
    expect anchor_element_asset_name == cont_anchor_element_asset_name
    expect anchor_element_ref_script == cont_anchor_element_ref_script

    // 7. The new node asset must live in the node namespace.
    expect
      bytearray.take(new_node_asset_name, node_key_prefix_length) == node_key_prefix

    let new_node_key =
      bytearray.drop(new_node_asset_name, node_key_prefix_length)

    let anchor_element_lovelace_change =
      cont_anchor_element_lovelace - anchor_element_lovelace

    // 8. The produced inner element must be a `Node`.
    expect Node { data: new_node_data } = new_node_element_data

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

    when anchor_element_data is {
      Root { .. } -> fail @"Root cannot anchor an inner-list insertion"
      InnerRoot { data: inner_root_data, child_link } -> {
        // 11a. An inner-root anchor must stay inside the node namespace.
        expect
          bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix

        let inner_root_key =
          bytearray.drop(anchor_element_asset_name, node_key_prefix_length)

        // 12a. The continued anchor datum must remain the same inner root.
        expect InnerRoot {
          data: cont_inner_root_data,
          child_link: cont_child_link,
        } = cont_anchor_element_data

        // 13a. The continued inner root must point to the new first child.
        expect cont_child_link == Some(new_node_key)

        // 14a. The continued inner root must preserve its outer-list link.
        expect cont_anchor_element_link == anchor_element_link

        // 15a. The new node must point to the old first child.
        expect new_node_link == child_link

        // 16a. The new key must fit before/after the old first child.
        expect
          when ordering_of_inner_node_keys is {
            Unordered -> True
            Ascending -> key_fits_between(Less, None, new_node_key, child_link)
            Descending ->
              key_fits_between(Greater, None, new_node_key, child_link)
          }

        // 17a. Delegate application-specific inner-list insertion checks.
        expect
          additional_validations(
            anchor_element_input,
            anchor_element_lovelace_change,
            fn(on_inner_root, _on_node) {
              on_inner_root(
                inner_root_key,
                inner_root_data,
                cont_inner_root_data,
                child_link,
              )
            },
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
        // 11b. A node anchor must stay inside the node namespace.
        expect
          bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix

        let anchor_node_key =
          bytearray.drop(anchor_element_asset_name, node_key_prefix_length)

        // 12b. The continued anchor datum must remain a node.
        expect Node { data: cont_anchor_node_data } = cont_anchor_element_data

        // 13b. The continued anchor must point to the new node.
        expect cont_anchor_element_link == Some(new_node_key)

        // 14b. The new node must point to the anchor's old inner successor.
        expect new_node_link == anchor_element_link

        // 15b. The new key must fit between the anchor and its old successor.
        expect
          when ordering_of_inner_node_keys is {
            Unordered -> True
            Ascending ->
              key_fits_between(
                Less,
                Some(anchor_node_key),
                new_node_key,
                anchor_element_link,
              )
            Descending ->
              key_fits_between(
                Greater,
                Some(anchor_node_key),
                new_node_key,
                anchor_element_link,
              )
          }

        // 16b. Delegate application-specific inner-list insertion checks.
        expect
          additional_validations(
            anchor_element_input,
            anchor_element_lovelace_change,
            fn(_on_inner_root, on_node) {
              on_node(anchor_node_key, anchor_node_data, cont_anchor_node_data)
            },
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

/// Mint a whole inner list and insert its `InnerRoot` into the outer list in
/// ascending order; `ordering_of_inner_node_keys` controls the child chain.
///
/// `inner_node_outputs` must follow `new_inner_root.child_link`, then each
/// produced node link, ending at `None`.
/// `continued_anchor_element_output`, `new_inner_root_output`, and every
/// `inner_node_outputs` entry must be selected from
/// `ScriptContext.transaction.outputs`. Callers decide whether that selection
/// is by index, filtering, or another deterministic convention.
///
/// Caller responsibility: use `prepare_state`, `node_validator`, and
/// `final_validator` to validate application data, authorization, lovelace
/// changes, and any allowed extra same-policy asset changes.
pub fn insert_inner_list_ascending(
  ordering_of_inner_node_keys: ListOrdering,
  continued_anchor_element_output: Output,
  new_inner_root_output: Output,
  inputs: List<Input>,
  inner_node_outputs: List<Output>,
  tx_mint: Value,
  prepare_state: InnerRootStatePreparation<state>,
  node_validator: InnerNodeValidation<state>,
  final_validator: InnerListFinalValidation<state>,
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
      prepare_state,
      node_validator,
      final_validator,
    )
  }
}

/// Descending variant of
/// [`insert_inner_list_ascending`](#insert_inner_list_ascending): only the
/// outer `InnerRoot` comparison changes to `Greater`; all other contract rules
/// are identical, including the requirement that all supplied outputs come from
/// `ScriptContext.transaction.outputs`.
pub fn insert_inner_list_descending(
  ordering_of_inner_node_keys: ListOrdering,
  continued_anchor_element_output: Output,
  new_inner_root_output: Output,
  inputs: List<Input>,
  inner_node_outputs: List<Output>,
  tx_mint: Value,
  prepare_state: InnerRootStatePreparation<state>,
  node_validator: InnerNodeValidation<state>,
  final_validator: InnerListFinalValidation<state>,
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
      prepare_state,
      node_validator,
      final_validator,
    )
  }
}

// ## Spending Script Helpers

/// Re-export of the base structural spend gate.
///
/// The same precondition applies here: this is not standalone authorization.
/// It must be paired with a nested/base list minting policy that accepts
/// structural mint/burns only through the matching linked-list mint helpers.
pub const spend_for_adding_or_removing_an_element =
  linked_list.spend_for_adding_or_removing_an_element

/// For spending an individual nested-list element and reproducing it with
/// updated data, without affecting the structure of the nested list.
///
/// The continuation receives:
/// 1. Preserved element address.
/// 2. Change in Lovelace count from input to output.
/// 3. The preserved `Element.link` field.
/// 4. A Church-style selector for `Root`, `InnerRoot`, and `Node` updates.
/// 5. Reference script of the input element, if present.
/// 6. Reference script of the continued element, if present.
///
/// No list-policy mint/burn is allowed for a pure data update.
pub fn spend_for_updating_elements_data(
  element_input_index: Int,
  continued_element_output_index: Int,
  element_input_outref: OutputReference,
  inputs: List<Input>,
  outputs: List<Output>,
  tx_mint: Value,
  additional_validations: fn(
    Address,
    LovelaceChange,
    Link,
    ElementUpdate<Bool>,
    Option<ScriptHash>,
    Option<ScriptHash>,
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
        dict.is_empty(tx_mint |> assets.tokens(list_nft_policy_id)),
      )

    let
      element_address,
      element_lovelace,
      element_asset_name,
      element_data,
      element_link,
      element_ref_script,
    <-
      authenticate_element_utxo_and_get_info(
        element_input.output,
        list_nft_policy_id,
      )

    let
      continued_element_address,
      continued_element_lovelace,
      continued_element_asset_name,
      continued_element_data,
      continued_element_link,
      continued_element_ref_script,
    <-
      authenticate_element_utxo_and_get_info(
        continued_element_output,
        list_nft_policy_id,
      )

    expect and {
        element_address == continued_element_address,
        element_asset_name == continued_element_asset_name,
        element_link == continued_element_link,
      }

    let lovelace_change = continued_element_lovelace - element_lovelace

    when element_data is {
      Root { data: root_data } -> {
        expect element_asset_name == root_key
        expect Root { data: continued_root_data } = continued_element_data
        additional_validations(
          element_address,
          lovelace_change,
          element_link,
          fn(on_root, _on_inner_root, _on_node) {
            on_root(root_data, continued_root_data)
          },
          element_ref_script,
          continued_element_ref_script,
        )
      }
      InnerRoot { data: inner_root_data, child_link } -> {
        expect
          bytearray.take(element_asset_name, node_key_prefix_length) == node_key_prefix
        expect InnerRoot {
          data: continued_inner_root_data,
          child_link: continued_child_link,
        } = continued_element_data
        expect child_link == continued_child_link
        let inner_root_key =
          bytearray.drop(element_asset_name, node_key_prefix_length)
        additional_validations(
          element_address,
          lovelace_change,
          element_link,
          fn(_on_root, on_inner_root, _on_node) {
            on_inner_root(
              inner_root_key,
              inner_root_data,
              continued_inner_root_data,
              child_link,
            )
          },
          element_ref_script,
          continued_element_ref_script,
        )
      }
      Node { data: node_data } -> {
        expect
          bytearray.take(element_asset_name, node_key_prefix_length) == node_key_prefix
        expect Node { data: continued_node_data } = continued_element_data
        let node_key =
          bytearray.drop(element_asset_name, node_key_prefix_length)
        additional_validations(
          element_address,
          lovelace_change,
          element_link,
          fn(_on_root, _on_inner_root, on_node) {
            on_node(node_key, node_data, continued_node_data)
          },
          element_ref_script,
          continued_element_ref_script,
        )
      }
    }
  }
}

// ## Exposed Helpers

/// Church-style branch selector for callbacks that need constructor-specific
/// information while reading a nested-list element.
///
/// Address, Lovelace, `Element.link`, and reference script are common to every
/// constructor and are passed outside this selector by `get_element_info`.
/// Only `InnerRoot` receives a link here, because only `InnerRoot` has the
/// constructor-specific `child_link`.
///
/// The handlers receive:
/// 1. `Root`: data.
/// 2. `InnerRoot`: key, data, and child link.
/// 3. `Node`: key and data.
pub type ElementInfoSelector<a> =
  fn(fn(Data) -> a, fn(NodeKey, Data, Link) -> a, fn(NodeKey, Data) -> a) -> a

/// `get_element_info` continuation.
///
/// Args: Address, Lovelace, `Element.link`, a Church-style selector for
/// constructor-specific data, and reference script.
pub type ElementInfo<a> =
  fn(Address, Lovelace, Link, ElementInfoSelector<a>, Option<ScriptHash>) -> a

/// Root-info continuation, including any reference script.
///
/// Args: Address, Lovelace, root data, root outer link, reference script.
pub type RootElementInfo<a> =
  fn(Address, Lovelace, Data, Link, Option<ScriptHash>) -> a

/// Inner-root-info continuation, including any reference script.
///
/// Args: Address, Lovelace, inner-root key, inner-root data, outer link,
/// child link, reference script.
pub type InnerRootElementInfo<a> =
  fn(Address, Lovelace, NodeKey, Data, Link, Link, Option<ScriptHash>) -> a

/// Node-info continuation, including any reference script.
///
/// Args: Address, Lovelace, node key, node data, inner-list link, reference
/// script.
pub type NodeElementInfo<a> =
  fn(Address, Lovelace, NodeKey, Data, Link, Option<ScriptHash>) -> a

/// Authenticate a nested-list element UTxO and expose its read-only info.
///
/// The callback receives:
/// 1. Element address.
/// 2. Lovelace quantity.
/// 3. The element's outer or inner-list `Element.link`.
/// 4. A Church-style selector for `Root`, `InnerRoot`, and `Node` data.
/// 5. Reference script of the element, if present.
///
/// Root elements must carry the configured root NFT. `InnerRoot` and `Node`
/// elements must carry an NFT under the configured node namespace; the callback
/// receives the stripped node key.
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
          element_link,
          fn(on_root, _on_inner_root, _on_node) { on_root(root_data) },
          element_ref_script,
        )
      }
      InnerRoot { data: inner_root_data, child_link } -> {
        expect
          bytearray.take(element_asset_name, node_key_prefix_length) == node_key_prefix
        let inner_root_key =
          bytearray.drop(element_asset_name, node_key_prefix_length)
        info_validations(
          element_address,
          element_lovelace,
          element_link,
          fn(_on_root, on_inner_root, _on_node) {
            on_inner_root(inner_root_key, inner_root_data, child_link)
          },
          element_ref_script,
        )
      }
      Node { data: node_data } -> {
        expect
          bytearray.take(element_asset_name, node_key_prefix_length) == node_key_prefix
        let node_key =
          bytearray.drop(element_asset_name, node_key_prefix_length)
        info_validations(
          element_address,
          element_lovelace,
          element_link,
          fn(_on_root, _on_inner_root, on_node) { on_node(node_key, node_data) },
          element_ref_script,
        )
      }
    }
  }
}

/// Read root info through `RootElementInfo`.
///
/// The UTxO must carry the configured root NFT and a `Root` datum. The callback
/// receives address, Lovelace, raw root payload data, the root outer link, and
/// the reference script attached to the UTxO, if any.
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

/// Read inner-root info through `InnerRootElementInfo`.
///
/// The UTxO must carry a list NFT whose asset name starts with
/// `node_key_prefix` and must contain an `InnerRoot` datum. The callback
/// receives address, Lovelace, the inner-root key with the prefix stripped, raw
/// inner-root payload data, the outer-list link, the inner child link, and the
/// reference script attached to the UTxO, if any.
pub fn get_inner_root_element_info(
  element_utxo: Output,
  info_validations: InnerRootElementInfo<a>,
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
    let inner_root_key =
      bytearray.drop(element_asset_name, node_key_prefix_length)
    expect InnerRoot { data: inner_root_data, child_link } = element_data

    info_validations(
      element_address,
      element_lovelace,
      inner_root_key,
      inner_root_data,
      element_link,
      child_link,
      element_ref_script,
    )
  }
}

/// Read node info through `NodeElementInfo`.
///
/// The UTxO must carry a list NFT whose asset name starts with
/// `node_key_prefix` and must contain a `Node` datum. The callback receives
/// address, Lovelace, the node key with the prefix stripped, raw node payload
/// data, the inner-list link, and the reference script attached to the UTxO, if
/// any.
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

fn ordered_insert_of_inner_list_helper(
  list_nft_policy_id: PolicyId,
  root_key: RootKey,
  node_key_prefix: NodeKeyPrefix,
  node_key_prefix_length: NodeKeyPrefixLength,
  required_neighbor_ordering: Ordering,
  ordering_of_inner_node_keys: ListOrdering,
  continued_anchor_element_output: Output,
  new_inner_root_output: Output,
  inputs: List<Input>,
  inner_node_outputs: List<Output>,
  tx_mint: Value,
  prepare_state: InnerRootStatePreparation<state>,
  node_validator: InnerNodeValidation<state>,
  final_validator: InnerListFinalValidation<state>,
) -> Bool {
  // 1. The transaction must spend exactly one authentic anchor input.
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

  // 3. The new inner-root output must be authentic.
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
  let Address { payment_credential: new_inner_root_payment_credential, .. } =
    new_inner_root_address

  // 4. The continued anchor must preserve the full address.
  expect anchor_element_address == cont_anchor_element_address

  // 5. The new inner root must share the anchor payment credential.
  expect anchor_payment_credential == new_inner_root_payment_credential

  // 6. The continued anchor must preserve its NFT and reference script.
  expect anchor_element_asset_name == cont_anchor_element_asset_name
  expect anchor_element_ref_script == cont_anchor_element_ref_script

  // 7. The anchor must be a root or inner root and its datum transition valid.
  let
    anchor_key,
    anchor_data,
    cont_anchor_data,
  <-
    with_anchor_element_info(
      anchor_element_data,
      cont_anchor_element_data,
      anchor_element_asset_name,
      root_key,
      node_key_prefix,
      node_key_prefix_length,
    )

  let anchor_element_lovelace_change =
    cont_anchor_element_lovelace - anchor_element_lovelace

  // 8. The new inner-root asset must live in the node namespace.
  expect
    bytearray.take(new_inner_root_asset_name, node_key_prefix_length) == node_key_prefix

  let new_inner_root_key =
    bytearray.drop(new_inner_root_asset_name, node_key_prefix_length)

  // 9. The new inner-root key must fit between the outer-list neighbors.
  expect
    key_fits_between(
      required_neighbor_ordering,
      anchor_key,
      new_inner_root_key,
      anchor_element_link,
    )

  // 10. The continued anchor must point to the new inner root.
  expect cont_anchor_element_link == Some(new_inner_root_key)

  // 11. The new inner root must point to the anchor's old outer successor.
  expect new_inner_root_link == anchor_element_link

  // 12. The produced outer element must be an `InnerRoot`.
  expect InnerRoot { data: inner_root_data, child_link: inner_root_child_link } =
    new_inner_root_element_data

  // 13. Insertion must mint the new inner-root NFT and return other assets.
  let remaining_list_asset_changes =
    validate_list_nft_and_get_other_list_assets(
      tx_mint,
      list_nft_policy_id,
      new_inner_root_asset_name,
      1,
    )

  // 14. Build caller state from the new inner root.
  let initial_state =
    prepare_state(
      new_inner_root_lovelace,
      new_inner_root_key,
      inner_root_data,
      inner_root_child_link,
      new_inner_root_ref_script,
    )

  // 15. Validate the produced inner-node chain.
  let
    final_remaining_list_asset_changes,
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
      remaining_list_asset_changes,
      initial_state,
      node_validator,
    )

  // 16. No unaccounted reserved list asset change may remain.
  expect
    validate_no_reserved_list_asset_changes(
      final_remaining_list_asset_changes,
      root_key,
      node_key_prefix,
      node_key_prefix_length,
    )

  // 17. Delegate final application-specific checks to the caller.
  expect
    final_validator(
      anchor_element_input,
      anchor_element_lovelace_change,
      anchor_key,
      anchor_data,
      cont_anchor_data,
      anchor_element_link,
      final_state,
      final_remaining_list_asset_changes,
    )

  // Done.
  True
}
