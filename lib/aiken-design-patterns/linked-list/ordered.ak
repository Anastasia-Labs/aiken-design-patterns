use aiken/collection/dict.{Dict}
use aiken/collection/list
use aiken_design_patterns/linked_list/internal/predicates.{
  is_member, is_not_member, key_added,
}
use aiken_design_patterns/linked_list/types.{NodeDatum, NodeKey}
use aiken_design_patterns/linked_list/unordered
use aiken_design_patterns/linked_list/utils.{
  get_key, get_link, get_raw_key_and_link, has_data_cs,
}
use cardano/assets.{AssetName, PolicyId, flatten}
use cardano/transaction.{InlineDatum, Output}

// ## Predicates (used outside of list validators)

/// Prove that a node belongs to the given list and is its root.
pub fn prove_is_root_node(policy_id: PolicyId, node: Output) -> Bool {
  unordered.prove_is_root_node(policy_id, node)
}

/// Prove that a node belongs to the given list and is its last node.
pub fn prove_is_last_node(policy_id: PolicyId, node: Output) -> Bool {
  unordered.prove_is_last_node(policy_id, node)
}

/// Prove that the given list is empty, as witnessed by a node that
/// is both the root and last node of the list.
pub fn prove_is_empty_list(policy_id: PolicyId, node: Output) -> Bool {
  unordered.prove_is_empty_list(policy_id, node)
}

/// Prove that a key is a member of the given list, as witnessed by a node
/// that satisfies the membership predicate with the key.
pub fn prove_is_member(policy_id: PolicyId, key: NodeKey, node: Output) -> Bool {
  unordered.prove_is_member(policy_id, key, node)
}

/// Prove that a key is a member of the given list, as witnessed by a node
/// that satisfies the non-membership predicate with the key.
pub fn prove_is_not_member(
  policy_id: PolicyId,
  key: NodeKey,
  node: Output,
) -> Bool {
  // Find the token:
  expect has_data_cs(policy_id, node.value)
  // Check the datum:
  expect InlineDatum(node_datum_raw) = node.datum
  expect node_datum: NodeDatum = node_datum_raw
  expect is_not_member(key, node_datum.key, node_datum.link)
  // Done.
  True
}

// ## State integrity handlers (used in list spending validator)

/// Detect whether the list's minting policy is invoked in the transaction,
/// so that the spending validator can forward to it.
pub fn list_state_transition(node_mint: Dict<AssetName, Int>) -> Bool {
  unordered.list_state_transition(node_mint)
}

/// Modify the `data` field of a list node without changing the `key` and
/// `link` fields.
pub fn modify_data(
  node_mint: Dict<AssetName, Int>,
  own_input: Output,
  own_output: Output,
  node_nft_policy_id: ByteArray,
  node_nft_asset_name: ByteArray,
) -> Bool {
  unordered.modify_data(
    node_mint,
    own_input,
    own_output,
    node_nft_policy_id,
    node_nft_asset_name,
  )
}

/// Initialize an empty unordered list.
///
/// Application code must ensure that this action can happen only once.
pub fn init(
  node_outputs: List<Output>,
  node_mint: Dict<AssetName, Int>,
  node_cs: ByteArray,
) -> Bool {
  unordered.init(node_outputs, node_mint, node_cs)
}

/// Deinitialize an empty unordered list.
pub fn deinit(
  node_inputs: List<Output>,
  node_mint: Dict<AssetName, Int>,
  node_cs: ByteArray,
) -> Bool {
  unordered.deinit(node_inputs, node_mint, node_cs)
}

/// Prepend a new node to the beginning of the list.
///
/// The index arguments in this function are relative to the node_inputs
/// and node_outputs. They are NOT absolute.
pub fn prepend(
  key_to_prepend: NodeKey,
  prepended_node_output_index: Int,
  anchor_node_output_index: Int,
  node_inputs: List<Output>,
  node_outputs: List<Output>,
  node_mint: Dict<AssetName, Int>,
) -> Bool {
  // key_to_prepend must not be a member of the list before the transaction,
  //   as witnessed by anchor_node_input.
  expect Some(anchor_node_input) = list.head(node_inputs)
  let anchor_node_input_raw_key_and_link =
    get_raw_key_and_link(anchor_node_input)
  expect
    is_not_member(
      key_to_prepend,
      node_key: get_key(anchor_node_input_raw_key_and_link),
      node_link: get_link(anchor_node_input_raw_key_and_link),
    )

  // Same conditions as unordered.prepend_unsafe.
  unordered.prepend_unsafe(
    key_to_prepend,
    prepended_node_output_index,
    anchor_node_output_index,
    node_inputs,
    node_outputs,
    node_mint,
  )
}

/// Append a new node to the end of the list.
/// 
/// The index arguments in this function are relative to the node_inputs
/// and node_outputs. They are NOT absolute.
pub fn append(
  key_to_append: NodeKey,
  appended_node_output_index: Int,
  anchor_node_output_index: Int,
  node_inputs: List<Output>,
  node_outputs: List<Output>,
  node_mint: Dict<AssetName, Int>,
) -> Bool {
  // key_to_append must not be a member of the list before the transaction,
  //   as witnessed by anchor_node_input.
  expect Some(anchor_node_input) = list.head(node_inputs)
  let anchor_node_input_raw_key_and_link =
    get_raw_key_and_link(anchor_node_input)
  expect
    is_not_member(
      key_to_append,
      node_key: get_key(anchor_node_input_raw_key_and_link),
      node_link: get_link(anchor_node_input_raw_key_and_link),
    )

  // Same conditions as unordered.append_unsafe.
  unordered.append_unsafe(
    key_to_append,
    appended_node_output_index,
    anchor_node_output_index,
    node_inputs,
    node_outputs,
    node_mint,
  )
}

/// Insert a node into the list.
///
/// The index arguments in this function are relative to the node_inputs
/// and node_outputs. They are NOT absolute.
pub fn insert(
  key_to_insert: NodeKey,
  inserted_node_output_index: Int,
  anchor_node_output_index: Int,
  node_inputs: List<Output>,
  node_outputs: List<Output>,
  node_mint: Dict<AssetName, Int>,
) -> Bool {
  // Verify mint:
  // 1. Let key_to_insert be the key being inserted.
  // 2. The transaction’s sole effect on the list is to add key_to_insert.
  expect key_added(key_to_insert, node_mint)

  // Verify inputs:
  // 3. node_inputs must be a singleton. Let anchor_node_input be its sole node.
  expect list.length(node_inputs) == 1
  expect Some(anchor_node_input) = list.head(node_inputs)
  expect InlineDatum(anchor_node_input_datum) = anchor_node_input.datum
  expect parsed_anchor_node_input_datum: NodeDatum = anchor_node_input_datum

  // 4. key_to_insert must not be a member of the list before the transaction,
  //    as witnessed by anchor_node_input.
  expect
    is_not_member(
      key_to_insert,
      parsed_anchor_node_input_datum.key,
      parsed_anchor_node_input_datum.link,
    )

  // Verify outputs:
  // 5. node_outputs must have exactly two nodes: inserted_node and anchor_node_output.
  expect list.length(node_outputs) == 2
  expect Some(inserted_node_output) =
    list.at(node_outputs, inserted_node_output_index)
  let inserted_node_output_raw_key_and_link =
    get_raw_key_and_link(inserted_node_output)
  expect Some(anchor_node_output) =
    list.at(node_outputs, anchor_node_output_index)
  expect InlineDatum(anchor_node_output_datum) = anchor_node_output.datum
  expect parsed_anchor_node_output_datum: NodeDatum = anchor_node_output_datum

  // 6. key_to_insert must be a member of the list after the transaction,
  //    as witnessed by inserted_node.
  expect
    is_member(key_to_insert, get_key(inserted_node_output_raw_key_and_link))

  // 7. anchor_node output must link to key_to_insert.
  let anchor_node_new_datum =
    NodeDatum {
      key: parsed_anchor_node_input_datum.key,
      link: key_to_insert,
      data: parsed_anchor_node_input_datum.data,
    }

  // 8. anchor_node_input and inserted_node must match on the link field.
  //    In other words, they must both link to the same key.
  expect
    parsed_anchor_node_input_datum.link == get_link(
      inserted_node_output_raw_key_and_link,
    )

  // 9. inserted_node must not contain any other non-ADA tokens.
  expect list.length(flatten(inserted_node_output.value)) == 2

  // Verify immutable data:
  // 10. anchor_node_input must match anchor node output on address, value,
  //     and datum except for the link field.
  expect anchor_node_input.address == anchor_node_output.address
  expect anchor_node_input.value == anchor_node_output.value
  expect anchor_node_new_datum == parsed_anchor_node_output_datum

  // 11. inserted_node must match anchor_node_output on address.
  expect inserted_node_output.address == anchor_node_output.address

  // Done.
  True
}

/// Remove a non-root node from the list.
///
/// The index arguments in this function are relative to the node_inputs
/// and node_outputs. They are NOT absolute.
pub fn remove(
  key_to_remove: NodeKey,
  removed_node_input_index: Int,
  anchor_node_input_index: Int,
  node_inputs: List<Output>,
  node_outputs: List<Output>,
  node_mint: Dict<AssetName, Int>,
) -> Bool {
  // Same conditions as unordered.remove.
  unordered.remove(
    key_to_remove,
    removed_node_input_index,
    anchor_node_input_index,
    node_inputs,
    node_outputs,
    node_mint,
  )
}
