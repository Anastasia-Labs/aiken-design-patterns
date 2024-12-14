use aiken/collection/dict.{Dict}
use aiken/collection/list
use aiken_design_patterns/linked_list/constants
use aiken_design_patterns/linked_list/types.{Empty, NodeDatum, NodeKey}
use aiken_design_patterns/linked_list/utils.{
  get_key, get_link, get_raw_key_and_link, serialize_key,
}
use cardano/assets.{AssetName, flatten, quantity_of}
use cardano/transaction.{InlineDatum, Output}

pub fn list_state_transition(node_mint: Dict<AssetName, Int>) {
  // 1. Tokens of the list's minting policy must be minted or burned.
  dict.is_empty(node_mint) == False
}

pub fn modify_data(
  node_mint: Dict<AssetName, Int>,
  own_input: Output,
  own_output: Output,
  node_nft_policy_id: ByteArray,
  node_nft_asset_name: ByteArray,
) -> Bool {
  // 1. Tokens of the list's minting policy must *not* be minted or burned.
  expect dict.is_empty(node_mint)

  // 2. Let own_input be the node utxo input for which this rule is evaluated.
  // 3. Let own_output be an output of the transaction indicated by the redeemer
  //    of the spending validator.
  // 4. The node NFT of the list must be present in own_input.
  expect
    quantity_of(own_input.value, node_nft_policy_id, node_nft_asset_name) == 1

  // 5. The value must match in own_input and own_output.
  expect own_input.value == own_output.value

  // 6. The key and link fields must match in own_input and own_output.
  let input_key_and_link = get_raw_key_and_link(own_input)
  let output_key_and_link = get_raw_key_and_link(own_output)
  expect input_key_and_link == output_key_and_link

  // Done.
  True
}

pub fn is_root_node(node_key: NodeKey) {
  node_key == Empty
}

pub fn is_last_node(node_link: NodeKey) {
  node_link == Empty
}

pub fn is_empty_list(node_key: NodeKey, node_link: NodeKey) {
  and {
    is_root_node(node_key),
    is_last_node(node_link),
  }
}

pub fn key_added(key: NodeKey, node_mint: Dict<AssetName, Int>) {
  and {
    dict.size(node_mint) == 1,
    dict.get(node_mint, serialize_key(key)) == Some(1),
  }
}

pub fn key_removed(key: NodeKey, node_mint: Dict<AssetName, Int>) {
  and {
    dict.size(node_mint) == 1,
    dict.get(node_mint, serialize_key(key)) == Some(-1),
  }
}

pub fn is_member(k: NodeKey, node_key: NodeKey) {
  k == node_key
}

// Application code must ensure that this action can happen only once
pub fn init(
  node_outputs: List<Output>,
  node_mint: Dict<AssetName, Int>,
  node_cs: ByteArray,
) {
  // 1. The transaction's sole effect on the list is to add the root key.
  expect key_added(Empty, node_mint)

  // 2. The list must be empty after the transaction, as proved by an output
  // root_node that holds the minted root node NFT.
  expect Some(root_node) = list.head(node_outputs)
  let raw_key_and_link = get_raw_key_and_link(root_node)
  expect is_empty_list(get_key(raw_key_and_link), get_link(raw_key_and_link))
  expect quantity_of(root_node.value, node_cs, constants.node_prefix) == 1

  // 3. The root_node must not contain any other non-ADA tokens.
  expect list.length(flatten(root_node.value)) == 2

  // Done.
  True
}

pub fn deinit(
  node_inputs: List<Output>,
  node_mint: Dict<AssetName, Int>,
  node_cs: ByteArray,
) {
  // 1. The transaction's sole effect on the list is to remove the root key.
  expect key_removed(Empty, node_mint)

  // 2. The list must be empty before the transaction, as proved by an input
  //    root_node that holds the minted root node NFT.
  expect Some(root_node) = list.head(node_inputs)
  let raw_key_and_link = get_raw_key_and_link(root_node)
  expect is_empty_list(get_key(raw_key_and_link), get_link(raw_key_and_link))
  expect quantity_of(root_node.value, node_cs, constants.node_prefix) == 1

  // Done.
  True
}

// An application using a key-unordered list MUST only add nodes with unique
// keys to the list. Duplicate keys break the linked list data structure.
// 
// The index arguments in this function are relative to the node_inputs
// and node_outputs. They are NOT absolute.
pub fn prepend_unsafe(
  key_to_prepend: NodeKey,
  prepended_node_index: Int,
  anchor_node_output_index: Int,
  node_inputs: List<Output>,
  node_outputs: List<Output>,
  node_mint: Dict<AssetName, Int>,
) {
  // # Verify the mint:
  // 1. Let key_to_prepend be the key being prepended.
  // 2. The transaction's sole effect on the list is to add key_to_prepend.
  expect key_added(key_to_prepend, node_mint)

  // # Verify the inputs:
  // 3. node_inputs must be a singleton. Let anchor_node_input be its sole node.
  expect list.length(node_inputs) == 1
  expect Some(anchor_node_input) = list.head(node_inputs)
  expect InlineDatum(anchor_node_input_datum) = anchor_node_input.datum
  expect parsed_anchor_node_input_datum: NodeDatum = anchor_node_input_datum

  // 4. anchor_node_input must be the root node of the list.
  expect is_root_node(parsed_anchor_node_input_datum.key)

  // # Verify the outputs:
  // 5. node_outputs must have exactly two nodes: prepended_node and anchor_node_output.
  expect list.length(node_outputs) == 2
  expect Some(prepended_node) = list.at(node_outputs, prepended_node_index)
  let prepended_node_raw_key_and_link = get_raw_key_and_link(prepended_node)
  expect Some(anchor_node_output) =
    list.at(node_outputs, anchor_node_output_index)
  expect InlineDatum(anchor_node_output_datum) = anchor_node_output.datum
  expect parsed_anchor_node_output_datum: NodeDatum = anchor_node_output_datum

  // 6. key_to_prepend must be a member of the list after the transaction,
  //    as witnessed by prepended_node.
  expect is_member(key_to_prepend, get_key(prepended_node_raw_key_and_link))

  // 7. anchor_node input and prepended node must match on the link_field.
  //    In other words, they must both link to the same key.
  expect
    parsed_anchor_node_input_datum.link == get_link(
      prepended_node_raw_key_and_link,
    )

  // 8. anchor_node_output must link to key_to_prepend.
  let anchor_node_new_datum =
    NodeDatum {
      key: parsed_anchor_node_input_datum.key,
      link: key_to_prepend,
      data: parsed_anchor_node_input_datum.data,
    }

  // 9. prepended_node must not contain any other non-ADA tokens.
  expect list.length(flatten(prepended_node.value)) == 2

  // # Verify immutable data:
  // 10. anchor node input must match anchor node output on address, value,
  //     and datum except for the link field.
  expect anchor_node_input.address == anchor_node_output.address
  expect anchor_node_input.value == anchor_node_output.value
  expect anchor_node_new_datum == parsed_anchor_node_output_datum

  // 11. prepended_node must match anchor_node_output on address.
  expect prepended_node.address == anchor_node_output.address

  // Done.
  True
}

// An application using a key-unordered list MUST only add nodes with unique
// keys to the list. Duplicate keys break the linked list data structure.
// 
// The index arguments in this function are relative to the node_inputs
// and node_outputs. They are NOT absolute.
pub fn append_unsafe(
  key_to_append: NodeKey,
  appended_node_index: Int,
  anchor_node_output_index: Int,
  node_inputs: List<Output>,
  node_outputs: List<Output>,
  node_mint: Dict<AssetName, Int>,
) {
  // # Verify the mint:
  // 1. Let key_to_append be the key being appended.
  // 2. The transaction's sole effect on the list is to add key_to_append.
  expect key_added(key_to_append, node_mint)

  // 3. node_inputs must be a singleton. Let anchor_node_input be its sole node.
  expect list.length(node_inputs) == 1
  expect Some(anchor_node_input) = list.head(node_inputs)
  expect InlineDatum(anchor_node_input_datum) = anchor_node_input.datum
  expect parsed_anchor_node_input_datum: NodeDatum = anchor_node_input_datum
  let anchor_node_raw_key_and_link = get_raw_key_and_link(anchor_node_input)

  // 4. anchor_node_input must be the last node of the list before the transaction.
  expect is_last_node(get_link(anchor_node_raw_key_and_link))

  // # Verify the outputs:
  // 5. node_outputs must have exactly two nodes: appended_node and anchor_node_output.
  expect list.length(node_outputs) == 2
  expect Some(appended_node) = list.at(node_outputs, appended_node_index)
  let appended_node_raw_key_and_link = get_raw_key_and_link(appended_node)
  expect Some(anchor_node_output) =
    list.at(node_outputs, anchor_node_output_index)
  expect InlineDatum(anchor_node_output_datum) = anchor_node_output.datum
  expect parsed_anchor_node_output_datum: NodeDatum = anchor_node_output_datum

  // 6. key_to_append must be a member of the list after the transaction,
  //    as witnessed by appended_node.
  expect is_member(key_to_append, get_key(appended_node_raw_key_and_link))

  // 7. appended_node must be the last node of the list after the transaction.
  expect is_last_node(get_link(appended_node_raw_key_and_link))

  // 8. anchor node output must link to key to append.
  let anchor_node_new_datum =
    NodeDatum {
      key: parsed_anchor_node_input_datum.key,
      link: key_to_append,
      data: parsed_anchor_node_input_datum.data,
    }

  // 9. appended_node must not contain any other non-ADA tokens.
  expect list.length(flatten(appended_node.value)) == 2

  // # Verify immutable data:
  // 10. anchor_node input must match anchor_node output on address, value,
  //     and datum except for the link field.
  expect anchor_node_input.address == anchor_node_output.address
  expect anchor_node_input.value == anchor_node_output.value
  expect anchor_node_new_datum == parsed_anchor_node_output_datum

  // 11. appended_node must match anchor_node_output on address.
  expect appended_node.address == anchor_node_output.address

  // Done.
  True
}

// The index arguments in this function are relative to the node_inputs
// and node_outputs. They are NOT absolute.
pub fn remove(
  key_to_remove: NodeKey,
  removed_node_input_index: Int,
  anchor_node_input_index: Int,
  node_inputs: List<Output>,
  node_outputs: List<Output>,
  node_mint: Dict<AssetName, Int>,
) {
  // # Verify the mint:
  // 1. Let key_to_remove be the key being removed.
  // 2. The transaction's sole effect on the list is to remove key_to_remove.
  expect key_removed(key_to_remove, node_mint)

  // # Verify the inputs:
  // 3. node_inputs must have exactly two nodes: removed_node and anchor_node_input.
  expect list.length(node_inputs) == 2
  expect Some(removed_node_input) =
    list.at(node_inputs, removed_node_input_index)
  let removed_node_raw_key_and_link = get_raw_key_and_link(removed_node_input)
  expect Some(anchor_node_input) = list.at(node_inputs, anchor_node_input_index)
  expect InlineDatum(anchor_node_input_datum) = anchor_node_input.datum
  expect parsed_anchor_node_input_datum: NodeDatum = anchor_node_input_datum

  // 4. key_to_remove must be a member of the list before the transaction,
  //    as witnessed by removed_node.
  expect is_member(key_to_remove, get_key(removed_node_raw_key_and_link))

  // 5. anchor_node_input must link to key_to_remove.
  expect parsed_anchor_node_input_datum.link == key_to_remove

  // # Verify the outputs:
  // 6. node_outputs must be a singleton. Let anchor_node_output be its sole node.
  expect list.length(node_outputs) == 1
  expect Some(anchor_node_output) = list.head(node_outputs)
  expect InlineDatum(anchor_node_output_datum) = anchor_node_output.datum
  expect parsed_anchor_node_output_datum: NodeDatum = anchor_node_output_datum

  // 7. anchor_node_output and removed_node must match on the link field.
  //    In other words, they must both link to the same key.
  let anchor_node_new_datum =
    NodeDatum {
      key: parsed_anchor_node_input_datum.key,
      link: get_link(removed_node_raw_key_and_link),
      data: parsed_anchor_node_input_datum.data,
    }

  // # Verify immutable data:
  // 8. anchor_node_input must match anchor_node_output on address, value,
  //    and datum except for the link field.
  expect anchor_node_input.address == anchor_node_output.address
  expect anchor_node_input.value == anchor_node_output.value
  expect anchor_node_new_datum == parsed_anchor_node_output_datum

  // Done.
  True
}
