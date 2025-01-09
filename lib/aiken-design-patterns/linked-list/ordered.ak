use aiken/builtin
use aiken/collection/dict.{Dict, has_key}
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken/primitive/bytearray
use aiken_scott_utils/types.{Scott4}
use cardano/assets.{AssetName, PolicyId, Value, flatten, quantity_of, to_dict}
use cardano/transaction.{InlineDatum, Input, Output}

// # Data types, constants, and accessors

pub type Key =
  AssetName

pub type HeadKey =
  Key

pub type NodeKeyPrefix =
  ByteArray

pub type NodeKeyPrefixLength =
  Int

pub type Eval =
  fn(HeadKey, NodeKeyPrefix, NodeKeyPrefixLength) -> Bool

pub type HeadEval =
  fn(HeadKey) -> Bool

pub type NodeEval =
  fn(NodeKeyPrefix, NodeKeyPrefixLength) -> Bool

pub fn run_eval_with(
  reader: Eval,
  head_key: HeadKey,
  node_key_prefix: NodeKeyPrefix,
  node_key_prefix_length: NodeKeyPrefixLength,
) -> Bool {
  reader(head_key, node_key_prefix, node_key_prefix_length)
}

pub fn run_head_with(
  reader: HeadEval,
  head_key: HeadKey,
) -> Bool {
  reader(head_key)
}

pub fn run_node_with(
  reader: NodeEval,
  node_key_prefix: NodeKeyPrefix,
  node_key_prefix_length: NodeKeyPrefixLength,
) -> Bool {
  reader(node_key_prefix, node_key_prefix_length)
}

pub type Node<head_data, link_data> {
  data: Data,
  next_link: Option<ByteArray>,
}

type GenericNode =
  Node<Data, Data>

pub type NodeInfo<result> =
  Scott4<ScriptHash, Key, Data, Option<ByteArray>, result>

fn unsafe_get_data_and_link(node_output: Output) -> (Data, Data) {
  expect InlineDatum(node_output_datum) = node_output.datum
  let constr_fields = builtin.un_constr_data(node_output_datum).2nd
  let data = builtin.head_list(constr_fields)
  let link = builtin.head_list(builtin.tail_list(constr_fields))
  (data, link)
}

pub fn authenticate_node_utxo_and_get_info(
  element_utxo: Output,
  nft_policy_id: PolicyId,
  return: NodeInfo<result>,
) -> result {
  // 1. The UTxO must be at a script address (staking part is not validated).
  // 2. Its datum must be inlined.
  expect Output {
    address: Address { payment_credential: Script(output_script_hash), .. },
    value,
    datum: InlineDatum(utxo_datum_data),
    ..
  } = element_utxo

  // 3. UTxO's datum must be properly structured.
  expect Node { data, next_link } = utxo_datum_data

  // 4. Apart from ADA, only one NFT must be included in the UTxO, such that its
  //    policy ID matched the provided one, and its quantity equals one.
  let
    nft_symbol,
    nft_name,
    nft_qty,
  <- utils.get_single_asset_from_value_apart_from_ada(value)
  expect and {
      nft_symbol == nft_policy_id,
      nft_qty == 1,
    }

  return(output_script_hash, nft_name, data, next_link)
}

pub fn get_node_outputs(
  outputs: List<Output>,
  policy_id: PolicyId,
) -> List<Output> {
  outputs
    |> list.filter(
        fn(output) {
          let Output { value, .. } = output
          has_data_cs(policy_id, value)
        },
      )
}

pub fn get_node_inputs(inputs: List<Input>, policy_id: PolicyId) -> List<Output> {
  filter_map_pre(
    inputs,
    fn(output) {
      let Output { value, .. } = output
      has_data_cs(policy_id, value)
    },
    fn(input) {
      let Input { output, .. } = input
      output
    },
  )
}

// ## Predicates (used outside of list validators)

/// Prove that a node belongs to the given list and is its root.
pub fn prove_is_root_node(policy_id: PolicyId, node: Output) -> Bool {
  // Check the datum:
  expect InlineDatum(node_datum_raw) = node.datum
  expect node_datum: NodeDatum = node_datum_raw
  expect is_root_node(node_datum.key)
  // Check the token:
  expect quantity_of(node.value, policy_id, node_prefix) == 1
  // Done.
  True
}

/// Prove that a node belongs to the given list and is its last node.
pub fn prove_is_last_node(policy_id: PolicyId, node: Output) -> Bool {
  // Check the datum:
  expect InlineDatum(node_datum_raw) = node.datum
  expect node_datum: NodeDatum = node_datum_raw
  expect is_last_node(node_datum.link)
  // Check the token:
  expect quantity_of(node.value, policy_id, serialize_key(node_datum.key)) == 1
  // Done.
  True
}

/// Prove that the given list is empty, as witnessed by a node that
/// is both the root and last node of the list.
pub fn prove_is_empty_list(policy_id: PolicyId, node: Output) -> Bool {
  // Check the datum:
  expect InlineDatum(node_datum_raw) = node.datum
  expect node_datum: NodeDatum = node_datum_raw
  expect is_empty_list(node_datum.key, node_datum.link)
  // Check the token:
  expect quantity_of(node.value, policy_id, node_prefix) == 1
  // Done.
  True
}

/// Prove that a key is a member of the given list, as witnessed by a node
/// that satisfies the membership predicate with the key.
pub fn prove_is_member(policy_id: PolicyId, key: NodeKey, node: Output) -> Bool {
  // Check the datum:
  expect InlineDatum(node_datum_raw) = node.datum
  expect node_datum: NodeDatum = node_datum_raw
  expect is_member(key, node_datum.key)
  // Check the token:
  expect quantity_of(node.value, policy_id, serialize_key(key)) == 1
  // Done.
  True
}

/// Prove that a key is a member of the given list, as witnessed by a node
/// that satisfies the non-membership predicate with the key.
pub fn prove_is_not_member(
  policy_id: PolicyId,
  key: NodeKey,
  node: Output,
) -> Bool {
  // Check the datum:
  expect InlineDatum(node_datum_raw) = node.datum
  expect node_datum: NodeDatum = node_datum_raw
  expect is_not_member(key, node_datum.key, node_datum.link)
  // Check the token:
  expect quantity_of(node.value, policy_id, serialize_key(node_datum.key)) == 1
  // Done.
  True
}

// ## State integrity handlers (used in list spending validator)

/// Detect whether the list's minting policy is invoked in the transaction,
/// so that the spending validator can forward to it.
pub fn list_state_transition(node_mint: Dict<AssetName, Int>) -> Bool {
  // 1. Tokens of the list's minting policy must be minted or burned.
  dict.is_empty(node_mint) == False
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

// ## State transition handlers (used in list minting policy)

/// Initialize an empty list.
pub fn init(
  nonce_out_ref: OutputReference,
  node_output: Output,
  expected_destination_script_hash: ScriptHash,
  node_nft_policy_id: PolicyId,
  head_data_validator: fn(Data) -> Bool,
  tx_inputs: List<Input>,
  tx_mint: Value,
) -> HeadEval {
  // 1. The nonce UTxO must be spent.
  expect utils.utxo_is_spent(tx_inputs, nonce_out_ref)

  // 2. Only one token must be minted with linked list's authentication policy.
  expect [Pair(mint_name, mint_qty)] =
    tx_mint |> assets.tokens(node_nft_policy_id) |> dict.to_pairs

  // 3. The produced UTxO must only contain the authentication/key NFT.
  // 4. Its datum must be properly structured.
  // 5. The payment part of its address must be a `Script`.
  let
    node_script_hash,
    node_asset_name,
    node_data,
    node_link,
  <-
    authenticate_node_utxo_and_get_info(
      node_output,
      node_nft_policy_id,
    )
  fn(head_key: HeadKey) -> Bool {
    and {
      // 6. The minted asset must be included in the produced UTxO.
      mint_name == node_asset_name,
      // 7. Only one NFT must be minted.
      mint_qty == 1,
      // 8. The UTxO must be produced at the expected script.
      node_script_hash == expected_destination_script_hash,
      // 9. The authentication NFT must have the head's hardcoded name.
      node_asset_name == head_key,
      // 10. Head's contained `Data` must pass the provided validation logic.
      head_data_validator(node_data),
      // 11. Produced head must have no links/children.
      node_link == None,
    }
  }
}

/// Deinitialize an empty unordered list.
pub fn deinit(
  node_output: Output,
  expected_script_hash: ScriptHash,
  node_nft_policy_id: PolicyId,
  head_data_validator: fn(Data) -> Bool,
  tx_inputs: List<Input>,
  tx_mint: Value,
) -> HeadEval {
  // 1. Only one token must be burnt with linked list's authentication policy.
  expect [Pair(mint_name, mint_qty)] =
    tx_mint |> assets.tokens(node_nft_policy_id) |> dict.to_pairs

  // 2. The spent UTxO must only contain the authentication/key NFT.
  // 3. Its datum must be properly structured.
  // 4. The payment part of its address must be a `Script`.
  let
    node_script_hash,
    node_asset_name,
    node_data,
    node_link,
  <-
    authenticate_node_utxo_and_get_info(
      node_output,
      node_nft_policy_id,
    )
  fn(head_key: HeadKey) -> Bool {
    and {
      // 5. The minted asset must be included in the spent UTxO.
      mint_name == node_asset_name,
      // 6. Only one NFT must be burnt.
      mint_qty == -1,
      // 7. The UTxO must be coming from the expected script.
      node_script_hash == expected_script_hash,
      // 8. The authentication NFT must have the head's hardcoded name.
      node_asset_name == head_key,
      // 9. Head's contained `Data` must pass the provided validation logic.
      head_data_validator(node_data),
      // 10. Spent head must have no links/children.
      node_link == None,
    }
  }
}

/// Prepend a new node to the beginning of the list.
///
/// The index arguments in this function are relative to the node_inputs
/// and node_outputs. They are NOT absolute.
pub fn prepend(
  key_to_prepend: NodeKey,
  prepended_node_index: Int,
  anchor_node_output_index: Int,
  node_inputs: List<Output>,
  node_outputs: List<Output>,
  node_mint: Dict<AssetName, Int>,
) -> Bool {
  // Verify the mint:
  // 1. Let key_to_prepend be the key being prepended.
  // 2. The transaction's sole effect on the list is to add key_to_prepend.
  expect key_added(key_to_prepend, node_mint)

  // Verify the inputs:
  // 3. node_inputs must be a singleton. Let anchor_node_input be its sole node.
  expect list.length(node_inputs) == 1
  expect Some(anchor_node_input) = list.head(node_inputs)
  expect InlineDatum(anchor_node_input_datum) = anchor_node_input.datum
  expect parsed_anchor_node_input_datum: NodeDatum = anchor_node_input_datum

  // 4. anchor_node_input must be the root node of the list.
  expect is_root_node(parsed_anchor_node_input_datum.key)

  // Verify the outputs:
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

  // Verify immutable data:
  // 10. anchor node input must match anchor node output on address, value,
  //     and datum except for the link field.
  expect anchor_node_input.address == anchor_node_output.address
  expect anchor_node_input.value == anchor_node_output.value
  expect anchor_node_new_datum == parsed_anchor_node_output_datum

  // 11. prepended_node must match anchor_node_output on address.
  expect prepended_node.address == anchor_node_output.address

  // 12. key_to_prepend must not be a member of the list before the transaction,
  //     as witnessed by anchor_node_input.
  expect
    is_not_member(
      key_to_prepend,
      node_key: parsed_anchor_node_input_datum.key,
      node_link: parsed_anchor_node_input_datum.link,
    )

  // Done.
  True
}

/// Append a new node to the end of the list.
///
/// The index arguments in this function are relative to the node_inputs
/// and node_outputs. They are NOT absolute.
pub fn append(
  key_to_append: NodeKey,
  appended_node_index: Int,
  anchor_node_output_index: Int,
  node_inputs: List<Output>,
  node_outputs: List<Output>,
  node_mint: Dict<AssetName, Int>,
) -> Bool {
  // Verify the mint:
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

  // Verify the outputs:
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

  // Verify immutable data:
  // 10. anchor_node input must match anchor_node output on address, value,
  //     and datum except for the link field.
  expect anchor_node_input.address == anchor_node_output.address
  expect anchor_node_input.value == anchor_node_output.value
  expect anchor_node_new_datum == parsed_anchor_node_output_datum

  // 11. appended_node must match anchor_node_output on address.
  expect appended_node.address == anchor_node_output.address

  // 12. key_to_append must not be a member of the list before the transaction,
  //     as witnessed by anchor_node_input.
  expect
    is_not_member(
      key_to_append,
      node_key: parsed_anchor_node_input_datum.key,
      node_link: parsed_anchor_node_input_datum.link,
    )

  // Done.
  True
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
  // Verify the mint:
  // 1. Let key_to_remove be the key being removed.
  // 2. The transaction's sole effect on the list is to remove key_to_remove.
  expect key_removed(key_to_remove, node_mint)

  // Verify the inputs:
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

  // Verify the outputs:
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

  // Verify immutable data:
  // 8. anchor_node_input must match anchor_node_output on address, value,
  //    and datum except for the link field.
  expect anchor_node_input.address == anchor_node_output.address
  expect anchor_node_input.value == anchor_node_output.value
  expect anchor_node_new_datum == parsed_anchor_node_output_datum

  // Done.
  True
}

// # Internal functions

// Adapted from Aiken stdlib.collection.list.filter_map
// Instead of using (predicate: fn(a) -> Option<a>)
// We decompose it into two arguments.

// In this variant, we apply the transform before the predicate.
fn filter_map_pre(
  self: List<a>,
  predicate: fn(b) -> Bool,
  transform: fn(a) -> b,
) -> List<b> {
  when self is {
    [] -> []
    [x, ..xs] -> {
      let y = transform(x)
      if predicate(y) {
        [y, ..filter_map_pre(xs, predicate, transform)]
      } else {
        filter_map_pre(xs, predicate, transform)
      }
    }
  }
}

// In this variant, we apply the transform after the predicate.
fn filter_map_post(
  self: List<a>,
  predicate: fn(a) -> Bool,
  transform: fn(a) -> b,
) -> List<b> {
  when self is {
    [] -> []
    [x, ..xs] ->
      if predicate(x) {
        [transform(x), ..filter_map_post(xs, predicate, transform)]
      } else {
        filter_map_post(xs, predicate, transform)
      }
  }
}

// Checks if a Currency Symbol is held within a Value
fn has_data_cs(cs: PolicyId, value: Value) -> Bool {
  value
    |> to_dict()
    |> has_key(cs)
}

fn is_root_node(node_key: NodeKey) -> Bool {
  node_key == Empty
}

fn is_last_node(node_link: NodeKey) -> Bool {
  node_link == Empty
}

fn is_empty_list(node_key: NodeKey, node_link: NodeKey) -> Bool {
  and {
    is_root_node(node_key),
    is_last_node(node_link),
  }
}

fn key_added(key: NodeKey, node_mint: Dict<AssetName, Int>) -> Bool {
  and {
    dict.size(node_mint) == 1,
    dict.get(node_mint, serialize_key(key)) == Some(1),
  }
}

fn key_removed(key: NodeKey, node_mint: Dict<AssetName, Int>) -> Bool {
  and {
    dict.size(node_mint) == 1,
    dict.get(node_mint, serialize_key(key)) == Some(-1),
  }
}

fn is_member(k: NodeKey, node_key: NodeKey) -> Bool {
  k == node_key
}

fn is_not_member(k: NodeKey, node_key: NodeKey, node_link: NodeKey) -> Bool {
  // k must contain a key.
  expect Key(actual_k) = k
  // k must be "between" the node's key and link.
  and {
    // The node is either the root node or its key is less than k.
    when node_key is {
      Empty -> True
      Key(actual_node_key) ->
        bytearray.compare(actual_node_key, actual_k) == Less
    },
    // The node is either the last node or k is less than its link.
    when node_link is {
      Empty -> True
      Key(actual_node_link) ->
        bytearray.compare(actual_k, actual_node_link) == Less
    },
  }
}
