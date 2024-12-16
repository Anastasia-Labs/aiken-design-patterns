//// @hidden

use aiken/builtin
use aiken/collection/dict.{Dict, has_key}
use aiken/collection/list
use aiken/primitive/bytearray
use cardano/assets.{AssetName, PolicyId, Value, to_dict}
use cardano/transaction.{InlineDatum, Input, Output}

/// Every list node's token name starts with this prefix.
pub const node_prefix: ByteArray = "Node"

/// Every list node utxo:
/// - has a unique `key` (unless it's the root node)
/// - has a unique `link` to another node's key 
///   (unless it's the last node of the list)
/// - holds some app-specific `data`
pub type NodeDatum {
  key: NodeKey,
  link: NodeKey,
  data: Data,
}

/// Same as `Option`, but with more informative constructor names.
pub type NodeKey {
  Key { key: ByteArray }
  Empty
}

pub fn is_root_node(node_key: NodeKey) -> Bool {
  node_key == Empty
}

pub fn is_last_node(node_link: NodeKey) -> Bool {
  node_link == Empty
}

pub fn is_empty_list(node_key: NodeKey, node_link: NodeKey) -> Bool {
  and {
    is_root_node(node_key),
    is_last_node(node_link),
  }
}

pub fn key_added(key: NodeKey, node_mint: Dict<AssetName, Int>) -> Bool {
  and {
    dict.size(node_mint) == 1,
    dict.get(node_mint, serialize_key(key)) == Some(1),
  }
}

pub fn key_removed(key: NodeKey, node_mint: Dict<AssetName, Int>) -> Bool {
  and {
    dict.size(node_mint) == 1,
    dict.get(node_mint, serialize_key(key)) == Some(-1),
  }
}

pub fn is_member(k: NodeKey, node_key: NodeKey) -> Bool {
  k == node_key
}

pub fn is_not_member(k: NodeKey, node_key: NodeKey, node_link: NodeKey) -> Bool {
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

// Checks if a Currency Symbol is held within a Value
pub fn has_data_cs(cs: PolicyId, value: Value) -> Bool {
  value
    |> to_dict()
    |> has_key(cs)
}

pub fn get_raw_key_and_link(node_output: Output) -> (Data, Data) {
  expect InlineDatum(node_output_datum) = node_output.datum
  let constr = builtin.un_constr_data(node_output_datum).2nd
  let key = builtin.head_list(constr)
  let link = builtin.head_list(builtin.tail_list(constr))
  (key, link)
}

pub fn get_key(raw_key_and_link: (Data, Data)) -> NodeKey {
  expect key: NodeKey = raw_key_and_link.1st
  key
}

pub fn get_link(raw_key_and_link: (Data, Data)) -> NodeKey {
  expect link: NodeKey = raw_key_and_link.2nd
  link
}

pub fn get_key_and_link(node_output: Output) -> (NodeKey, NodeKey) {
  let raw = get_raw_key_and_link(node_output)
  (get_key(raw), get_link(raw))
}

pub fn serialize_key(key: NodeKey) -> ByteArray {
  when key is {
    Empty -> node_prefix
    Key(actual_key) -> bytearray.concat(node_prefix, actual_key)
  }
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

// Adapted from Aiken stdlib.collection.list.filter_map
// Instead of using (predicate: fn(a) -> Option<a>)
// We decompose it into two arguments.

// In this variant, we apply the transform before the predicate.
pub fn filter_map_pre(
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
pub fn filter_map_post(
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
