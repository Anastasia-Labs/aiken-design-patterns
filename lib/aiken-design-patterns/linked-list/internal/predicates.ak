use aiken/collection/dict.{Dict}
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list/types.{Empty, Key, NodeKey}
use aiken_design_patterns/linked_list/utils.{serialize_key}
use cardano/assets.{AssetName}

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
