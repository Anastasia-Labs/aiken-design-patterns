use aiken/builtin
use aiken/collection/dict.{has_key}
use aiken/collection/list
use aiken/primitive/bytearray
use cardano/assets.{PolicyId, Value, to_dict}
use cardano/transaction.{InlineDatum, Input, Output}
use linked_list/constants
use linked_list/types.{Empty, Key, NodeKey}

// Checks if a Currency Symbol is held within a Value
pub fn has_data_cs(cs: PolicyId, value: Value) -> Bool {
  value
    |> to_dict()
    |> has_key(cs)
}

pub fn get_outputs(inputs: List<Input>) -> List<Output> {
  list.map(
    inputs,
    fn(input) {
      let Input { output, .. } = input
      output
    },
  )
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
    Empty -> constants.node_prefix
    Key(actual_key) -> bytearray.concat(constants.node_prefix, actual_key)
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

pub fn get_node_in_outputs(
  inputs: List<Input>,
  policy_id: PolicyId,
) -> List<Output> {
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
