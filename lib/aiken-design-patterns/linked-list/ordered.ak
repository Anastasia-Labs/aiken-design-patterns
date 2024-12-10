use aiken/collection/dict.{Dict}
use aiken/collection/list
use aiken/primitive/bytearray
use cardano/address.{Address}
use cardano/assets.{AssetName, flatten}
use cardano/transaction.{InlineDatum, Input, Output}
use linked_list/types.{Empty, Key, NodeDatum, NodeKey}
use linked_list/unordered
use linked_list/utils.{get_key, get_link, get_raw_key_and_link}

pub fn list_state_transition(node_mint: Dict<AssetName, Int>) {
  unordered.list_state_transition(node_mint)
}

pub fn modify_data(
  node_mint: Dict<AssetName, Int>,
  own_input: Input,
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

pub fn is_root_node(node_key: NodeKey) {
  unordered.is_root_node(node_key)
}

pub fn is_last_node(node_link: NodeKey) {
  unordered.is_last_node(node_link)
}

pub fn is_empty_list(node_key: NodeKey, node_link: NodeKey) {
  unordered.is_empty_list(node_key, node_link)
}

pub fn key_added(key: NodeKey, node_mint: Dict<AssetName, Int>) {
  unordered.key_added(key, node_mint)
}

pub fn key_removed(key: NodeKey, node_mint: Dict<AssetName, Int>) {
  unordered.key_removed(key, node_mint)
}

pub fn is_member(
  k: NodeKey,
  node_key: NodeKey,
  node_address: Address,
  linked_list_address: Address,
) {
  unordered.is_member(k, node_key, node_address, linked_list_address)
}

pub fn is_not_member(
  k: NodeKey,
  node_key: NodeKey,
  node_link: NodeKey,
  node_address: Address,
  linked_list_address: Address,
) {
  or {
    node_address != linked_list_address,
    and {
      k != Empty,
      {
        expect Key(actual_key) = k
        and {
          or {
            unordered.is_root_node(node_key),
            {
              expect Key(actual_node_key) = node_key
              bytearray.compare(actual_node_key, actual_key) == Less
            },
          },
          or {
            unordered.is_last_node(node_link),
            {
              expect Key(actual_node_link) = node_link
              bytearray.compare(actual_key, actual_node_link) == Less
            },
          },
        }
      },
    },
  }
}

//Application code must ensure that this action can happen only once
pub fn init(
  node_outputs: List<Output>,
  node_mint: Dict<AssetName, Int>,
  node_cs: ByteArray,
) {
  unordered.init(node_outputs, node_mint, node_cs)
}

pub fn deinit(
  node_in_outputs: List<Output>,
  node_mint: Dict<AssetName, Int>,
  node_cs: ByteArray,
) {
  unordered.deinit(node_in_outputs, node_mint, node_cs)
}

pub fn prepend(
  key_to_prepend: NodeKey,
  prepended_node_output_index: Int,
  anchor_node_output_index: Int,
  node_in_outputs: List<Output>,
  node_outputs: List<Output>,
  node_mint: Dict<AssetName, Int>,
) {
  //We know it's only 1 from unordered_prepend()
  expect Some(anchor_node_input) = list.head(node_in_outputs)
  let anchor_node_input_raw_key_and_link =
    get_raw_key_and_link(anchor_node_input)
  expect Some(prepended_node_output) =
    list.at(node_outputs, prepended_node_output_index)
  and {
    unordered.prepend(
      key_to_prepend,
      prepended_node_output_index,
      anchor_node_output_index,
      node_in_outputs,
      node_outputs,
      node_mint,
    ),
    is_not_member(
      key_to_prepend,
      node_key: get_key(anchor_node_input_raw_key_and_link),
      node_link: get_link(anchor_node_input_raw_key_and_link),
      node_address: prepended_node_output.address,
      linked_list_address: anchor_node_input.address,
    ),
  }
}

pub fn append(
  key_to_append: NodeKey,
  appended_node_output_index: Int,
  anchor_node_output_index: Int,
  node_in_outputs: List<Output>,
  node_outputs: List<Output>,
  node_mint: Dict<AssetName, Int>,
) {
  //We know it's only 1 from unordered.prepend()
  expect Some(anchor_node_input) = list.head(node_in_outputs)
  let anchor_node_input_raw_key_and_link =
    get_raw_key_and_link(anchor_node_input)
  expect Some(appended_node_output) =
    list.at(node_outputs, appended_node_output_index)
  and {
    unordered.append(
      key_to_append,
      appended_node_output_index,
      anchor_node_output_index,
      node_in_outputs,
      node_outputs,
      node_mint,
    ),
    is_not_member(
      key_to_append,
      node_key: get_key(anchor_node_input_raw_key_and_link),
      node_link: get_link(anchor_node_input_raw_key_and_link),
      node_address: appended_node_output.address,
      linked_list_address: anchor_node_input.address,
    ),
  }
}

pub fn insert(
  key_to_insert: NodeKey,
  inserted_node_output_index: Int,
  anchor_node_output_index: Int,
  node_in_outputs: List<Output>,
  node_outputs: List<Output>,
  node_mint: Dict<AssetName, Int>,
) {
  expect Some(anchor_node_input) = list.head(node_in_outputs)
  expect InlineDatum(anchor_node_input_datum) = anchor_node_input.datum
  expect parsed_anchor_node_input_datum: NodeDatum = anchor_node_input_datum

  expect Some(inserted_node_output) =
    list.at(node_outputs, inserted_node_output_index)
  expect Some(anchor_node_output) =
    list.at(node_outputs, anchor_node_output_index)
  let inserted_node_output_raw_key_and_link =
    get_raw_key_and_link(inserted_node_output)
  expect InlineDatum(anchor_node_output_datum) = anchor_node_output.datum
  expect parsed_anchor_node_output_datum: NodeDatum = anchor_node_output_datum

  let anchor_node_new_datum =
    NodeDatum {
      key: parsed_anchor_node_input_datum.key,
      link: key_to_insert,
      data: parsed_anchor_node_input_datum.data,
    }
  and {
    unordered.key_added(key_to_insert, node_mint),
    list.length(node_in_outputs) == 1,
    is_not_member(
      key_to_insert,
      parsed_anchor_node_input_datum.key,
      parsed_anchor_node_input_datum.link,
      node_address: inserted_node_output.address,
      linked_list_address: anchor_node_input.address,
    ),
    list.length(node_outputs) == 2,
    is_member(
      key_to_insert,
      get_key(inserted_node_output_raw_key_and_link),
      inserted_node_output.address,
      anchor_node_input.address,
    ),
    parsed_anchor_node_output_datum.link == key_to_insert,
    parsed_anchor_node_input_datum.link == get_link(
      inserted_node_output_raw_key_and_link,
    ),
    anchor_node_input.address == anchor_node_output.address,
    anchor_node_input.value == anchor_node_output.value,
    anchor_node_new_datum == parsed_anchor_node_output_datum,
    inserted_node_output.address == anchor_node_output.address,
    list.length(flatten(inserted_node_output.value)) == 2,
  }
}

pub fn remove(
  key_to_remove: NodeKey,
  removed_node_input_index: Int,
  anchor_node_input_index: Int,
  node_in_outputs: List<Output>,
  node_outputs: List<Output>,
  node_mint: Dict<AssetName, Int>,
) {
  unordered.remove(
    key_to_remove,
    removed_node_input_index,
    anchor_node_input_index,
    node_in_outputs,
    node_outputs,
    node_mint,
  )
}
