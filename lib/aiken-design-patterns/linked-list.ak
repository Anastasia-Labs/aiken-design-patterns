//// Storing lists in datums is generally impractical, as its growth can lead to
//// unspendable UTxOs due to limited resources available on-chain.
////
//// A linked list is a construct for storing an infinitely large array of
//// elements on-chain, such that each element is represented with a UTxO that
//// points to its immediate successor.

use aiken/collection/dict
use aiken/crypto.{ScriptHash}
use aiken/primitive/bytearray
use aiken_design_patterns/utils
use aiken_scott_utils/types.{Scott4}
use cardano/address.{Address, Script}
use cardano/assets.{AssetName, PolicyId, Value}
use cardano/transaction.{InlineDatum, Input, Output, OutputReference}

pub type Key =
  AssetName

pub type HeadKey =
  Key

pub type NodeKeyPrefix =
  ByteArray

pub type NodeKeyPrefixLength =
  Int

/// This is the datatype for allowing you to provide environment constants. To
/// be a bit nerdy, this is essentially a `Reader` monad.
pub type Eval =
  fn(HeadKey, NodeKeyPrefix, NodeKeyPrefixLength) -> Bool

pub type HeadEval =
  fn(HeadKey) -> Bool

/// The terminology used here is as follows:
/// - `Head` is the first element of the linked list
/// - `Node` is any other element in a linked list other than the head
/// - `Element` is the umbrella term to refer to either the head or nodes
pub type Element<head_data, node_data> {
  data: ElementData<head_data, node_data>,
  next_link: Option<ByteArray>,
}

pub type ElementData<head_data, node_data> {
  Head { data: head_data }
  Node { data: node_data }
}

// ## Finalization Functions

pub fn run_eval_with(
  reader: Eval,
  head_key: HeadKey,
  node_key_prefix: NodeKeyPrefix,
  node_key_prefix_length: NodeKeyPrefixLength,
) -> Bool {
  reader(head_key, node_key_prefix, node_key_prefix_length)
}

pub fn run_head_with(reader: HeadEval, head_key: HeadKey) -> Bool {
  reader(head_key)
}

// ## Initialization and De-initialization

/// Initialize a linked list with an optional first node.
pub fn init(
  nonce_out_ref: OutputReference,
  produced_element_output: Output,
  expected_destination_script_hash: ScriptHash,
  list_nft_policy_id: PolicyId,
  head_data_validator: fn(Data) -> Bool,
  tx_inputs: List<Input>,
  tx_mint: Value,
) -> HeadEval {
  // 1. The nonce UTxO must be spent.
  expect utils.utxo_is_spent(tx_inputs, nonce_out_ref)

  // 2. Only one token must be minted with linked list's authentication policy.
  expect [Pair(mint_name, mint_qty)] =
    tx_mint |> assets.tokens(list_nft_policy_id) |> dict.to_pairs

  // 3. The produced UTxO must only contain the authentication/key NFT.
  // 4. Its datum must be properly structured.
  // 5. The payment part of its address must be a `Script`.
  let
    element_script_hash,
    element_asset_name,
    element_data,
    element_link,
  <-
    authenticate_element_utxo_and_get_info(
      produced_element_output,
      list_nft_policy_id,
    )

  // 6. Contained data must be `Head`.
  expect Head { data: head_data }: GenericElementData = element_data

  fn(head_key: HeadKey) -> Bool {
    and {
      // 7. The minted asset must be included in the produced UTxO.
      mint_name == element_asset_name,
      // 8. The authentication NFT must have the head's hardcoded name.
      element_asset_name == head_key,
      // 9. Only one NFT must be minted.
      mint_qty == 1,
      // 10. The UTxO must be produced at the expected script.
      element_script_hash == expected_destination_script_hash,
      // 11. Head's contained `Data` must pass the provided validation logic.
      head_data_validator(head_data),
      // 12. Produced head must not have a link.
      element_link == None,
    }
  }
}

/// Deinitialize an empty list.
pub fn deinit(
  head_input: Input,
  expected_origin_script_hash: ScriptHash,
  list_nft_policy_id: PolicyId,
  head_data_validator: fn(Data) -> Bool,
  tx_mint: Value,
) -> HeadEval {
  // 1. Only one token must be burnt with linked list's authentication policy.
  expect [Pair(mint_name, mint_qty)] =
    tx_mint |> assets.tokens(list_nft_policy_id) |> dict.to_pairs

  // 2. The spent UTxO must only contain the authentication/key NFT.
  // 3. Its datum must be properly structured.
  // 4. The payment part of its address must be a `Script`.
  let
    element_script_hash,
    element_asset_name,
    element_data,
    element_link,
  <-
    authenticate_element_utxo_and_get_info(
      head_input.output,
      list_nft_policy_id,
    )

  // 5. Contained data must be `Head`.
  expect Head { data: head_data }: GenericElementData = element_data

  fn(head_key: HeadKey) -> Bool {
    and {
      // 6. The minted asset must be included in the spent UTxO.
      mint_name == element_asset_name,
      // 7. Only one NFT must be burnt.
      mint_qty == -1,
      // 8. The UTxO must be coming from the expected script.
      element_script_hash == expected_origin_script_hash,
      // 9. The authentication NFT must have the head's hardcoded name.
      element_asset_name == head_key,
      // 10. Head's contained `Data` must pass the provided validation logic.
      head_data_validator(head_data),
      // 11. Spent head must have no links/children.
      element_link == None,
    }
  }
}

// ## Element Addition and Removal

/// It is assumed the address from which the covering element comes from is the
/// destination address for the new node.
///
/// The `additional_validations` argument provides you with 4 values:
/// 1. Output reference of the spent covering UTxO
/// 2. An `is_head` flag -- it'll allow you to perform different logics
///    depending on whether the data is from a `Head` or a `Node` covering
///    element
/// 3. Key (i.e. asset name) of the covering element
/// 4. Underlying data of the covering element -- note that this can come from
///    either a `Head` or a `Node`
/// 5. Key (i.e. asset name) of the new node
/// 6. Underlying data of the new node -- note that this is extracted from a
///    `Node`
pub fn insert_ordered(
  list_nft_policy_id: PolicyId,
  covering_element_input: Input,
  continued_covering_element_output: Output,
  new_element_output: Output,
  additional_validations: fn(OutputReference, Bool, Key, Data, Key, Data) ->
    Bool,
  tx_mint: Value,
) -> Eval {
  let Input {
    output: covering_element_input_utxo,
    output_reference: covering_element_out_ref,
  } = covering_element_input

  // 1. Only one token must be minted with linked list's authentication policy.
  expect [Pair(mint_name, mint_qty)] =
    tx_mint |> assets.tokens(list_nft_policy_id) |> dict.to_pairs

  // 2. Each of the 3 element UTxOs must only contain single authentication NFTs.
  // 3. All their datums must be properly structured (i.e. `Element`).
  // 4. The payment parts of their addresses must be `Script`s.
  let
    covering_element_asset_name,
    covering_element_data,
    covering_element_link,
    cont_covering_element_link,
    new_element_asset_name,
    new_element_data,
    new_element_link,
  <-
    validate_three_elements(
      list_nft_policy_id,
      covering_element_input_utxo,
      continued_covering_element_output,
      new_element_output,
    )

  // 5. New element's data must be `Node`.
  expect Node { data: new_node_data } = new_element_data

  expect and {
      // 6. New element's NFT asset name must be the one that's minted.
      mint_name == new_element_asset_name,
      // 7. NFT must be minted with a quantity of 1.
      mint_qty == 1,
      // 8. Reproduced covering element must point to the new node.
      cont_covering_element_link == Some(new_element_asset_name),
      // 9. The new element must point to what the covering element used to link
      //    to.
      new_element_link == covering_element_link,
    }

  fn(
    head_key: HeadKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    // 10. The new node's asset name must start with the provided label.
    expect
      bytearray.take(new_element_asset_name, node_key_prefix_length) == node_key_prefix
    when covering_element_data is {
      Head { data: head_data } -> and {
          // 11a. Token name of the covering element must be identical to the
          //      constant `head_key`.
          covering_element_asset_name == head_key,
          // 12a. If the head is already pointing to a firs node, the new node
          //      must have a key such that it is less than the previous link's.
          when covering_element_link is {
            None -> True
            Some(covering_element_link_key) ->
              bytearray.compare(
                new_element_asset_name,
                covering_element_link_key,
              ) == Less
          },
          // 13a. Custom validation against the spent covering element and the
          //      new node must pass.
          additional_validations(
            covering_element_out_ref,
            True,
            covering_element_asset_name,
            head_data,
            new_element_asset_name,
            new_node_data,
          ),
        }
      Node { data: covering_node_data } -> and {
          // 11b. The covering node's key must start with the provided label.
          bytearray.take(covering_element_asset_name, node_key_prefix_length) == node_key_prefix,
          // 12b. The new node must have a key that is greater than the covering
          //      node's.
          // 13b. If the covering node is already pointing to a link, the new
          //      node's key (i.e. asset name) must be less than this link's.
          when covering_element_link is {
            None ->
              bytearray.compare(
                covering_element_asset_name,
                new_element_asset_name,
              ) == Less
            Some(covering_element_link_key) -> and {
                bytearray.compare(
                  covering_element_asset_name,
                  new_element_asset_name,
                ) == Less,
                bytearray.compare(
                  new_element_asset_name,
                  covering_element_link_key,
                ) == Less,
              }
          },
          // 14b. Custom validation against the spent covering element and the
          //      new node must pass.
          additional_validations(
            covering_element_out_ref,
            False,
            covering_element_asset_name,
            covering_node_data,
            new_element_asset_name,
            new_node_data,
          ),
        }
    }
  }
}

/// Append a new element at the very end of an unordered list. There is no
/// validation for the new key to be greater than the covering element's.
///
/// `additional_validations` takes the same arguments as
/// [`insert_ordered`](#insert_ordered).
pub fn append_unordered(
  list_nft_policy_id: PolicyId,
  covering_element_input: Input,
  continued_covering_element_output: Output,
  new_element_output: Output,
  additional_validations: fn(OutputReference, Bool, Key, Data, Key, Data) ->
    Bool,
  tx_mint: Value,
) -> Eval {
  let Input {
    output: covering_element_input_utxo,
    output_reference: covering_element_out_ref,
  } = covering_element_input

  // 1. Only one token must be minted with linked list's authentication policy.
  expect [Pair(mint_name, mint_qty)] =
    tx_mint |> assets.tokens(list_nft_policy_id) |> dict.to_pairs

  // 2. Each of the 3 element UTxOs must only contain single authentication NFTs.
  // 3. All their datums must be properly structured (i.e. `Element`).
  // 4. The payment parts of their addresses must be `Script`s.
  let
    covering_element_asset_name,
    covering_element_data,
    covering_element_link,
    cont_covering_element_link,
    new_element_asset_name,
    new_element_data,
    new_element_link,
  <-
    validate_three_elements(
      list_nft_policy_id,
      covering_element_input_utxo,
      continued_covering_element_output,
      new_element_output,
    )

  // 5. New element's data must be `Node`.
  expect Node { data: new_node_data } = new_element_data

  expect and {
      // 6. New element's NFT asset name must be the one that's minted.
      mint_name == new_element_asset_name,
      // 7. NFT must be minted with a quantity of 1.
      mint_qty == 1,
      // 8. Covering element must be the last element of the list.
      covering_element_link == None,
      // 9. Reproduced covering element must point to the new node.
      cont_covering_element_link == Some(new_element_asset_name),
      // 10. The new element must point to no other nodes.
      new_element_link == None,
    }

  fn(
    head_key: HeadKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    // 11. The new node's asset name must start with the provided label.
    expect
      bytearray.take(new_element_asset_name, node_key_prefix_length) == node_key_prefix
    when covering_element_data is {
      Head { data: head_data } -> and {
          // 12a. Token name of the covering element must be identical to the
          //      constant `head_key`.
          covering_element_asset_name == head_key,
          // 13a. Custom validation against the spent covering element and the
          //      new node must pass.
          additional_validations(
            covering_element_out_ref,
            True,
            covering_element_asset_name,
            head_data,
            new_element_asset_name,
            new_node_data,
          ),
        }
      Node { data: covering_node_data } -> and {
          // 12b. The covering node's key must start with the provided label.
          bytearray.take(covering_element_asset_name, node_key_prefix_length) == node_key_prefix,
          // 13b. Custom validation against the spent covering element and the
          //      new node must pass.
          additional_validations(
            covering_element_out_ref,
            False,
            covering_element_asset_name,
            covering_node_data,
            new_element_asset_name,
            new_node_data,
          ),
        }
    }
  }
}

/// Remove a node. It expects two spent UTxOs: the node subject to removal, and
/// its previous element (i.e. covering element).
///
/// `additional_validations` takes the same arguments as
/// [`insert_ordered`](#insert_ordered), the difference being last `Key` and
/// `Data` are from the removing node.
pub fn remove(
  list_nft_policy_id: PolicyId,
  covering_element_input: Input,
  removing_element_input: Input,
  continued_covering_element_output: Output,
  additional_validations: fn(OutputReference, Bool, Key, Data, Key, Data) ->
    Bool,
  tx_mint: Value,
) -> Eval {
  let Input {
    output: covering_element_input_utxo,
    output_reference: covering_element_out_ref,
  } = covering_element_input
  let Input { output: removing_element_input_utxo, .. } = removing_element_input

  // 1. Only one token must be burnt with linked list's authentication policy.
  expect [Pair(mint_name, mint_qty)] =
    tx_mint |> assets.tokens(list_nft_policy_id) |> dict.to_pairs

  // 2. Each of the 3 element UTxOs must only contain single authentication NFTs.
  // 3. All their datums must be properly structured (i.e. `Element`).
  // 4. The payment parts of their addresses must be `Script`s.
  let
    covering_element_asset_name,
    covering_element_data,
    covering_element_link,
    cont_covering_element_link,
    removing_element_asset_name,
    removing_element_data,
    removing_element_link,
  <-
    validate_three_elements(
      list_nft_policy_id,
      covering_element_input_utxo,
      continued_covering_element_output,
      removing_element_input_utxo,
    )

  // 5. Removing element's data must be `Node`.
  expect Node { data: removing_node_data } = removing_element_data

  expect and {
      // 6. Burnt NFT must be the same as the one from removing node.
      mint_name == removing_element_asset_name,
      // 7. Burnt quantity must be 1.
      mint_qty == -1,
      // 8. Covering element must point to the node being removed.
      covering_element_link == Some(removing_element_asset_name),
      // 9. Reproduced covering element must point to what the removed element
      //    pointed to.
      cont_covering_element_link == removing_element_link,
    }

  fn(
    head_key: HeadKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    // 10. Asset name of the removing node must have the expected label.
    expect
      bytearray.take(removing_element_asset_name, node_key_prefix_length) == node_key_prefix
    when covering_element_data is {
      Head { data: head_data } -> and {
          // 11a. Token name of the covering element must be identical to the
          //      constant `head_key`.
          covering_element_asset_name == head_key,
          // 12a. The new node's asset name must start with the provided label.
          additional_validations(
            covering_element_out_ref,
            True,
            covering_element_asset_name,
            head_data,
            removing_element_asset_name,
            removing_node_data,
          ),
        }
      Node { data: covering_node_data } -> and {
          // 11b. The covering node's key must start with the provided label.
          bytearray.take(covering_element_asset_name, node_key_prefix_length) == node_key_prefix,
          // 12b. Custom validation against the spent covering element and the
          //      removing node must pass.
          additional_validations(
            covering_element_out_ref,
            False,
            covering_element_asset_name,
            covering_node_data,
            removing_element_asset_name,
            removing_node_data,
          ),
        }
    }
  }
}

// ## Internal Helpers

type GenericElement =
  Element<Data, Data>

type GenericElementData =
  ElementData<Data, Data>

type ElementInfo<result> =
  Scott4<ScriptHash, Key, GenericElementData, Option<ByteArray>, result>

type ThreeElementInfo =
  fn(
    Key,
    GenericElementData,
    Option<ByteArray>,
    Option<ByteArray>,
    Key,
    GenericElementData,
    Option<ByteArray>,
  ) ->
    Eval

/// Helper function to handle recurring validations. Namely the authenticity of
/// its given UTxOs.
///
/// > [!NOTE]
/// > The staking part of the address is not validated.
fn authenticate_element_utxo_and_get_info(
  element_utxo: Output,
  nft_policy_id: PolicyId,
  return: ElementInfo<result>,
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
  expect Element { data, next_link }: GenericElement = utxo_datum_data

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

/// Helper function used for addition and removal of elements (since they all
/// involve 3 element UTxOs). It performs a few common validations, and returns
/// multiple values needed for further, and more specific validations.
///
/// The 2 elements shared by all the functions that use this helper, are the
/// spent "covering" element, and its "continued" reproduction (referred to as
/// `elem_0` and `cont_elem_0` here respectively).
///
/// In case of addition (insert and append), `elem_1` will be the newly produced
/// UTxO. On the other hand, in case of remove, `elem_1` will refer to the spent
/// UTxO which its NFT is to be burnt.
fn validate_three_elements(
  nft_policy_id: PolicyId,
  elem_0: Output,
  cont_elem_0: Output,
  elem_1: Output,
  return: ThreeElementInfo,
) -> Eval {
  let
    elem_0_script_hash,
    elem_0_asset_name,
    elem_0_data,
    elem_0_link,
  <- authenticate_element_utxo_and_get_info(elem_0, nft_policy_id)
  let
    cont_elem_0_script_hash,
    cont_elem_0_asset_name,
    cont_elem_0_data,
    cont_elem_0_link,
  <- authenticate_element_utxo_and_get_info(cont_elem_0, nft_policy_id)
  let
    elem_1_script_hash,
    elem_1_asset_name,
    elem_1_data,
    elem_1_link,
  <- authenticate_element_utxo_and_get_info(elem_1, nft_policy_id)
  expect and {
      // 1. Covering element must be reproduced at the same script.
      elem_0_script_hash == cont_elem_0_script_hash,
      // 2. New/removed element must go to / come from the same script as the
      //    covering element.
      elem_0_script_hash == elem_1_script_hash,
      // 3. Covering element must preserve its NFT.
      elem_0_asset_name == cont_elem_0_asset_name,
      // 4. Underlying data of the covering element must remain unchanged.
      elem_0_data == cont_elem_0_data,
    }
  return(
    elem_0_asset_name,
    elem_0_data,
    elem_0_link,
    cont_elem_0_link,
    elem_1_asset_name,
    elem_1_data,
    elem_1_link,
  )
}
