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

pub type RootKey =
  Key

pub type NodeKeyPrefix =
  ByteArray

pub type NodeKeyPrefixLength =
  Int

/// This is the datatype for allowing you to provide environment constants. To
/// be a bit nerdy, this is essentially a `Reader` monad.
pub type Eval =
  fn(RootKey, NodeKeyPrefix, NodeKeyPrefixLength) -> Bool

pub type RootEval =
  fn(RootKey) -> Bool

/// The terminology used here is as follows:
/// - `Root` is the first element of the linked list
/// - `Node` is any other element in a linked list other than the root
/// - `Element` is the umbrella term to refer to either the root or nodes
pub type Element<root_data, node_data> {
  data: ElementData<root_data, node_data>,
  next_link: Option<ByteArray>,
}

pub type ElementData<root_data, node_data> {
  Root { data: root_data }
  Node { data: node_data }
}

// ## Finalization Functions

pub fn run_eval_with(
  reader: Eval,
  root_key: RootKey,
  node_key_prefix: NodeKeyPrefix,
  node_key_prefix_length: NodeKeyPrefixLength,
) -> Bool {
  reader(root_key, node_key_prefix, node_key_prefix_length)
}

pub fn run_root_with(reader: RootEval, root_key: RootKey) -> Bool {
  reader(root_key)
}

// ## Initialization and De-initialization

/// Initialize a linked list with an optional first node.
pub fn init(
  nonce_validated: Bool,
  produced_element_output: Output,
  expected_destination_script_hash: ScriptHash,
  list_nft_policy_id: PolicyId,
  root_data_validator: fn(Data) -> Bool,
  tx_mint: Value,
) -> RootEval {
  // 1. Helper guardrail to remind nonce validation logic.
  expect nonce_validated

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

  // 6. Contained data must be `Root`.
  expect Root { data: root_data }: GenericElementData = element_data

  fn(root_key: RootKey) -> Bool {
    and {
      // 7. The minted asset must be included in the produced UTxO.
      mint_name == element_asset_name,
      // 8. The authentication NFT must have the root's hardcoded name.
      element_asset_name == root_key,
      // 9. Only one NFT must be minted.
      mint_qty == 1,
      // 10. The UTxO must be produced at the expected script.
      element_script_hash == expected_destination_script_hash,
      // 11. Root's contained `Data` must pass the provided validation logic.
      root_data_validator(root_data),
      // 12. Produced root must not have a link.
      element_link == None,
    }
  }
}

/// Deinitialize an empty list.
pub fn deinit(
  root_input: Input,
  expected_origin_script_hash: ScriptHash,
  list_nft_policy_id: PolicyId,
  root_data_validator: fn(Data) -> Bool,
  tx_mint: Value,
) -> RootEval {
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
      root_input.output,
      list_nft_policy_id,
    )

  // 5. Contained data must be `Root`.
  expect Root { data: root_data }: GenericElementData = element_data

  fn(root_key: RootKey) -> Bool {
    and {
      // 6. The minted asset must be included in the spent UTxO.
      mint_name == element_asset_name,
      // 7. Only one NFT must be burnt.
      mint_qty == -1,
      // 8. The UTxO must be coming from the expected script.
      element_script_hash == expected_origin_script_hash,
      // 9. The authentication NFT must have the root's hardcoded name.
      element_asset_name == root_key,
      // 10. Root's contained `Data` must pass the provided validation logic.
      root_data_validator(root_data),
      // 11. Spent root must have no links/children.
      element_link == None,
    }
  }
}

// ## Element Addition and Removal

/// It is assumed the address from which the achor element comes from is the
/// destination address for the new node.
///
/// The `additional_validations` argument provides you with 4 values:
/// 1. Output reference of the spent achor UTxO
/// 2. An `is_root` flag -- it'll allow you to perform different logics
///    depending on whether the data is from a `Root` or a `Node` achor element
/// 3. Key (i.e. asset name) of the achor element
/// 4. Underlying data of the anchor element -- note that this can come from
///    either a `Root` or a `Node`
/// 5. Key (i.e. asset name) of the new node
/// 6. Underlying data of the new node -- note that this is extracted from a
///    `Node`
pub fn insert_ordered(
  list_nft_policy_id: PolicyId,
  anchor_element_input: Input,
  continued_anchor_element_output: Output,
  new_element_output: Output,
  additional_validations: fn(OutputReference, Bool, Key, Data, Key, Data) ->
    Bool,
  tx_mint: Value,
) -> Eval {
  let Input {
    output: anchor_element_input_utxo,
    output_reference: anchor_element_out_ref,
  } = anchor_element_input

  // 1. Only one token must be minted with linked list's authentication policy.
  expect [Pair(mint_name, mint_qty)] =
    tx_mint |> assets.tokens(list_nft_policy_id) |> dict.to_pairs

  // 2. Each of the 3 element UTxOs must only contain single authentication NFTs.
  // 3. All their datums must be properly structured (i.e. `Element`).
  // 4. The payment parts of their addresses must be `Script`s.
  let
    anchor_element_asset_name,
    anchor_element_data,
    anchor_element_link,
    cont_anchor_element_link,
    new_element_asset_name,
    new_element_data,
    new_element_link,
  <-
    validate_three_elements(
      list_nft_policy_id,
      anchor_element_input_utxo,
      continued_anchor_element_output,
      new_element_output,
    )

  // 5. New element's data must be `Node`.
  expect Node { data: new_node_data } = new_element_data

  expect and {
      // 6. New element's NFT asset name must be the one that's minted.
      mint_name == new_element_asset_name,
      // 7. NFT must be minted with a quantity of 1.
      mint_qty == 1,
      // 8. Reproduced anchor element must point to the new node.
      cont_anchor_element_link == Some(new_element_asset_name),
      // 9. The new element must point to what the anchor element used to link
      //    to.
      new_element_link == anchor_element_link,
    }

  fn(
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    // 10. The new node's asset name must start with the provided label.
    expect
      bytearray.take(new_element_asset_name, node_key_prefix_length) == node_key_prefix
    when anchor_element_data is {
      Root { data: root_data } -> and {
          // 11a. Token name of the anchor element must be identical to the
          //      constant `root_key`.
          anchor_element_asset_name == root_key,
          // 12a. If the root is already pointing to a firs node, the new node
          //      must have a key such that it is less than the previous link's.
          when anchor_element_link is {
            None -> True
            Some(anchor_element_link_key) ->
              bytearray.compare(new_element_asset_name, anchor_element_link_key) == Less
          },
          // 13a. Custom validation against the spent anchor element and the new
          //      node must pass.
          additional_validations(
            anchor_element_out_ref,
            True,
            anchor_element_asset_name,
            root_data,
            new_element_asset_name,
            new_node_data,
          ),
        }
      Node { data: anchor_node_data } -> and {
          // 11b. The anchor node's key must start with the provided label.
          bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix,
          // 12b. The new node must have a key that is greater than the anchor
          //      node's.
          // 13b. If the anchor node is already pointing to a link, the new
          //      node's key (i.e. asset name) must be less than this link's.
          when anchor_element_link is {
            None ->
              bytearray.compare(
                anchor_element_asset_name,
                new_element_asset_name,
              ) == Less
            Some(anchor_element_link_key) -> and {
                bytearray.compare(
                  anchor_element_asset_name,
                  new_element_asset_name,
                ) == Less,
                bytearray.compare(
                  new_element_asset_name,
                  anchor_element_link_key,
                ) == Less,
              }
          },
          // 14b. Custom validation against the spent anchor element and the new
          //      node must pass.
          additional_validations(
            anchor_element_out_ref,
            False,
            anchor_element_asset_name,
            anchor_node_data,
            new_element_asset_name,
            new_node_data,
          ),
        }
    }
  }
}

/// Append a new element at the very end of an unordered list. There is no
/// validation for the new key to be greater than the anchor element's.
///
/// `additional_validations` takes the same arguments as
/// [`insert_ordered`](#insert_ordered).
pub fn append_unordered(
  list_nft_policy_id: PolicyId,
  anchor_element_input: Input,
  continued_anchor_element_output: Output,
  new_element_output: Output,
  additional_validations: fn(OutputReference, Bool, Key, Data, Key, Data) ->
    Bool,
  tx_mint: Value,
) -> Eval {
  let Input {
    output: anchor_element_input_utxo,
    output_reference: anchor_element_out_ref,
  } = anchor_element_input

  // 1. Only one token must be minted with linked list's authentication policy.
  expect [Pair(mint_name, mint_qty)] =
    tx_mint |> assets.tokens(list_nft_policy_id) |> dict.to_pairs

  // 2. Each of the 3 element UTxOs must only contain single authentication NFTs.
  // 3. All their datums must be properly structured (i.e. `Element`).
  // 4. The payment parts of their addresses must be `Script`s.
  let
    anchor_element_asset_name,
    anchor_element_data,
    anchor_element_link,
    cont_anchor_element_link,
    new_element_asset_name,
    new_element_data,
    new_element_link,
  <-
    validate_three_elements(
      list_nft_policy_id,
      anchor_element_input_utxo,
      continued_anchor_element_output,
      new_element_output,
    )

  // 5. New element's data must be `Node`.
  expect Node { data: new_node_data } = new_element_data

  expect and {
      // 6. New element's NFT asset name must be the one that's minted.
      mint_name == new_element_asset_name,
      // 7. NFT must be minted with a quantity of 1.
      mint_qty == 1,
      // 8. Anchor element must be the last element of the list.
      anchor_element_link == None,
      // 9. Reproduced anchor element must point to the new node.
      cont_anchor_element_link == Some(new_element_asset_name),
      // 10. The new element must point to no other nodes.
      new_element_link == None,
    }

  fn(
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    // 11. The new node's asset name must start with the provided label.
    expect
      bytearray.take(new_element_asset_name, node_key_prefix_length) == node_key_prefix
    when anchor_element_data is {
      Root { data: root_data } -> and {
          // 12a. Token name of the anchor element must be identical to the
          //      constant `root_key`.
          anchor_element_asset_name == root_key,
          // 13a. Custom validation against the spent anchor element and the new
          //      node must pass.
          additional_validations(
            anchor_element_out_ref,
            True,
            anchor_element_asset_name,
            root_data,
            new_element_asset_name,
            new_node_data,
          ),
        }
      Node { data: anchor_node_data } -> and {
          // 12b. The anchor node's key must start with the provided label.
          bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix,
          // 13b. Custom validation against the spent anchor element and the new
          //      node must pass.
          additional_validations(
            anchor_element_out_ref,
            False,
            anchor_element_asset_name,
            anchor_node_data,
            new_element_asset_name,
            new_node_data,
          ),
        }
    }
  }
}

/// Remove a node. It expects two spent UTxOs: the node subject to removal, and
/// its previous element (i.e. anchor element).
///
/// `additional_validations` takes the same arguments as
/// [`insert_ordered`](#insert_ordered), the difference being last `Key` and
/// `Data` are from the removing node.
pub fn remove(
  list_nft_policy_id: PolicyId,
  anchor_element_input: Input,
  removing_element_input: Input,
  continued_anchor_element_output: Output,
  additional_validations: fn(OutputReference, Bool, Key, Data, Key, Data) ->
    Bool,
  tx_mint: Value,
) -> Eval {
  let Input {
    output: anchor_element_input_utxo,
    output_reference: anchor_element_out_ref,
  } = anchor_element_input
  let Input { output: removing_element_input_utxo, .. } = removing_element_input

  // 1. Only one token must be burnt with linked list's authentication policy.
  expect [Pair(mint_name, mint_qty)] =
    tx_mint |> assets.tokens(list_nft_policy_id) |> dict.to_pairs

  // 2. Each of the 3 element UTxOs must only contain single authentication NFTs.
  // 3. All their datums must be properly structured (i.e. `Element`).
  // 4. The payment parts of their addresses must be `Script`s.
  let
    anchor_element_asset_name,
    anchor_element_data,
    anchor_element_link,
    cont_anchor_element_link,
    removing_element_asset_name,
    removing_element_data,
    removing_element_link,
  <-
    validate_three_elements(
      list_nft_policy_id,
      anchor_element_input_utxo,
      continued_anchor_element_output,
      removing_element_input_utxo,
    )

  // 5. Removing element's data must be `Node`.
  expect Node { data: removing_node_data } = removing_element_data

  expect and {
      // 6. Burnt NFT must be the same as the one from removing node.
      mint_name == removing_element_asset_name,
      // 7. Burnt quantity must be 1.
      mint_qty == -1,
      // 8. Anchor element must point to the node being removed.
      anchor_element_link == Some(removing_element_asset_name),
      // 9. Reproduced anchor element must point to what the removed element
      //    pointed to.
      cont_anchor_element_link == removing_element_link,
    }

  fn(
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    // 10. Asset name of the removing node must have the expected label.
    expect
      bytearray.take(removing_element_asset_name, node_key_prefix_length) == node_key_prefix
    when anchor_element_data is {
      Root { data: root_data } -> and {
          // 11a. Token name of the anchor element must be identical to the
          //      constant `root_key`.
          anchor_element_asset_name == root_key,
          // 12a. The new node's asset name must start with the provided label.
          additional_validations(
            anchor_element_out_ref,
            True,
            anchor_element_asset_name,
            root_data,
            removing_element_asset_name,
            removing_node_data,
          ),
        }
      Node { data: anchor_node_data } -> and {
          // 11b. The anchor node's key must start with the provided label.
          bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix,
          // 12b. Custom validation against the spent anchor element and the
          //      removing node must pass.
          additional_validations(
            anchor_element_out_ref,
            False,
            anchor_element_asset_name,
            anchor_node_data,
            removing_element_asset_name,
            removing_node_data,
          ),
        }
    }
  }
}

// ## Fold Functions

pub fn fold_and_update(
  list_nft_policy_id: PolicyId,
  anchor_root_input: Input,
  folding_node_input: Input,
  continued_anchor_root_output: Output,
  continued_folding_node_output: Output,
  additional_validations: fn(RootKey, Data, Key, Data, RootKey, Data, Key, Data) ->
    Bool,
) -> Eval {
  let
    anchor_root_script_hash,
    anchor_root_asset_name,
    anchor_root_data,
    anchor_root_link,
  <-
    authenticate_element_utxo_and_get_info(
      anchor_root_input.output,
      list_nft_policy_id,
    )
  let
    cont_anchor_root_script_hash,
    cont_anchor_root_asset_name,
    cont_anchor_root_data,
    cont_anchor_root_link,
  <-
    authenticate_element_utxo_and_get_info(
      continued_anchor_root_output,
      list_nft_policy_id,
    )
  expect and {
      anchor_root_script_hash == cont_anchor_root_script_hash,
      anchor_root_asset_name == cont_anchor_root_asset_name,
    }
  let
    folding_node_script_hash,
    folding_node_asset_name,
    folding_node_data,
    folding_node_link,
  <-
    authenticate_element_utxo_and_get_info(
      folding_node_input.output,
      list_nft_policy_id,
    )
  let
    cont_folding_node_script_hash,
    cont_folding_node_asset_name,
    cont_folding_node_data,
    cont_folding_node_link,
  <-
    authenticate_element_utxo_and_get_info(
      continued_folding_node_output,
      list_nft_policy_id,
    )
  todo
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

type FourElementInfo =
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
/// spent "anchor" element, and its "continued" reproduction (referred to as
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
      // 1. Anchor element must be reproduced at the same script.
      elem_0_script_hash == cont_elem_0_script_hash,
      // 2. New/removed element must go to / come from the same script as the
      //    anchor element.
      elem_0_script_hash == elem_1_script_hash,
      // 3. Anchor element must preserve its NFT.
      elem_0_asset_name == cont_elem_0_asset_name,
      // 4. Underlying data of the anchor element must remain unchanged.
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

fn validate_four_elements(
  nft_policy_id: PolicyId,
  elem_0: Output,
  cont_elem_0: Output,
  elem_1: Output,
  cont_elem_1: Output,
  return: FourElementInfo,
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
  let
    cont_elem_1_script_hash,
    cont_elem_1_asset_name,
    cont_elem_1_data,
    cont_elem_1_link,
  <- authenticate_element_utxo_and_get_info(cont_elem_1, nft_policy_id)
  expect and {
      // 1. Anchor element must be reproduced at the same script.
      elem_0_script_hash == cont_elem_0_script_hash,
      // 2. Updating element must come from the same script as the anchor
      //    element.
      elem_0_script_hash == elem_1_script_hash,
      // 3. Updating element must be reproduced at the same script.
      elem_1_script_hash == cont_elem_1_script_hash,
      // 4. Anchor element must preserve its NFT.
      elem_0_asset_name == cont_elem_0_asset_name,
      // 5. Updating element must preserve its NFT.
      elem_1_asset_name == cont_elem_1_asset_name,
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
