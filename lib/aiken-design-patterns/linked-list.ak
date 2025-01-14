//// Storing lists in datums is generally impractical, as its growth can lead to
//// unspendable UTxOs due to limited resources available on-chain.
////
//// A linked list is a construct for storing an infinitely large array of
//// elements on-chain, such that each element is represented with a UTxO that
//// points to its immediate successor.

use aiken/builtin
use aiken/collection/dict
use aiken/crypto.{ScriptHash, blake2b_224, sha2_256}
use aiken/fuzz
use aiken/primitive/bytearray
use aiken_design_patterns/utils
use aiken_scott_utils/types.{Scott4}
use cardano/address.{Address, Script, VerificationKey}
use cardano/assets.{AssetName, PolicyId, Value}
use cardano/transaction.{InlineDatum, Input, Output, OutputReference}

// ## Types

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
  first_link: Option<ByteArray>,
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
      // 12. Produced head must point to the provided link.
      element_link == first_link,
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

// ## Tests

const test_head_key = #""

const test_node_key = #"00"

const test_node_key_length = 1

const b_data = builtin.b_data(#"00")

fn change_tn_by(b: ByteArray, change: Int) -> ByteArray {
  let b_length = bytearray.length(b)
  b
    |> bytearray.to_int_big_endian
    |> fn(x: Int) -> Int { x + change }
    |> bytearray.from_int_big_endian(b_length)
}

fn two_elements_fuzzer(
  label: ByteArray,
  covering_is_head: Bool,
  node_has_link: Bool,
  consequtive: Bool,
) -> Fuzzer<(ScriptHash, Input, Input)> {
  let label_length = bytearray.length(label)
  let tn_length = 32 - label_length
  let script_hash <- fuzz.and_then(fuzz.bytearray_fixed(28))
  let no_label_tn_0 <- fuzz.and_then(fuzz.bytearray_fixed(tn_length))
  let additional_no_label_tn <- fuzz.and_then(fuzz.bytearray_fixed(tn_length))
  let no_label_tn_1 =
    if consequtive {
      no_label_tn_0 |> change_tn_by(1)
    } else {
      additional_no_label_tn
    }
  let tn_0 =
    if covering_is_head {
      test_head_key
    } else {
      label |> bytearray.concat(no_label_tn_0)
    }
  let tn_1 = label |> bytearray.concat(no_label_tn_1)
  let lovelace_value = assets.from_lovelace(2_000_000)
  let beacon_0 = assets.from_asset(script_hash, tn_0, 1)
  let beacon_1 = assets.from_asset(script_hash, tn_1, 1)
  let v_0 = assets.merge(lovelace_value, beacon_0)
  let v_1 = assets.merge(lovelace_value, beacon_1)
  let out_ref_0 <- fuzz.and_then(utils.output_reference_fuzzer())
  let out_ref_1 <- fuzz.and_then(utils.output_reference_fuzzer())
  fuzz.constant(
    (
      script_hash,
      Input {
        output_reference: out_ref_0,
        output: Output {
          address: Address {
            payment_credential: Script(script_hash),
            stake_credential: None,
          },
          value: v_0,
          datum: InlineDatum(
            Element {
              data: if covering_is_head {
                Head(b_data)
              } else {
                Node(b_data)
              },
              next_link: Some(tn_1),
            },
          ),
          reference_script: None,
        },
      },
      Input {
        output: Output {
          address: Address {
            payment_credential: Script(script_hash),
            stake_credential: None,
          },
          value: v_1,
          datum: InlineDatum(
            Element {
              data: Node(b_data),
              next_link: if node_has_link {
                Some(
                  label |> bytearray.concat(no_label_tn_1 |> change_tn_by(1)),
                )
              } else {
                None
              },
            },
          ),
          reference_script: None,
        },
        output_reference: out_ref_1,
      },
    ),
  )
}

fn init_fuzzer(
  head_datum: Bool,
  next_link: Option<ByteArray>,
) -> Fuzzer<(List<Input>, OutputReference, ScriptHash, Output)> {
  let inputs <- fuzz.and_then(utils.user_inputs_fuzzer())
  let out_ref =
    builtin.head_list(inputs)
      |> fn(i: Input) -> OutputReference { i.output_reference }
  let (script_hash, script_output) <-
    fuzz.and_then(
      utils.authentic_script_output_with_given_asset_name_fuzzer(
        test_head_key,
        InlineDatum(
          Element {
            data: if head_datum {
              Head(b_data)
            } else {
              Node(b_data)
            },
            next_link,
          },
        ),
      ),
    )
  fuzz.constant((inputs, out_ref, script_hash, script_output))
}

test success_init(init_values via init_fuzzer(True, None)) {
  let (inputs, out_ref, script_hash, script_output) = init_values
  init(
    out_ref,
    script_output,
    script_hash,
    script_hash,
    fn(_) { True },
    None,
    inputs,
    assets.from_asset(script_hash, test_head_key, 1),
  )
    |> run_head_with(test_head_key)
}

test fail_init_bad_datum(init_values via init_fuzzer(False, None)) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  init(
    out_ref,
    script_output,
    script_hash,
    script_hash,
    fn(_) { True },
    None,
    inputs,
    assets.from_asset(script_hash, test_head_key, 1),
  )
    |> run_head_with(test_head_key)
}

test fail_init_bad_asset_name(init_values via init_fuzzer(True, None)) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  init(
    out_ref,
    script_output,
    script_hash,
    script_hash,
    fn(_) { True },
    None,
    inputs,
    assets.from_asset(script_hash, test_head_key, 1),
  )
    |> run_head_with("HEAD")
}

test fail_init_bad_nonce(init_values via init_fuzzer(True, None)) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  init(
    out_ref
      |> fn(o_ref: OutputReference) -> OutputReference {
          OutputReference {
            ..o_ref,
            transaction_id: sha2_256(o_ref.transaction_id),
          }
        },
    script_output,
    script_hash,
    script_hash,
    fn(_) { True },
    None,
    inputs,
    assets.from_asset(script_hash, test_head_key, 1),
  )
    |> run_head_with(test_head_key)
}

test fail_init_bad_first_link(init_values via init_fuzzer(True, None)) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  init(
    out_ref,
    script_output,
    script_hash,
    script_hash,
    fn(_) { True },
    Some(test_head_key),
    inputs,
    assets.from_asset(script_hash, test_head_key, 1),
  )
    |> run_head_with(test_head_key)
}

test fail_init_bad_nft_symbol(init_values via init_fuzzer(True, None)) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  init(
    out_ref,
    script_output,
    script_hash,
    blake2b_224(script_hash),
    fn(_) { True },
    None,
    inputs,
    assets.from_asset(script_hash, test_head_key, 1),
  )
    |> run_head_with(test_head_key)
}

test fail_init_bad_destination(init_values via init_fuzzer(True, None)) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  init(
    out_ref,
    script_output,
    blake2b_224(script_hash),
    script_hash,
    fn(_) { True },
    None,
    inputs,
    assets.from_asset(script_hash, test_head_key, 1),
  )
    |> run_head_with(test_head_key)
}

test fail_init_bad_head_data_validator(
  init_values via init_fuzzer(True, None),
) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  init(
    out_ref,
    script_output,
    script_hash,
    script_hash,
    fn(_) { False },
    None,
    inputs,
    assets.from_asset(script_hash, test_head_key, 1),
  )
    |> run_head_with(test_head_key)
}

test fail_init_bad_mint(init_values via init_fuzzer(True, None)) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  init(
    out_ref,
    script_output,
    script_hash,
    script_hash,
    fn(_) { True },
    None,
    inputs,
    assets.zero,
  )
    |> run_head_with(test_head_key)
}

test success_deinit(init_values via init_fuzzer(True, None)) {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let head_input = Input { output_reference: out_ref, output: script_output }
  deinit(
    head_input,
    script_hash,
    script_hash,
    fn(_) { True },
    assets.from_asset(script_hash, test_head_key, -1),
  )
    |> run_head_with(test_head_key)
}

test fail_deinit_bad_datum(init_values via init_fuzzer(False, None)) fail {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let head_input = Input { output_reference: out_ref, output: script_output }
  deinit(
    head_input,
    script_hash,
    script_hash,
    fn(_) { True },
    assets.from_asset(script_hash, test_head_key, -1),
  )
    |> run_head_with(test_head_key)
}

test fail_deinit_bad_link(
  init_values via init_fuzzer(
    True,
    Some(#"0000000000000000000000000000000000000000000000000000000000000000"),
  ),
) fail {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let head_input = Input { output_reference: out_ref, output: script_output }
  deinit(
    head_input,
    script_hash,
    script_hash,
    fn(_) { True },
    assets.from_asset(script_hash, test_head_key, -1),
  )
    |> run_head_with(test_head_key)
}

test fail_deinit_bad_origin(init_values via init_fuzzer(True, None)) fail {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let head_input = Input { output_reference: out_ref, output: script_output }
  deinit(
    head_input,
    blake2b_224(script_hash),
    script_hash,
    fn(_) { True },
    assets.from_asset(script_hash, test_head_key, -1),
  )
    |> run_head_with(test_head_key)
}

test fail_deinit_bad_nft_symbol(init_values via init_fuzzer(True, None)) fail {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let head_input = Input { output_reference: out_ref, output: script_output }
  deinit(
    head_input,
    script_hash,
    blake2b_224(script_hash),
    fn(_) { True },
    assets.from_asset(script_hash, test_head_key, -1),
  )
    |> run_head_with(test_head_key)
}

test fail_deinit_bad_head_data_validator(
  init_values via init_fuzzer(True, None),
) fail {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let head_input = Input { output_reference: out_ref, output: script_output }
  deinit(
    head_input,
    script_hash,
    script_hash,
    fn(_) { False },
    assets.from_asset(script_hash, test_head_key, -1),
  )
    |> run_head_with(test_head_key)
}

test fail_deinit_bad_mint(init_values via init_fuzzer(True, None)) fail {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let head_input = Input { output_reference: out_ref, output: script_output }
  deinit(head_input, script_hash, script_hash, fn(_) { True }, assets.zero)
    |> run_head_with(test_head_key)
}

fn addition_test_helper(
  covering_is_head: Bool,
  args: (ScriptHash, Input, Input),
) -> Fuzzer<(ScriptHash, Input, Output, Output, Value)> {
  let (script_hash, cont_head_input, node_input) = args
  expect InlineDatum(node_datum_data) = node_input.output.datum
  expect Element { next_link: nodes_next_link, .. }: GenericElement =
    node_datum_data
  let head_element: GenericElement =
    Element(
      if covering_is_head {
        Head(b_data)
      } else {
        Node(b_data)
      },
      nodes_next_link,
    )
  let head_output: Output =
    Output { ..cont_head_input.output, datum: InlineDatum(head_element) }
  let head_input: Input = Input { ..cont_head_input, output: head_output }
  fuzz.constant(
    (
      script_hash,
      head_input,
      cont_head_input.output,
      node_input.output,
      node_input.output.value |> assets.without_lovelace,
    ),
  )
}

fn insert_ordered_fuzzer(
  label: ByteArray,
  covering_is_head: Bool,
  node_has_link: Bool,
) -> Fuzzer<(ScriptHash, Input, Output, Output, Value)> {
  let args <-
    fuzz.and_then(
      two_elements_fuzzer(label, covering_is_head, node_has_link, True),
    )
  addition_test_helper(covering_is_head, args)
}

test success_insert_head_covering(
  insert_ordered_args via insert_ordered_fuzzer(test_node_key, True, False),
) {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    insert_ordered_args
  insert_ordered(
    script_hash,
    head_input,
    cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test success_insert_node_covering(
  insert_ordered_args via insert_ordered_fuzzer(test_node_key, False, False),
) {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    insert_ordered_args
  insert_ordered(
    script_hash,
    head_input,
    cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test success_insert_head_covering_with_link(
  insert_ordered_args via insert_ordered_fuzzer(test_node_key, True, True),
) {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    insert_ordered_args
  insert_ordered(
    script_hash,
    head_input,
    cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test success_insert_node_covering_with_link(
  insert_ordered_args via insert_ordered_fuzzer(test_node_key, False, True),
) {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    insert_ordered_args
  insert_ordered(
    script_hash,
    head_input,
    cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

fn alter_outputs_address(output: Output) -> Output {
  expect Script(script_hash) = output.address.payment_credential
  let altered_address: Address =
    Address {
      payment_credential: VerificationKey(script_hash),
      stake_credential: None,
    }
  Output { ..output, address: altered_address }
}

test fail_insert_head_covering_bad_node_destination(
  insert_ordered_args via insert_ordered_fuzzer(test_node_key, True, False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    insert_ordered_args
  let altered_node_output: Output = alter_outputs_address(node_output)
  insert_ordered(
    script_hash,
    head_input,
    cont_head_output,
    altered_node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail_insert_node_covering_bad_node_destination(
  insert_ordered_args via insert_ordered_fuzzer(test_node_key, False, False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    insert_ordered_args
  let altered_node_output: Output = alter_outputs_address(node_output)
  insert_ordered(
    script_hash,
    head_input,
    cont_head_output,
    altered_node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail_insert_node_covering_with_link_bad_node_destination(
  insert_ordered_args via insert_ordered_fuzzer(test_node_key, False, True),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    insert_ordered_args
  let altered_node_output: Output = alter_outputs_address(node_output)
  insert_ordered(
    script_hash,
    head_input,
    cont_head_output,
    altered_node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail_insert_head_covering_with_link_bad_continued_head_destination(
  insert_ordered_args via insert_ordered_fuzzer(test_node_key, True, True),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    insert_ordered_args
  let altered_cont_head_output = alter_outputs_address(cont_head_output)
  insert_ordered(
    script_hash,
    head_input,
    altered_cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

fn alter_outputs_link(output: Output) -> Output {
  expect InlineDatum(datum_data) = output.datum
  expect Element { data, next_link }: GenericElement = datum_data
  let altered_datum =
    InlineDatum(
      Element(
        data,
        when next_link is {
          None ->
            Some(#"00000000000000000000000000000000000000000000000000000000")
          Some(_) -> None
        },
      ),
    )
  Output { ..output, datum: altered_datum }
}

test fail_insert_head_covering_bad_node_link(
  insert_ordered_args via insert_ordered_fuzzer(test_node_key, True, False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    insert_ordered_args
  let altered_node_output: Output = alter_outputs_link(node_output)
  insert_ordered(
    script_hash,
    head_input,
    cont_head_output,
    altered_node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail_insert_node_covering_bad_node_link(
  insert_ordered_args via insert_ordered_fuzzer(test_node_key, False, False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    insert_ordered_args
  let altered_node_output: Output = alter_outputs_link(node_output)
  insert_ordered(
    script_hash,
    head_input,
    cont_head_output,
    altered_node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail_insert_node_covering_with_link_bad_node_link(
  insert_ordered_args via insert_ordered_fuzzer(test_node_key, False, True),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    insert_ordered_args
  let altered_node_output: Output = alter_outputs_link(node_output)
  insert_ordered(
    script_hash,
    head_input,
    cont_head_output,
    altered_node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail_insert_head_covering_with_link_bad_continued_head_link(
  insert_ordered_args via insert_ordered_fuzzer(test_node_key, True, True),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    insert_ordered_args
  let altered_cont_head_output = alter_outputs_link(cont_head_output)
  insert_ordered(
    script_hash,
    head_input,
    altered_cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

fn append_unordered_fuzzer(
  label: ByteArray,
  covering_is_head: Bool,
  node_has_link: Bool,
) -> Fuzzer<(ScriptHash, Input, Output, Output, Value)> {
  let args <-
    fuzz.and_then(
      two_elements_fuzzer(label, covering_is_head, node_has_link, False),
    )
  addition_test_helper(covering_is_head, args)
}

test success_append_head_covering(
  append_unordered_args via append_unordered_fuzzer(test_node_key, True, False),
) {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  append_unordered(
    script_hash,
    head_input,
    cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test success_append_node_covering(
  append_unordered_args via append_unordered_fuzzer(test_node_key, False, False),
) {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  append_unordered(
    script_hash,
    head_input,
    cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail_append_head_covering_with_link(
  append_unordered_args via append_unordered_fuzzer(test_node_key, True, True),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  append_unordered(
    script_hash,
    head_input,
    cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail_append_node_covering_with_link(
  append_unordered_args via append_unordered_fuzzer(test_node_key, False, True),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  append_unordered(
    script_hash,
    head_input,
    cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail_append_head_covering_bad_nft_symbol(
  append_unordered_args via append_unordered_fuzzer(test_node_key, True, False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  append_unordered(
    blake2b_224(script_hash),
    head_input,
    cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail_append_head_covering_bad_cont_head_destination(
  append_unordered_args via append_unordered_fuzzer(test_node_key, True, False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  let altered_cont_head_output = alter_outputs_address(cont_head_output)
  append_unordered(
    script_hash,
    head_input,
    altered_cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail_append_head_covering_bad_node_destination(
  append_unordered_args via append_unordered_fuzzer(test_node_key, True, False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  let altered_node_output = alter_outputs_address(node_output)
  append_unordered(
    script_hash,
    head_input,
    cont_head_output,
    altered_node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail_append_head_covering_bad_cont_head_link(
  append_unordered_args via append_unordered_fuzzer(test_node_key, True, False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  let altered_cont_head_output = alter_outputs_link(cont_head_output)
  append_unordered(
    script_hash,
    head_input,
    altered_cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail_append_head_covering_bad_node_link(
  append_unordered_args via append_unordered_fuzzer(test_node_key, True, False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  let altered_node_output = alter_outputs_link(node_output)
  append_unordered(
    script_hash,
    head_input,
    cont_head_output,
    altered_node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail_append_head_covering_bad_mint(
  append_unordered_args via append_unordered_fuzzer(test_node_key, True, False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, _mint_value) =
    append_unordered_args
  append_unordered(
    script_hash,
    head_input,
    cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    assets.zero,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail_append_node_covering_bad_nft_symbol(
  append_unordered_args via append_unordered_fuzzer(test_node_key, False, False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  append_unordered(
    blake2b_224(script_hash),
    head_input,
    cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail_append_node_covering_bad_cont_node_destination(
  append_unordered_args via append_unordered_fuzzer(test_node_key, False, False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  let altered_cont_node_output = alter_outputs_address(cont_head_output)
  append_unordered(
    blake2b_224(script_hash),
    head_input,
    altered_cont_node_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail_append_node_covering_bad_cont_node_link(
  append_unordered_args via append_unordered_fuzzer(test_node_key, False, False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  let altered_cont_node_output = alter_outputs_link(cont_head_output)
  append_unordered(
    blake2b_224(script_hash),
    head_input,
    altered_cont_node_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail_append_node_covering_bad_node_destination(
  append_unordered_args via append_unordered_fuzzer(test_node_key, False, False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  let altered_node_output = alter_outputs_link(node_output)
  append_unordered(
    blake2b_224(script_hash),
    head_input,
    cont_head_output,
    altered_node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}
