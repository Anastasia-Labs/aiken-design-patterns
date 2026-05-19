//// @hidden
//// This module contains datatypes and logic shared by `simple` and `advanced`
//// linked list modules. These are not meant to be used directly.

use aiken/builtin
use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken/primitive/bytearray
use aiken_design_patterns/singular_utxo_indexer
use cardano/address.{Address, Credential}
use cardano/assets.{AssetName, Lovelace, PolicyId, Value}
use cardano/transaction.{Datum, InlineDatum, Input, Output, OutputReference}

/// An alias for the asset name of the NFT held in the root element. This can be
/// zero bytes or more (32 bytes at most).
///
/// Choose this outside the node namespace: it must not begin with
/// `NodeKeyPrefix`. The usual low-budget setup is an empty root key, a non-empty
/// node prefix, and non-empty node keys.
///
/// > [!NOTE]
/// > Keep in mind that some UTF-8 characters occupy more than 1 byte. For
/// > example the tree emoji (🌳) takes up 4 bytes.
pub type RootKey =
  AssetName

/// Alias for representing the keys of linked list nodes. This must be at least
/// one byte long, and contracts should implement validations on them depending
/// on their needs. The generic module assumes this invariant rather than
/// re-checking it on every operation.
///
/// Requiring keys to be unique is the recommended approach (e.g. making sure
/// it's hash of an input's out ref). If you do need to allow duplicate keys,
/// proceed with extreme caution as linked list integrity breaks without some
/// other means of preserving it.
///
/// As with the general principle of this API, for ordered operations (e.g.
/// [`insert_ascending`](#insert_ascending)), proper ordering is already
/// validated.
pub type NodeKey =
  ByteArray

/// Bytes prefixing all linked list nodes (i.e. all elements except for the
/// root). It should be non-empty and must not prefix `RootKey`.
///
/// Note that the total number of bytes allowed for NFTs of linked list elements
/// can be 32 bytes at most. Therefore, if for example your prefix occupies 4
/// bytes, your keys can have 28 bytes at most.
pub type NodeKeyPrefix =
  ByteArray

/// A sort of boilerplate to reduce execution budgets. You can use `const` to
/// leverage Aiken compiler's optimizations:
/// ```aiken
/// pub const node_key_prefix = "🔗"
///
/// pub const node_key_prefix_length =
///   bytearray.length(node_key_prefix)
/// ```
pub type NodeKeyPrefixLength =
  Int

pub type LovelaceChange =
  Lovelace

pub type RootData =
  Data

pub type NodeData =
  Data

pub type Link =
  Option<NodeKey>

/// This is the datatype for allowing you to provide environment constants. To
/// be a bit nerdy, this is essentially a `Reader` monad.
///
/// > [!NOTE]
/// > To prevent excessive overhead, this function requires the length of the
/// > key prefix to be provided explicitly, next to the key prefix itself
/// > (otherwise the length should have been validated on-chain).
///
/// > [!NOTE]
/// > The length of the `RootKey` can be 32 bytes at the maximum. On the other
/// > hand, the length of any of the `NodeKey`s can be at most
/// > `(32 - NodeKeyPrefixLength)`. "Length" here refers to the number of bytes
/// > after the asset name is decoded from any of the encoding schemes (e.g.
/// > UTF-8).
pub type Eval<result> =
  fn(PolicyId, RootKey, NodeKeyPrefix, NodeKeyPrefixLength) -> result

/// Similar to [`Eval`](#eval), but for (`init`)[#init] and (`deinit`)[#deinit],
/// which don't validate node key prefixes.
pub type RootEval<result> =
  fn(PolicyId, RootKey) -> result


// ## Finalization Functions

/// This typically ends up as boilerplate by defining a helper like this:
/// ```aiken
/// use aiken_design_patterns/linked_list
/// 
/// const node_key_prefix = "NODE"
/// 
/// const node_key_prefix_length =
///   bytearray.length(node_key_prefix)
/// 
/// pub fn finalize_linked_list(
///   eval: linked_list.Eval,
///   list_nft_policy_id: PolicyId,
/// ) -> Bool {
///   linked_list.run_eval_with(
///     eval,
///     list_nft_policy_id,
///     node_key_prefix,
///     node_key_prefix_length,
///   )
/// }
/// ```
/// 
/// As an example, with this you'll be able to turn your `Eval` results to
/// `Bool`s as such:
/// ```aiken
/// // In your minting contract:
///
/// let linked_list_eval = insert_ascending(...)
/// 
/// expect linked_list_eval |> finalize_linked_list(own_policy_id)
/// ```
pub fn run_eval_with(
  reader: Eval<a>,
  list_nft_policy_id: PolicyId,
  root_key: RootKey,
  node_key_prefix: NodeKeyPrefix,
  node_key_prefix_length: NodeKeyPrefixLength,
) -> a {
  reader(list_nft_policy_id, root_key, node_key_prefix, node_key_prefix_length)
}

pub fn run_root_with(
  reader: RootEval<a>,
  list_nft_policy_id: PolicyId,
  root_key: RootKey,
) -> a {
  reader(list_nft_policy_id, root_key)
}

pub fn run_element_with(
  reader: Eval<a>,
  list_nft_policy_id: PolicyId,
  root_key: RootKey,
  node_key_prefix: NodeKeyPrefix,
  node_key_prefix_length: NodeKeyPrefixLength,
) -> a {
  reader(list_nft_policy_id, root_key, node_key_prefix, node_key_prefix_length)
}

/// Given a UTxO (`Output`), this function authenticates it by checking it
/// contains only one NFT (apart from ADA) whose policy ID matches the provided
/// one, and its quantity equals one
///
/// Upon successful authentication, it returns the following information about
/// the element:
/// - Its address
/// - Its Lovelace count
/// - Its NFT's asset name (i.e. element's key)
/// - Its inline datum data
/// - Its attached script (if any)
pub fn authenticate_element_utxo_and_get_info_helper(
  element_utxo: Output,
  nft_policy_id: PolicyId,
  return: fn(Address, Lovelace, AssetName, Data, Option<ScriptHash>) -> result,
) -> result {
  // 1. Its datum must be inlined, and no script must be attached to it.
  expect Output {
    address: output_address,
    value,
    datum: InlineDatum(utxo_datum_data),
    reference_script,
  } = element_utxo

  // 2. Apart from ADA, only one NFT must be included in the UTxO, such that its
  //    policy ID matched the provided one, and its quantity equals one.
  expect [(_, _, lovelace_count),
    (nft_symbol, nft_name, nft_qty)] = assets.flatten(value)
  expect and {
      nft_symbol == nft_policy_id,
      nft_qty == 1,
    }

  return(
    output_address,
    lovelace_count,
    nft_name,
    utxo_datum_data,
    reference_script,
  )
}

type InternalInputInfo<result> =
  fn(Input, Lovelace, AssetName, Data) -> result

/// Goes through the input list and performs the given validation at its first
/// encounter with the authentic input. After that, if it encounters any other UTxO
/// with a linked list NFT policy ID, it fails.
///
/// An important assumption here is that no authentic linked list element UTxO
/// can carry tokens other than ADA and its NFT. So it only checks for absence
/// of list NFT if the input's value has the same shape (namely, only ADA with
/// one other policy ID).
pub fn validate_singular_authentic_input_helper(
  inputs: List<Input>,
  nft_policy_id: PolicyId,
  return: InternalInputInfo<Bool>,
) -> Bool {
  let nft_policy_id_data: Data = builtin.b_data(nft_policy_id)
  let i, input_found <- list.foldr(inputs, False)

  let i_output = i.output
  let i_value = i_output.value

  if input_found {
    let value_unmapped: List<Pair<Data, Data>> = builtin.un_map_data(i_value)

    let input_non_ada_assets_pairs = value_unmapped |> builtin.tail_list

    when input_non_ada_assets_pairs is {
      [policy_name_pair] -> {
        // If the singular list element has been found already and the input has
        // only one other asset apart from ADA, the only requirement is that
        // it must not be of the same policy ID as the linked list's.
        expect policy_name_pair.1st != nft_policy_id_data
        input_found
      }
      _ ->
        // Any other shape for the input value is acceptable since we are
        // assuming linked list UTxOs cannot carry assets other than ADA and
        // their NFTs.
        input_found
    }
  } else {
    process_input_for_nft(
      nft_policy_id_data,
      i,
      i_output,
      i_value,
      input_found,
      return,
    )
  }
}

/// An internal helper for breaking down a `Value` through `Data` encoding and
/// builtin functions.
fn process_input_for_nft(
  nft_policy_id_data: Data,
  i: Input,
  i_output: Output,
  i_value: Value,
  fold_acc: acc,
  return: InternalInputInfo<acc>,
) -> acc {
  let v_unmapped: List<Pair<Data, Data>> = builtin.un_map_data(i_value)

  let v_non_ada_assets_pairs = v_unmapped |> builtin.tail_list

  when v_non_ada_assets_pairs is {
    [policy_name_pair] ->
      if policy_name_pair.1st == nft_policy_id_data {
        let
          i_lovelace,
          nft_name,
          datum_data,
        <-
          internal_input_processor_validator(
            i_output.datum,
            v_unmapped,
            policy_name_pair.2nd,
          )

        return(i, i_lovelace, nft_name, datum_data)
      } else {
        fold_acc
      }
    _ -> fold_acc
  }
}

/// Shared internal logic for singular and dual input validators. This is used
/// for validating a given list of "asset name - quantity" pairs (as `Data`)
/// matches correctly to expected shape for list elements.
///
/// It also requires the prior unmapped version of the original `Value` so that
/// it can extract the Lovelace count as well.
fn internal_input_processor_validator(
  i_datum: Datum,
  v_unmapped: List<Pair<Data, Data>>,
  names_qty_pairs_data: Data,
  return: fn(Lovelace, AssetName, Data) -> res,
) -> res {
  expect [nft_name_qty_pair] = builtin.un_map_data(names_qty_pairs_data)

  let nft_name = nft_name_qty_pair.1st |> builtin.un_b_data()

  // TODO: This check might not be needed.
  expect nft_name_qty_pair.2nd == builtin.i_data(1)

  let i_lovelace_pair =
    builtin.head_list(v_unmapped).2nd
      |> builtin.un_map_data
      |> builtin.head_list

  let i_lovelace = i_lovelace_pair.2nd |> builtin.un_i_data()

  expect InlineDatum(i_datum_data) = i_datum

  return(i_lovelace, nft_name, i_datum_data)
}

type InputsFoundScott =
  fn(
    fn() -> Bool,
    fn(Input, Credential, Lovelace, AssetName, Data) -> Bool,
    fn() -> Bool,
  ) ->
    Bool

/// Validate exactly two authentic list inputs using a Scott-encoded fold state.
/// This assumes the list payment credential is dedicated to list inputs; any
/// additional same-payment input is invalid even if it does not carry a list
/// NFT.
///
/// Implementation note: the fold is intentionally asymmetric for budget reasons.
/// After one authentic list input has been found, a later input at the same
/// payment credential is treated as the expected second list input and must
/// authenticate as such. Therefore, non-authentic same-payment inputs can cause
/// order-dependent rejection. This is desirable: callers must not include them.
///
/// The fold accumulator is an eliminator for the three possible states:
/// - no authentic input found
/// - one authentic input found
/// - two authentic inputs found
pub fn validate_dual_authentic_inputs_helper(
  anchor_input_outref: OutputReference,
  inputs: List<Input>,
  nft_policy_id: PolicyId,
  with: fn(Input, Lovelace, AssetName, Data, Input, Lovelace, AssetName, Data) ->
    Bool,
) -> Bool {
  let nft_policy_id_data = builtin.b_data(nft_policy_id)

  let final_inputs_found: InputsFoundScott =
    list.foldr(
      inputs,
      fn(on_none, _on_one, _on_two) { on_none() },
      fn(i, inputs_found) {
        fn(on_none, on_one, on_two) {
          let i_output = i.output

          inputs_found(
            fn() {
              let value_unmapped: List<Pair<Data, Data>> =
                builtin.un_map_data(i_output.value)

              let non_ada_assets_pairs = value_unmapped |> builtin.tail_list

              when non_ada_assets_pairs is {
                [policy_name_pair] ->
                  if policy_name_pair.1st == nft_policy_id_data {
                    let
                      i_lovelace,
                      i_nft_name,
                      i_datum_data,
                    <-
                      internal_input_processor_validator(
                        i_output.datum,
                        value_unmapped,
                        policy_name_pair.2nd,
                      )

                    on_one(
                      i,
                      i_output.address.payment_credential,
                      i_lovelace,
                      i_nft_name,
                      i_datum_data,
                    )
                  } else {
                    on_none()
                  }
                _ -> on_none()
              }
            },
            fn(
              i0_input: Input,
              i0_payment_cred: Credential,
              i0_lovelace: Lovelace,
              i0_nft_name: AssetName,
              i0_datum_data: Data,
            ) {
              let Output { address: i_address, value: i_value, .. } = i_output

              if i0_payment_cred == i_address.payment_credential {
                let i1_value_unmapped: List<Pair<Data, Data>> =
                  builtin.un_map_data(i_value)

                expect [i1_policy_name_pair] =
                  i1_value_unmapped |> builtin.tail_list

                expect i1_policy_name_pair.1st == nft_policy_id_data

                let
                  i1_lovelace,
                  i1_nft_name,
                  i1_datum_data,
                <-
                  internal_input_processor_validator(
                    i_output.datum,
                    i1_value_unmapped,
                    i1_policy_name_pair.2nd,
                  )

                expect
                  if i0_input.output_reference == anchor_input_outref {
                    with(
                      i0_input,
                      i0_lovelace,
                      i0_nft_name,
                      i0_datum_data,
                      i,
                      i1_lovelace,
                      i1_nft_name,
                      i1_datum_data,
                    )
                  } else {
                    expect i.output_reference == anchor_input_outref
                    with(
                      i,
                      i1_lovelace,
                      i1_nft_name,
                      i1_datum_data,
                      i0_input,
                      i0_lovelace,
                      i0_nft_name,
                      i0_datum_data,
                    )
                  }

                on_two()
              } else {
                on_one(
                  i0_input,
                  i0_payment_cred,
                  i0_lovelace,
                  i0_nft_name,
                  i0_datum_data,
                )
              }
            },
            fn() {
              let value_unmapped = builtin.un_map_data(i_output.value)

              let input_non_ada_assets_pairs =
                value_unmapped |> builtin.tail_list

              when input_non_ada_assets_pairs is {
                [policy_name_pair] -> {
                  expect policy_name_pair.1st != nft_policy_id_data
                  on_two()
                }
                _ -> on_two()
              }
            },
          )
        }
      },
    )

  final_inputs_found(fn() { False }, fn(_, _, _, _, _) { False }, fn() { True })
}
