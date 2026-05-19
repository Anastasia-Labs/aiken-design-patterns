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
pub type Eval =
  fn(PolicyId, RootKey, NodeKeyPrefix, NodeKeyPrefixLength) -> Bool

/// Similar to [`Eval`](#eval), but for (`init`)[#init] and (`deinit`)[#deinit],
/// which don't validate node key prefixes.
pub type RootEval =
  fn(PolicyId, RootKey) -> Bool

///  Similar to [`Eval`](#eval), but with polymorphic return type. This allows
///  returning custom types with [`get_element_info`](#get_element_info).
pub type ElementEval<a> =
  fn(PolicyId, RootKey, NodeKeyPrefix, NodeKeyPrefixLength) -> a

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
  reader: Eval,
  list_nft_policy_id: PolicyId,
  root_key: RootKey,
  node_key_prefix: NodeKeyPrefix,
  node_key_prefix_length: NodeKeyPrefixLength,
) -> Bool {
  reader(list_nft_policy_id, root_key, node_key_prefix, node_key_prefix_length)
}

pub fn run_root_with(
  reader: RootEval,
  list_nft_policy_id: PolicyId,
  root_key: RootKey,
) -> Bool {
  reader(list_nft_policy_id, root_key)
}

pub fn run_element_with(
  reader: ElementEval<a>,
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

  return(output_address, lovelace_count, nft_name, utxo_datum_data, reference_script)
}
