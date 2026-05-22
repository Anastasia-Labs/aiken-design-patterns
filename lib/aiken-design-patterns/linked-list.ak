//// Storing lists in datums is generally impractical, as its growth can lead to
//// unspendable UTxOs due to limited resources available on-chain.
////
//// A linked list is a construct for storing an infinitely large array of
//// elements on-chain, such that each element is represented with a UTxO that
//// points to its immediate successor.
////
//// ## Usage Guideline
////
//// Contracts using this module must keep the linked list controlled by one
//// dedicated spend script and one list NFT minting policy:
////
//// 1. Define the spend script datum as an applied alias of `Element<a, b>`:
//// ```aiken
//// pub type Datum = linked_list.Element<RootType, NodeType>
//// ```
//// 2. Ensure that the UTxO produced by `init` goes to that spend script
////    credential.
//// 3. Implement list spend scripts so they only succeed through this module's
////    two spend helpers: `spend_for_adding_or_removing_an_element` and
////    `spend_for_updating_elements_data`.
//// 4. Implement list mint scripts so they only succeed through this module's
////    provided mint helpers.
//// 5. Choose root and node NFT names so their namespaces are disjoint: use a
////    non-empty `node_key_prefix`, non-empty node keys, and a `root_key` that
////    does not begin with the node prefix. This avoids root/node identity
////    collisions without adding repeated runtime checks to every operation.
////
//// These rules preserve the invariant that linked list NFTs cannot leave the
//// list spend script/payment credential.
////
//// The guideline above implies five important design constraints:
//// 1. The default API does not expose or validate reference scripts on element
////    UTxOs. Use the advanced module if reference scripts must be preserved or
////    inspected by callbacks.
//// 2. While continued anchor nodes are validated to go to the same
////    **address**, for new/removed nodes only the payment parts are validated
////    to match the anchors'. This allows customization of staking parts of new
////    nodes, while preserving the staking parts of existing elements.
//// 3. Extra mints under the list NFT policy beyond the NFT needed for the list
////    structure are unsupported (e.g. CIP-68 tokens are not supported). The
////    provided mint helpers enforce exactly the mint/burn operation needed by
////    the list structure.
//// 4. List operations assume that the list script/payment credential is
////    dedicated to the linked list. For remove/fold operations, every spent
////    input at that payment credential is expected to be an authentic list
////    element participating in the operation. Non-authentic inputs at the same
////    payment credential are invalid transaction construction; implementations
////    may reject them without trying to ignore or classify them.
//// 5. The module assumes root and node asset-name namespaces are disjoint. It
////    validates the root key and node prefix at operation boundaries, but does
////    not add extra comparisons to prove namespace disjointness on-chain.

use aiken/collection/dict
use aiken/crypto.{ScriptHash}
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list/internal.{
  authenticate_element_utxo_and_get_info_helper, is_only_mint_under_policy,
  validate_dual_authentic_inputs_helper,
  validate_singular_authentic_input_helper,
}
use aiken_design_patterns/singular_utxo_indexer
use cardano/address.{Address}
use cardano/assets.{AssetName, Lovelace, PolicyId, Value}
use cardano/transaction.{Input, Output, OutputReference}

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
/// it's a hash of an input's out ref). If you do need to allow duplicate keys,
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

/// Reader alias for helpers that can validate either root elements or node
/// elements. These helpers need both namespaces: the root asset name, and the
/// node asset-name prefix.
///
/// > [!NOTE]
/// > To prevent excessive overhead, readers receive the node prefix length
/// > explicitly, next to the node prefix itself (otherwise the length would
/// > need to be computed on-chain).
///
/// > [!NOTE]
/// > The length of the `RootKey` can be 32 bytes at the maximum. On the other
/// > hand, the length of any of the `NodeKey`s can be at most
/// > `(32 - NodeKeyPrefixLength)`. "Length" here refers to the number of bytes
/// > after the asset name is decoded from any of the encoding schemes (e.g.
/// > UTF-8).
pub type ElementEval<result> =
  fn(PolicyId, RootKey, NodeKeyPrefix, NodeKeyPrefixLength) -> result

/// Reader alias for helpers that only need the list policy and root asset name.
/// These helpers don't validate node keys, so they don't require the node
/// namespace constants.
pub type RootEval<result> =
  fn(PolicyId, RootKey) -> result

/// Reader alias for helpers that only need the list policy and node namespace.
/// These helpers don't validate the root asset name.
pub type NodeEval<result> =
  fn(PolicyId, NodeKeyPrefix, NodeKeyPrefixLength) -> result

// ## Finalization Functions

/// `ElementEval` typically ends up as boilerplate by defining a helper like
/// this:
/// ```aiken
/// use aiken_design_patterns/linked_list
/// 
/// const node_key_prefix = "NODE"
///
/// const root_key = #""
/// 
/// const node_key_prefix_length =
///   bytearray.length(node_key_prefix)
/// 
/// pub fn finalize_linked_list(
///   eval: linked_list.ElementEval<Bool>,
///   list_nft_policy_id: PolicyId,
/// ) -> Bool {
///   linked_list.run_element_with(
///     eval,
///     list_nft_policy_id,
///     root_key,
///     node_key_prefix,
///     node_key_prefix_length,
///   )
/// }
/// ```
/// 
/// As an example, with this you'll be able to turn your `ElementEval` results
/// to `Bool`s as such:
/// ```aiken
/// // In your minting contract:
///
/// let linked_list_eval = insert_ascending(...)
/// 
/// expect linked_list_eval |> finalize_linked_list(own_policy_id)
/// ```
///
/// If your redeemer asserts whether a root must be expected or a node, use
/// either [`run_root_with`](#run_root_with) or [`run_node_with`](#run_node_with)
/// with the narrower set of constants.
pub fn run_element_with(
  reader: ElementEval<a>,
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

pub fn run_node_with(
  reader: NodeEval<a>,
  list_nft_policy_id: PolicyId,
  node_key_prefix: NodeKeyPrefix,
  node_key_prefix_length: NodeKeyPrefixLength,
) -> a {
  reader(list_nft_policy_id, node_key_prefix, node_key_prefix_length)
}

/// The terminology used here is as follows:
/// - `Root` is the first element of the linked list
/// - `Node` is any other element in a linked list other than the root
/// - `Element` is the umbrella term to refer to either the root or nodes
///
/// You probably won't need to interact with this.
pub type Element<root_data, node_data> {
  data: ElementData<root_data, node_data>,
  link: Link,
}

/// Similar to [`Element`](#Element) above, the API is designed so that you
/// wouldn't need to work with this datatype directly.
///
/// Continuations that provide element data implicitly signal whether it should
/// be coerced into a `root_data` or a `node_data` through the (potential) key.
/// That is, if no key is provided, it means the element at hand is a root
/// element.
pub type ElementData<root_data, node_data> {
  Root { data: root_data }
  Node { data: node_data }
}

pub type GenericElement =
  Element<Data, Data>

pub type GenericElementData =
  ElementData<Data, Data>

// ## Initialization and De-initialization

/// Initialize a linked list, i.e. produce a UTxO which contains some ADA and
/// the authentication NFT, with a `Root` element data. The asset name of the
/// NFT (i.e. `RootKey`) is something that must be validated by passing the
/// result of this function to [`run_root_with`](#run_root_with).
pub fn init(
  nonce_validated: Bool,
  produced_element_output: Output,
  tx_mint: Value,
  root_validator: fn(Lovelace, Data) -> Bool,
) -> RootEval<Bool> {
  // 1. Helper guardrail for caller-provided nonce validation.
  expect nonce_validated

  fn(list_nft_policy_id: PolicyId, root_key: RootKey) -> Bool {
    // 2. The produced UTxO must only contain the authentication/key NFT.
    // 3. Its datum must be properly structured.
    let
      _element_address,
      element_lovelace,
      element_asset_name,
      element_data,
      element_link,
      _element_ref_script,
    <-
      authenticate_element_utxo_and_get_info(
        produced_element_output,
        list_nft_policy_id,
      )

    // 4. Contained data must be `Root`.
    expect Root { data: root_data } = element_data

    // 5. The authentication NFT must use the root key.
    expect element_asset_name == root_key

    // 6. Root NFT must be the only asset minted under its policy.
    expect
      is_only_mint_under_policy(
        tx_mint,
        list_nft_policy_id,
        element_asset_name,
        1,
      )

    // 7. Produced root must not have a link.
    expect element_link == None

    // 8. Custom validation on Lovelace count and data of the produced root must
    //    pass.
    expect root_validator(element_lovelace, root_data)

    // Done.
    True
  }
}

/// Deinitialize an empty list.
pub fn deinit(
  inputs: List<Input>,
  tx_mint: Value,
  root_validator: fn(Input, Lovelace, Data) -> Bool,
) -> RootEval<Bool> {
  fn(list_nft_policy_id: PolicyId, root_key: RootKey) -> Bool {
    // 1. There must be exactly one input with the list's NFT.
    let
      element_input,
      element_lovelace,
      element_asset_name,
      element_data,
      element_link,
    <- validate_singular_authentic_input(inputs, list_nft_policy_id)

    // 2. Contained data must be `Root`.
    expect Root { data: root_data }: GenericElementData = element_data

    // 3. Root NFT must be the only asset burnt under its policy.
    expect
      is_only_mint_under_policy(
        tx_mint,
        list_nft_policy_id,
        element_asset_name,
        -1,
      )

    // 4. Custom validation on the root UTxO's contained `Data`, along with
    //    its Lovelace count must pass the provided validator.
    expect root_validator(element_input, element_lovelace, root_data)

    // 5. The authentication NFT must use the root key.
    expect element_asset_name == root_key

    // 6. Spent root must have no links/children.
    expect element_link == None

    // Done.
    True
  }
}

// ## Element Addition and Removal

/// The anchor element is inferred from `inputs` by requiring exactly one
/// authentic linked list element input. It is assumed the address from which the
/// anchor element comes from is the destination address for the new node.
///
/// The `additional_validations` argument provides you with 8 values:
/// 1. Input of the anchor element
/// 2. Change in Lovelace count from anchor input to continued anchor output
/// 3. If the anchor element is a node, its key (i.e. asset name without the
///    prefix) is provided
/// 4. Underlying data of the anchor element -- note that this can come from
///    either a `Root` or a `Node`
/// 5. Lovelace count of the new node UTxO
/// 6. Key (i.e. asset name without the prefix) of the new node
/// 7. Underlying data of the new node -- note that this is extracted from a
///    `Node`
/// 8. `Link` of the new node
pub fn insert_ascending(
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: fn(
    Input,
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
  ) ->
    Bool,
) -> ElementEval<Bool> {
  insert_ordered(
    Less,
    continued_anchor_element_output,
    new_node_output,
    inputs,
    tx_mint,
    additional_validations,
  )
}

/// This is exactly like [`insert_ascending`](#insert_ascending), with the
/// exception that the inserted key is expected to be less than the anchor's,
/// and greater than anchor's link (if any).
pub fn insert_descending(
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: fn(
    Input,
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
  ) ->
    Bool,
) -> ElementEval<Bool> {
  insert_ordered(
    Greater,
    continued_anchor_element_output,
    new_node_output,
    inputs,
    tx_mint,
    additional_validations,
  )
}

/// Append a new element at the very end of an unordered list. The anchor
/// element is inferred from `inputs` by requiring exactly one authentic linked
/// list element input. There is no comparison validation for the new key with
/// respect to the anchor element's, but the anchor must be terminal.
///
/// The `additional_validations` argument provides you with 7 values:
/// 1. Input of the anchor element
/// 2. Change in Lovelace count from anchor input to continued anchor output
/// 3. If the anchor element is a node, its key (i.e. asset name without the
///    prefix) is provided
/// 4. Underlying data of the anchor element -- note that this can come from
///    either a `Root` or a `Node`
/// 5. Lovelace count of the new node UTxO
/// 6. Key (i.e. asset name without the prefix) of the new node
/// 7. Underlying data of the new node -- note that this is extracted from a
///    `Node`
pub fn append_unordered(
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: fn(
    Input,
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Lovelace,
    NodeKey,
    NodeData,
  ) ->
    Bool,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    let
      anchor_element_input,
      anchor_element_lovelace_change,
      anchor_element_asset_name,
      anchor_element_data,
      anchor_element_link,
      new_node_lovelace,
      _new_node_asset_name,
      new_node_key,
      new_node_data,
      _new_node_link,
    <-
      common_insertion_validations(
        list_nft_policy_id,
        node_key_prefix,
        node_key_prefix_length,
        continued_anchor_element_output,
        new_node_output,
        inputs,
        tx_mint,
      )

    // 1. The input anchor element and new node must both be the last elements
    //    of the list (equality is already checked).
    expect anchor_element_link == None

    when anchor_element_data is {
      Root { data: root_data } -> {
        // 2a. Asset name of the anchor element must be identical to the
        //     constant `root_key`.
        expect anchor_element_asset_name == root_key

        // 3a. Custom validation against the spent anchor element and the new
        //     node must pass.
        expect
          additional_validations(
            anchor_element_input,
            anchor_element_lovelace_change,
            None,
            root_data,
            new_node_lovelace,
            new_node_key,
            new_node_data,
          )

        // Done.
        True
      }
      Node { data: anchor_node_data } -> {
        // 2b. The anchor node's asset name must start with the node key prefix.
        expect
          bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix

        // 3b. Custom validation against the spent anchor element and the new
        //     node must pass.
        expect
          additional_validations(
            anchor_element_input,
            anchor_element_lovelace_change,
            Some(
              bytearray.drop(anchor_element_asset_name, node_key_prefix_length),
            ),
            anchor_node_data,
            new_node_lovelace,
            new_node_key,
            new_node_data,
          )

        // Done.
        True
      }
    }
  }
}

/// Prepend a new element at the very start of an unordered list. The root
/// element is inferred from `inputs` by requiring exactly one authentic linked
/// list element input. There is no validation for the new key to be less than
/// or greater than the root element's potential link.
///
/// The `additional_validations` argument provides you with 7 values:
/// 1. Input of the root element
/// 2. Change in Lovelace count from root input to continued root output
/// 3. Underlying data of the root
/// 4. Lovelace count of the new node UTxO
/// 5. Key (i.e. asset name without the prefix) of the new node
/// 6. Underlying data of the new node -- note that this is extracted from a
///    `Node`
/// 7. `Link` of the new node
pub fn prepend_unordered(
  continued_root_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: fn(
    Input,
    LovelaceChange,
    RootData,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
  ) ->
    Bool,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    let
      root_element_input,
      root_lovelace_change,
      root_element_asset_name,
      root_element_data,
      _root_element_link,
      new_node_lovelace,
      _new_node_asset_name,
      new_node_key,
      new_node_data,
      new_node_link,
    <-
      common_insertion_validations(
        list_nft_policy_id,
        node_key_prefix,
        node_key_prefix_length,
        continued_root_element_output,
        new_node_output,
        inputs,
        tx_mint,
      )

    // 1. Anchor element's data must be `Root`.
    expect Root { data: root_data } = root_element_data

    // 2. Asset name of the root element must be identical to the constant
    //    `root_key`.
    expect root_element_asset_name == root_key

    // 3. Custom validation against the spent root element and the new node
    //    must pass.
    expect
      additional_validations(
        root_element_input,
        root_lovelace_change,
        root_data,
        new_node_lovelace,
        new_node_key,
        new_node_data,
        new_node_link,
      )

    // Done.
    True
  }
}

/// Remove a node. The anchor element is identified by its output reference, and
/// the anchor and removing node are inferred from the transaction inputs.
/// This operation assumes the list script/payment credential is dedicated to
/// list elements, so the transaction must not include unrelated inputs at the
/// same payment credential.
///
/// The `additional_validations` argument provides you with 9 values:
/// 1. Input of the anchor element
/// 2. Change in Lovelace count from anchor input to continued anchor output
/// 3. If the anchor element is a node, its key (i.e. asset name without the
///    prefix) is provided
/// 4. Underlying data of the anchor element -- note that this can come from
///    either a `Root` or a `Node`
/// 5. Input of the removing node
/// 6. Lovelace count of the removing node UTxO
/// 7. Key (i.e. asset name without the prefix) of the removing node
/// 8. Underlying data of the removing node
/// 9. `Link` of the removing node
pub fn remove(
  anchor_input_outref: OutputReference,
  continued_anchor_element_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: fn(
    Input,
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Input,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
  ) ->
    Bool,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    // 1. Inputs list must contain the anchor and removing node as authentic
    //    list inputs.
    let
      anchor_input,
      anchor_lovelace,
      anchor_asset_name,
      anchor_element_data,
      anchor_link,
      removing_node_input,
      removing_node_lovelace,
      removing_node_asset_name,
      removing_node_element_data,
      removing_node_link,
    <-
      validate_dual_authentic_inputs(
        anchor_input_outref,
        inputs,
        list_nft_policy_id,
      )

    // 2. Continued anchor output must be authentic.
    let
      cont_anchor_address,
      cont_anchor_lovelace,
      cont_anchor_asset_name,
      cont_anchor_element_data,
      cont_anchor_link,
      _cont_anchor_ref_script,
    <-
      authenticate_element_utxo_and_get_info(
        continued_anchor_element_output,
        list_nft_policy_id,
      )

    let anchor_element_lovelace_change = cont_anchor_lovelace - anchor_lovelace

    let removing_node_key =
      bytearray.drop(removing_node_asset_name, node_key_prefix_length)

    // 3. Anchor continuation must be proper and preserve the list structure.
    expect cont_anchor_address == anchor_input.output.address
    expect cont_anchor_asset_name == anchor_asset_name
    expect cont_anchor_element_data == anchor_element_data

    // 4. Removing element's `ElementData` must be `Node`.
    expect Node { data: removing_node_data } = removing_node_element_data

    // 5. The removing node's NFT must be the only asset burnt under its policy.
    expect
      is_only_mint_under_policy(
        tx_mint,
        list_nft_policy_id,
        removing_node_asset_name,
        -1,
      )

    // 6. Anchor element must point to the node being removed.
    expect anchor_link == Some(removing_node_key)

    // 7. Reproduced anchor element must point to what the removed node pointed
    //    to.
    expect cont_anchor_link == removing_node_link

    // 8. Removing node's asset name must start with the node key prefix.
    expect
      bytearray.take(removing_node_asset_name, node_key_prefix_length) == node_key_prefix

    when anchor_element_data is {
      Root { data: root_data } -> {
        // 9a. Asset name of the anchor element must be identical to the
        //     constant `root_key`.
        expect anchor_asset_name == root_key

        // 10a. Custom validation against the spent anchor element and the
        //      removing node must pass.
        expect
          additional_validations(
            anchor_input,
            anchor_element_lovelace_change,
            None,
            root_data,
            removing_node_input,
            removing_node_lovelace,
            removing_node_key,
            removing_node_data,
            removing_node_link,
          )

        // Done.
        True
      }
      Node { data: anchor_node_data } -> {
        // 9b. The anchor node's asset name must start with the node key prefix.
        expect
          bytearray.take(anchor_asset_name, node_key_prefix_length) == node_key_prefix

        // 10b. Custom validation against the spent anchor element and the
        //      removing node must pass.
        expect
          additional_validations(
            anchor_input,
            anchor_element_lovelace_change,
            Some(bytearray.drop(anchor_asset_name, node_key_prefix_length)),
            anchor_node_data,
            removing_node_input,
            removing_node_lovelace,
            removing_node_key,
            removing_node_data,
            removing_node_link,
          )

        // Done.
        True
      }
    }
  }
}

// ## Fold Functions

/// Spend a root element and its link, reproduce the root while expecting the
/// linked node to be burnt. The root is identified by its output reference.
/// This traverses the whole `inputs` list and expects exactly two authentic
/// list inputs at the list payment credential: the root input and the folding
/// node input. This relies on the list spending validators preserving the
/// invariant that list NFTs do not leave their list script/payment credential,
/// and on the list script/payment credential being dedicated to list elements.
/// Unrelated inputs at the same payment credential are intentionally rejected.
/// Additionally, performs an arbitrary validation on keys and underlying data.
///
/// This function ensures:
/// - Authenticity of the two spent list inputs and root's continued counterpart
/// - The anchor is root, and that it correctly points to the folding node
/// - The root is continued at the same address
/// - The continued anchor data remains a `Root`
/// - The folding node shares the root's payment credential
/// - Folding node is burnt
/// - Root's key is correct, and node's key is prefixed as expected
///
/// The function you define for `additional_validations` is provided with 9
/// values (in order):
/// 1. Input of the root element
/// 2. Change in Lovelace count from input root to output
/// 3. Underlying data of the root
/// 4. Input of the folding node
/// 5. Lovelace count of the folding node
/// 6. Key (i.e. asset name without the prefix) of the folding node
/// 7. Underlying data of the folding node
/// 8. `Link` of the folding node
/// 9. Underlying data of the reproduced/continued root
pub fn fold_from_root(
  anchor_root_input_outref: OutputReference,
  continued_anchor_root_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: fn(
    Input,
    LovelaceChange,
    RootData,
    Input,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
    RootData,
  ) ->
    Bool,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    let
      anchor_root_input,
      anchor_root_lovelace,
      anchor_root_asset_name,
      anchor_root_element_data,
      anchor_root_link,
      folding_node_input,
      folding_node_lovelace,
      folding_node_asset_name,
      folding_node_element_data,
      folding_node_link,
    <-
      validate_dual_authentic_inputs(
        anchor_root_input_outref,
        inputs,
        list_nft_policy_id,
      )

    // 1. The anchor element must be a `Root`.
    expect Root { data: anchor_root_data }: GenericElementData =
      anchor_root_element_data

    let
      cont_anchor_root_address,
      cont_anchor_root_lovelace,
      cont_anchor_root_asset_name,
      cont_anchor_root_element_data,
      cont_anchor_root_link,
      _cont_anchor_root_ref_script,
    <-
      authenticate_element_utxo_and_get_info(
        continued_anchor_root_output,
        list_nft_policy_id,
      )

    let folding_node_key =
      folding_node_asset_name |> bytearray.drop(node_key_prefix_length)

    // 2. The folding element must be a `Node`.
    expect Node { data: folding_node_data }: GenericElementData =
      folding_node_element_data

    // 3. Continued anchor data must remain a `Root`.
    expect Root { data: cont_anchor_root_data }: GenericElementData =
      cont_anchor_root_element_data

    // 4. Folding node's NFT must be the only asset burnt under its policy.
    expect
      is_only_mint_under_policy(
        tx_mint,
        list_nft_policy_id,
        folding_node_asset_name,
        -1,
      )

    // 5. Anchor root is reproduced properly.
    expect anchor_root_input.output.address == cont_anchor_root_address
    expect anchor_root_asset_name == cont_anchor_root_asset_name

    // 6. Folding node is the anchor root's link.
    expect anchor_root_link == Some(folding_node_key)

    // 7. Reproduced root points to what the folding node pointed to.
    expect cont_anchor_root_link == folding_node_link

    // 8. Asset name of the anchor root must match the `root_key`.
    expect anchor_root_asset_name == root_key

    // 9. Folding node's asset name must start with the node key prefix.
    expect
      bytearray.take(folding_node_asset_name, node_key_prefix_length) == node_key_prefix

    // 10. Custom validation passes.
    expect
      additional_validations(
        anchor_root_input,
        cont_anchor_root_lovelace - anchor_root_lovelace,
        anchor_root_data,
        folding_node_input,
        folding_node_lovelace,
        folding_node_key,
        folding_node_data,
        folding_node_link,
        cont_anchor_root_data,
      )

    // Done.
    True
  }
}

// ## Spending Script Helpers

/// Simply checks if there are any tokens getting minted/burnt in transaction's
/// `mint` field. How you provide `list_nft_policy_id` is most likely the
/// "coupling" needed between the spending and minting endpoints.
pub fn spend_for_adding_or_removing_an_element(
  list_nft_policy_id: PolicyId,
  tx_mint: Value,
) -> Bool {
  !(assets.tokens(tx_mint, list_nft_policy_id) |> dict.is_empty)
}

/// For spending an individual element within a linked list and reproducing it
/// with updated data, without affecting the structure of the linked list.
///
/// The continuation provides you with:
/// 1. Change in Lovelace count from input to output (i.e. output minus input).
/// 2. A possible node key (i.e. its asset name without the prefix). It'll be
///    `None` if the spent element is root.
/// 3. Input underlying data.
/// 4. Updated data in the reproduced element.
/// 5. Element's link.
///
/// The transaction's mint is required to ensure no linked list assets are minted
/// or burnt.
pub fn spend_for_updating_elements_data(
  element_input_index: Int,
  continued_element_output_index: Int,
  element_input_outref: OutputReference,
  inputs: List<Input>,
  outputs: List<Output>,
  tx_mint: Value,
  additional_validations: fn(LovelaceChange, Option<NodeKey>, Data, Data, Link) ->
    Bool,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    let
      element_input,
      continued_element_output,
    <-
      singular_utxo_indexer.one_to_one(
        element_input_index,
        continued_element_output_index,
        element_input_outref,
        inputs,
        outputs,
        // Preventing double satisfaction by ensuring no tokens are minted/burnt
        // with the same policy as the linked list's NFT.
        dict.is_empty(tx_mint |> assets.tokens(list_nft_policy_id)),
      )
    let
      elem_address,
      elem_lovelace,
      elem_asset_name,
      elem_data,
      elem_link,
      _elem_ref_script,
    <-
      authenticate_element_utxo_and_get_info(
        element_input.output,
        list_nft_policy_id,
      )
    let
      cont_elem_address,
      cont_elem_lovelace,
      cont_elem_asset_name,
      cont_elem_data,
      cont_elem_link,
      _cont_elem_ref_script,
    <-
      authenticate_element_utxo_and_get_info(
        continued_element_output,
        list_nft_policy_id,
      )
    expect and {
        // 1. Element must be reproduced at the same address.
        elem_address == cont_elem_address,
        // 2. Element must preserve its NFT.
        elem_asset_name == cont_elem_asset_name,
        // 3. Element's link must remain unchanged.
        elem_link == cont_elem_link,
      }
    let lovelace_change = cont_elem_lovelace - elem_lovelace
    when elem_data is {
      Root { data } -> {
        // 4a. Element's data must remain as `Root`.
        expect Root { data: continued_data } = cont_elem_data
        and {
          // 5a. Root key must match properly.
          elem_asset_name == root_key,
          // 6a. User's custom validation must pass.
          additional_validations(
            lovelace_change,
            None,
            data,
            continued_data,
            elem_link,
          ),
        }
      }
      Node { data } -> {
        // 4b. Element's data must remain as `Node`.
        expect Node { data: continued_data } = cont_elem_data
        and {
          // 5b. Element's key prefix must match properly.
          bytearray.take(elem_asset_name, node_key_prefix_length) == node_key_prefix,
          // 6b. User's custom validation must pass.
          additional_validations(
            lovelace_change,
            Some(bytearray.drop(elem_asset_name, node_key_prefix_length)),
            data,
            continued_data,
            elem_link,
          ),
        }
      }
    }
  }
}

// ## Exposed Helpers

/// Type alias for the continuation function passed to
/// [`get_element_info`](#get_element_info).
pub type ElementInfo<a> =
  fn(Lovelace, Option<NodeKey>, Data, Link) -> a

/// Type alias for the continuation function passed to
/// [`get_root_element_info`](#get_root_element_info).
pub type RootElementInfo<a> =
  fn(Lovelace, RootData, Link) -> a

/// Type alias for the continuation function passed to
/// [`get_node_element_info`](#get_node_element_info).
pub type NodeElementInfo<a> =
  fn(Lovelace, NodeKey, NodeData, Link) -> a

/// This should generally not be needed, but in cases where another script wants
/// to validate expenditure from the linked list, this function can help.
///
/// After validating the authenticity of the provided element UTxO, it provides
/// the continuation with:
/// 1. Lovelace count of the element
/// 2. A possible `NodeKey` (i.e. it will be `None` if the element UTxO is root)
/// 3. Underlying data of the element
/// 4. Element's link
///
/// This returns an `ElementEval<a>` because the provided UTxO can be either a
/// root or node element. The type variable `a` allows the final evaluation to
/// result in any type rather than being restricted to `Bool`.
pub fn get_element_info(
  element_utxo: Output,
  info_validations: ElementInfo<a>,
) -> ElementEval<a> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> a {
    let
      _element_address,
      element_lovelace,
      element_asset_name,
      element_data,
      element_link,
      _element_ref_script,
    <- authenticate_element_utxo_and_get_info(element_utxo, list_nft_policy_id)

    when element_data is {
      Root { data: root_data } -> {
        expect element_asset_name == root_key
        info_validations(element_lovelace, None, root_data, element_link)
      }
      Node { data: node_data } -> {
        expect
          bytearray.take(element_asset_name, node_key_prefix_length) == node_key_prefix
        info_validations(
          element_lovelace,
          Some(bytearray.drop(element_asset_name, node_key_prefix_length)),
          node_data,
          element_link,
        )
      }
    }
  }
}

/// Like [`get_element_info`](#get_element_info), but requires the provided UTxO
/// to be the root element. This returns a `RootEval<a>` because it doesn't need
/// node namespace constants.
pub fn get_root_element_info(
  element_utxo: Output,
  info_validations: RootElementInfo<a>,
) -> RootEval<a> {
  fn(list_nft_policy_id: PolicyId, root_key: RootKey) -> a {
    let
      _element_address,
      element_lovelace,
      element_asset_name,
      element_data,
      element_link,
      _element_ref_script,
    <- authenticate_element_utxo_and_get_info(element_utxo, list_nft_policy_id)

    expect element_asset_name == root_key
    expect Root { data: root_data } = element_data

    info_validations(element_lovelace, root_data, element_link)
  }
}

/// Like [`get_element_info`](#get_element_info), but requires the provided UTxO
/// to be a node element. This returns a `NodeEval<a>` because it doesn't need
/// the root asset name.
pub fn get_node_element_info(
  element_utxo: Output,
  info_validations: NodeElementInfo<a>,
) -> NodeEval<a> {
  fn(
    list_nft_policy_id: PolicyId,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> a {
    let
      _element_address,
      element_lovelace,
      element_asset_name,
      element_data,
      element_link,
      _element_ref_script,
    <- authenticate_element_utxo_and_get_info(element_utxo, list_nft_policy_id)

    expect
      bytearray.take(element_asset_name, node_key_prefix_length) == node_key_prefix
    let node_key = bytearray.drop(element_asset_name, node_key_prefix_length)
    expect Node { data: node_data } = element_data

    info_validations(element_lovelace, node_key, node_data, element_link)
  }
}

// ## Internal Helpers

/// In addition to the validations performed by `authenticate_element_utxo_and_get_info_helper`,
/// this function validates the datum is an `Element`.
///
/// The callback is provided with relevant info of the UTxO:
/// - Its address
/// - Its Lovelace count
/// - Its NFT's asset name (i.e. element's key)
/// - Its underlying data
/// - Its link
/// - Its reference script (if any)
pub fn authenticate_element_utxo_and_get_info(
  element_utxo: Output,
  nft_policy_id: PolicyId,
  return: fn(
    Address,
    Lovelace,
    AssetName,
    GenericElementData,
    Link,
    Option<ScriptHash>,
  ) ->
    result,
) -> result {
  let
    output_address,
    lovelace_count,
    nft_name,
    utxo_datum_data,
    utxo_ref_script,
  <- authenticate_element_utxo_and_get_info_helper(element_utxo, nft_policy_id)

  // 1. UTxO's datum must be properly structured.
  expect Element { data, link }: GenericElement = utxo_datum_data

  return(output_address, lovelace_count, nft_name, data, link, utxo_ref_script)
}

pub fn validate_singular_authentic_input(
  inputs: List<Input>,
  nft_policy_id: PolicyId,
  return: fn(Input, Lovelace, AssetName, GenericElementData, Link) -> Bool,
) -> Bool {
  validate_singular_authentic_input_helper(
    inputs,
    nft_policy_id,
    fn(element_input, element_lovelace, element_asset_name, element_datum_data) {
      expect Element { data, link }: GenericElement = element_datum_data
      return(element_input, element_lovelace, element_asset_name, data, link)
    },
  )
}

pub fn validate_dual_authentic_inputs(
  anchor_input_outref: OutputReference,
  inputs: List<Input>,
  nft_policy_id: PolicyId,
  with: fn(
    Input,
    Lovelace,
    AssetName,
    GenericElementData,
    Link,
    Input,
    Lovelace,
    AssetName,
    GenericElementData,
    Link,
  ) ->
    Bool,
) -> Bool {
  validate_dual_authentic_inputs_helper(
    anchor_input_outref,
    inputs,
    nft_policy_id,
    fn(
      anchor_input,
      anchor_lovelace,
      anchor_asset_name,
      anchor_datum_data,
      removing_node_input,
      removing_node_lovelace,
      removing_node_asset_name,
      removing_node_datum_data,
    ) {
      expect Element { data: anchor_data, link: anchor_link }: GenericElement =
        anchor_datum_data
      expect Element { data: removing_node_data, link: removing_node_link }: GenericElement =
        removing_node_datum_data

      with(
        anchor_input,
        anchor_lovelace,
        anchor_asset_name,
        anchor_data,
        anchor_link,
        removing_node_input,
        removing_node_lovelace,
        removing_node_asset_name,
        removing_node_data,
        removing_node_link,
      )
    },
  )
}

/// Use `Less` for ascending and `Greater` for descending for the value of
/// `ordering_of_new_key_vs_anchors_link`.
fn insert_ordered(
  ordering_of_new_key_vs_anchors_link: Ordering,
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: fn(
    Input,
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
  ) ->
    Bool,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    let
      anchor_element_input,
      anchor_element_lovelace_change,
      anchor_element_asset_name,
      anchor_element_data,
      anchor_element_link,
      new_node_lovelace,
      new_node_asset_name,
      new_node_key,
      new_node_data,
      new_node_link,
    <-
      common_insertion_validations(
        list_nft_policy_id,
        node_key_prefix,
        node_key_prefix_length,
        continued_anchor_element_output,
        new_node_output,
        inputs,
        tx_mint,
      )

    when anchor_element_data is {
      Root { data: root_data } -> {
        // 1a. Asset name of the anchor element must be identical to the
        //     constant `root_key`.
        expect anchor_element_asset_name == root_key

        // 2a. If the root is already pointing to a first node, the new node
        //     must have a key such that it is less (or greater for descending)
        //     than the previous link's.
        expect
          when anchor_element_link is {
            None -> True
            Some(anchor_element_link_key) ->
              bytearray.compare(new_node_key, anchor_element_link_key) == ordering_of_new_key_vs_anchors_link
          }

        // 3a. Custom validation against the spent anchor element and the new
        //     node must pass.
        expect
          additional_validations(
            anchor_element_input,
            anchor_element_lovelace_change,
            None,
            root_data,
            new_node_lovelace,
            new_node_key,
            new_node_data,
            new_node_link,
          )

        // Done.
        True
      }
      Node { data: anchor_node_data } -> {
        // 1b. The anchor node's asset name must start with the node key prefix.
        expect
          bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix

        // 2b. The new node must have a key that is greater (or less for
        //     descending) than the anchor node's.
        // 3b. If the anchor node is already pointing to a link, the new node's
        //     key must be ordered before that link.
        expect
          when anchor_element_link is {
            None ->
              bytearray.compare(anchor_element_asset_name, new_node_asset_name) == ordering_of_new_key_vs_anchors_link
            Some(anchor_element_link_key) -> and {
                bytearray.compare(
                  anchor_element_asset_name,
                  new_node_asset_name,
                ) == ordering_of_new_key_vs_anchors_link,
                bytearray.compare(new_node_key, anchor_element_link_key) == ordering_of_new_key_vs_anchors_link,
              }
          }

        // 4b. Custom validation against the spent anchor element and the new
        //     node must pass.
        expect
          additional_validations(
            anchor_element_input,
            anchor_element_lovelace_change,
            Some(
              bytearray.drop(anchor_element_asset_name, node_key_prefix_length),
            ),
            anchor_node_data,
            new_node_lovelace,
            new_node_key,
            new_node_data,
            new_node_link,
          )

        // Done.
        True
      }
    }
  }
}

fn common_insertion_validations(
  list_nft_policy_id: PolicyId,
  node_key_prefix: NodeKeyPrefix,
  node_key_prefix_length: NodeKeyPrefixLength,
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  callback: fn(
    Input,
    LovelaceChange,
    AssetName,
    GenericElementData,
    Link,
    Lovelace,
    AssetName,
    NodeKey,
    NodeData,
    Link,
  ) ->
    Bool,
) -> Bool {
  // 1. Inputs list must carry exactly one UTxO with the list NFT.
  let
    anchor_element_input,
    anchor_element_lovelace,
    anchor_element_asset_name,
    anchor_element_data,
    anchor_element_link,
  <- validate_singular_authentic_input(inputs, list_nft_policy_id)

  let anchor_element_address = anchor_element_input.output.address

  // 2. Provided output for the continued anchor must be authentic.
  let
    cont_anchor_element_address,
    cont_anchor_element_lovelace,
    cont_anchor_element_asset_name,
    cont_anchor_element_data,
    cont_anchor_element_link,
    _cont_anchor_element_ref_script,
  <-
    authenticate_element_utxo_and_get_info(
      continued_anchor_element_output,
      list_nft_policy_id,
    )

  // 3. Provided output for the new node must be authentic.
  let
    new_node_address,
    new_node_lovelace,
    new_node_asset_name,
    new_node_element_data,
    new_node_link,
    _new_node_ref_script,
  <- authenticate_element_utxo_and_get_info(new_node_output, list_nft_policy_id)

  // 4. Anchor element must be continued at the same address.
  expect anchor_element_address == cont_anchor_element_address

  // 5. Inserted node must share payment credential with the anchor element.
  expect
    anchor_element_address.payment_credential == new_node_address.payment_credential

  // 6. Anchor element's NFT must be preserved.
  expect anchor_element_asset_name == cont_anchor_element_asset_name

  // 7. Underlying data of anchor element must not change.
  expect anchor_element_data == cont_anchor_element_data

  let anchor_element_lovelace_change =
    cont_anchor_element_lovelace - anchor_element_lovelace

  let new_node_key = bytearray.drop(new_node_asset_name, node_key_prefix_length)

  // 8. New node's NFT must be the only asset minted under its policy.
  expect
    is_only_mint_under_policy(
      tx_mint,
      list_nft_policy_id,
      new_node_asset_name,
      1,
    )

  // 9. Reproduced anchor element must point to the new node.
  expect cont_anchor_element_link == Some(new_node_key)

  // 10. The new element must point to what the anchor element used to link to.
  expect new_node_link == anchor_element_link

  // 11. The new node's asset name must start with the node key prefix.
  expect
    bytearray.take(new_node_asset_name, node_key_prefix_length) == node_key_prefix

  // 12. New node's `ElementData` must be `Node`.
  expect Node { data: new_node_data } = new_node_element_data

  // 13. Further validations must pass.
  callback(
    anchor_element_input,
    anchor_element_lovelace_change,
    anchor_element_asset_name,
    anchor_element_data,
    anchor_element_link,
    new_node_lovelace,
    new_node_asset_name,
    new_node_key,
    new_node_data,
    new_node_link,
  )
}
