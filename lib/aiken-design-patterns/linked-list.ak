//// Storing lists in datums is generally impractical, as its growth can lead to
//// unspendable UTxOs due to limited resources available on-chain.
////
//// A linked list is a construct for storing an infinitely large array of
//// elements on-chain, such that each element is represented with a UTxO that
//// points to its immediate successor.
////
//// The presumption throughout is that the datum of the spending contract which
//// holds the linked list UTxOs is of type `Element<a, b>`. So the recommended
//// approach is to define your datum as its applied alias:
//// ```aiken
//// pub type Datum = linked_list.Element<RootType, NodeType>
//// ```
////
//// There are two opinionated designs that should be highlighted:
//// 1. The elements are required to have no scripts attached to them. The
////    continuations are already provided with too many values. Providing their
////    reference script fields would overwhelm the API even further. So far
////    this doesn't seem to be a needed feature.
//// 2. While continued anchor nodes are validated to go to the same
////    **address**, for new/removed nodes only the payment parts are validated
////    to match the anchors'. This allows customization of staking parts of new
////    nodes, while preserving the staking parts of existing elements.

use aiken/collection/dict
use aiken/option
use aiken/primitive/bytearray
use aiken_design_patterns/singular_utxo_indexer
use cardano/address.{Address}
use cardano/assets.{AssetName, Lovelace, PolicyId, Value}
use cardano/transaction.{InlineDatum, Input, Output, OutputReference}

/// An alias for the asset name of the NFT held in the root element. This can be
/// zero bytes or more (32 bytes at most).
///
/// > [!NOTE]
/// > Keep in mind that some UTF-8 characters occupy more than 1 byte. For
/// > example the tree emoji (🌳) takes up 4 bytes.
pub type RootKey =
  AssetName

/// Alias for representing the keys of linked list nodes. This must be at least
/// one byte long, and contracts should implement validations on them depending
/// on their needs.
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
/// root).
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
) -> RootEval {
  // 1. Helper guardrail to remind nonce validation logic.
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
    <-
      authenticate_element_utxo_and_get_info(
        produced_element_output,
        list_nft_policy_id,
      )

    // 4. Contained data must be `Root`.
    expect Root { data: root_data }: GenericElementData = element_data

    and {
      // 5. The authentication NFT must have the root's hardcoded name.
      element_asset_name == root_key,
      // 6. Root NFT must be the only asset minted under its policy.
      is_only_mint_under_policy(
        tx_mint,
        list_nft_policy_id,
        element_asset_name,
        1,
      ),
      // 7. Custom validation on Lovelace count and data of the produced root
      //    must pass.
      root_validator(element_lovelace, root_data),
      // 8. Produced root must not have a link.
      element_link == None,
    }
  }
}

/// Deinitialize an empty list.
pub fn deinit(
  root_input: Input,
  tx_mint: Value,
  root_validator: fn(Lovelace, Data) -> Bool,
) -> RootEval {
  fn(list_nft_policy_id: PolicyId, root_key: RootKey) -> Bool {
    // 1. The spent UTxO must only contain the authentication/key NFT.
    // 2. Its datum must be properly structured.
    let
      _element_address,
      element_lovelace,
      element_asset_name,
      element_data,
      element_link,
    <-
      authenticate_element_utxo_and_get_info(
        root_input.output,
        list_nft_policy_id,
      )

    // 3. Contained data must be `Root`.
    expect Root { data: root_data }: GenericElementData = element_data

    and {
      // 4. Root NFT must be the only asset burnt under its policy.
      is_only_mint_under_policy(
        tx_mint,
        list_nft_policy_id,
        element_asset_name,
        -1,
      ),
      // 5. Custom validation on the root UTxO's contained `Data`, along with
      //    its Lovelace count must pass the provided validator.
      root_validator(element_lovelace, root_data),
      // 6. The authentication NFT must have the root's hardcoded name.
      element_asset_name == root_key,
      // 7. Spent root must have no links/children.
      element_link == None,
    }
  }
}

// ## Element Addition and Removal

/// It is assumed the address from which the anchor element comes from is the
/// destination address for the new node.
///
/// The `additional_validations` argument provides you with 7 values:
/// 1. Change in Lovelace count from anchor input to continued anchor output
/// 2. If the anchor element is a node, its key (i.e. asset name without the
///    prefix) is provided
/// 3. Underlying data of the anchor element -- note that this can come from
///    either a `Root` or a `Node`
/// 4. Lovelace count of the new node UTxO
/// 5. Key (i.e. asset name without the prefix) of the new node
/// 6. Underlying data of the new node -- note that this is extracted from a
///    `Node`
/// 7. `Link` of the new node
pub fn insert_ascending(
  anchor_element_input: Input,
  continued_anchor_element_output: Output,
  new_element_output: Output,
  tx_mint: Value,
  additional_validations: fn(
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
  ) ->
    Bool,
) -> Eval {
  insert_ordered(
    Less,
    anchor_element_input,
    continued_anchor_element_output,
    new_element_output,
    tx_mint,
    additional_validations,
  )
}

/// This is exactly like [`insert_ascending`](#insert_ascending), with the
/// exception that the inserted key is expected to be less than the anchor's,
/// and greater than anchor's link (if any).
pub fn insert_descending(
  anchor_element_input: Input,
  continued_anchor_element_output: Output,
  new_element_output: Output,
  tx_mint: Value,
  additional_validations: fn(
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
  ) ->
    Bool,
) -> Eval {
  insert_ordered(
    Greater,
    anchor_element_input,
    continued_anchor_element_output,
    new_element_output,
    tx_mint,
    additional_validations,
  )
}

/// Use `Less` for ascending and `Greater` for descending for the value of
/// `ordering_of_new_key_vs_anchors_link`.
fn insert_ordered(
  ordering_of_new_key_vs_anchors_link: Ordering,
  anchor_element_input: Input,
  continued_anchor_element_output: Output,
  new_element_output: Output,
  tx_mint: Value,
  additional_validations: fn(
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
  ) ->
    Bool,
) -> Eval {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    let Input { output: anchor_element_input_utxo, .. } = anchor_element_input

    // 1. Each of the 3 element UTxOs must only contain single authentication
    //    NFTs.
    // 2. All their datums must be properly structured (i.e. `Element`).
    let
      anchor_element_asset_name,
      anchor_element_data,
      anchor_element_link,
      anchor_element_lovelace_change,
      cont_anchor_element_link,
      new_element_lovelace,
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

    let new_element_key =
      bytearray.drop(new_element_asset_name, node_key_prefix_length)

    // 3. New element's data must be `Node`.
    expect Node { data: new_node_data } = new_element_data

    expect and {
        // 4. New node's NFT must be the only asset minted under its policy.
        is_only_mint_under_policy(
          tx_mint,
          list_nft_policy_id,
          new_element_asset_name,
          1,
        ),
        // 5. Reproduced anchor element must point to the new node.
        cont_anchor_element_link == Some(new_element_key),
        // 6. The new element must point to what the anchor element used to link
        //    to.
        new_element_link == anchor_element_link,
        // 7. The new node's asset name must start with the provided label.
        bytearray.take(new_element_asset_name, node_key_prefix_length) == node_key_prefix,
      }

    when anchor_element_data is {
      Root { data: root_data } -> and {
          // 8a. Token name of the anchor element must be identical to the
          //     constant `root_key`.
          anchor_element_asset_name == root_key,
          // 9a. If the root is already pointing to a firs node, the new node
          //     must have a key such that it is less (or greater for
          //     descending) than the previous link's.
          when anchor_element_link is {
            None -> True
            Some(anchor_element_link_key) ->
              bytearray.compare(new_element_key, anchor_element_link_key) == ordering_of_new_key_vs_anchors_link
          },
          // 10a. Custom validation against the spent anchor element and the new
          //      node must pass.
          additional_validations(
            anchor_element_lovelace_change,
            None,
            root_data,
            new_element_lovelace,
            new_element_key,
            new_node_data,
            new_element_link,
          ),
        }
      Node { data: anchor_node_data } -> and {
          // 8b. The anchor node's key must start with the provided label.
          bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix,
          // 9b. The new node must have a key that is greater (or less for
          //     descending) than the anchor node's.
          // 10b. If the anchor node is already pointing to a link, the new
          //      node's key (i.e. asset name) must be less than this link's.
          when anchor_element_link is {
            None ->
              bytearray.compare(
                anchor_element_asset_name,
                new_element_asset_name,
              ) == ordering_of_new_key_vs_anchors_link
            Some(anchor_element_link_key) -> and {
                bytearray.compare(
                  anchor_element_asset_name,
                  new_element_asset_name,
                ) == ordering_of_new_key_vs_anchors_link,
                bytearray.compare(new_element_key, anchor_element_link_key) == ordering_of_new_key_vs_anchors_link,
              }
          },
          // 11b. Custom validation against the spent anchor element and the new
          //      node must pass.
          additional_validations(
            anchor_element_lovelace_change,
            Some(
              bytearray.drop(anchor_element_asset_name, node_key_prefix_length),
            ),
            anchor_node_data,
            new_element_lovelace,
            new_element_key,
            new_node_data,
            new_element_link,
          ),
        }
    }
  }
}

/// Append a new element at the very end of an unordered list. There is no
/// validation for the new key to be greater than the anchor element's.
///
/// `additional_validations` takes the same arguments as
/// [`insert_ascending`](#insert_ascending).
pub fn append_unordered(
  anchor_element_input: Input,
  continued_anchor_element_output: Output,
  new_element_output: Output,
  tx_mint: Value,
  additional_validations: fn(
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Lovelace,
    NodeKey,
    NodeData,
  ) ->
    Bool,
) -> Eval {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    let Input { output: anchor_element_input_utxo, .. } = anchor_element_input

    // 1. Each of the 3 element UTxOs must only contain single authentication
    //    NFTs.
    // 2. All their datums must be properly structured (i.e. `Element`).
    let
      anchor_element_asset_name,
      anchor_element_data,
      anchor_element_link,
      anchor_element_lovelace_change,
      cont_anchor_element_link,
      new_element_lovelace,
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

    let new_element_key =
      bytearray.drop(new_element_asset_name, node_key_prefix_length)

    // 3. New element's data must be `Node`.
    expect Node { data: new_node_data } = new_element_data

    expect and {
        // 4. New node's NFT must be the only asset minted under its policy.
        is_only_mint_under_policy(
          tx_mint,
          list_nft_policy_id,
          new_element_asset_name,
          1,
        ),
        // 5. Anchor element must be the last element of the list.
        anchor_element_link == None,
        // 6. Reproduced anchor element must point to the new node.
        cont_anchor_element_link == Some(new_element_key),
        // 7. The new element must point to no other nodes.
        new_element_link == None,
        // 8. The new node's asset name must start with the provided label.
        bytearray.take(new_element_asset_name, node_key_prefix_length) == node_key_prefix,
      }

    when anchor_element_data is {
      Root { data: root_data } -> and {
          // 9a. Token name of the anchor element must be identical to the
          //     constant `root_key`.
          anchor_element_asset_name == root_key,
          // 10a. Custom validation against the spent anchor element and the new
          //      node must pass.
          additional_validations(
            anchor_element_lovelace_change,
            None,
            root_data,
            new_element_lovelace,
            new_element_key,
            new_node_data,
          ),
        }
      Node { data: anchor_node_data } -> and {
          // 9b. The anchor node's key must start with the provided label.
          bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix,
          // 10b. Custom validation against the spent anchor element and the new
          //      node must pass.
          additional_validations(
            anchor_element_lovelace_change,
            Some(
              bytearray.drop(anchor_element_asset_name, node_key_prefix_length),
            ),
            anchor_node_data,
            new_element_lovelace,
            new_element_key,
            new_node_data,
          ),
        }
    }
  }
}

/// Prepend a new element at the very start of an unordered list. There is no
/// validation for the new key to be less than the anchor/root element's
/// potential link.
///
/// `additional_validations` takes the same arguments as
/// [`insert_ascending`](#insert_ascending), without a possible element key, as the
/// anchor is required to be root, which is a value that is already accessible.
pub fn prepend_unordered(
  root_element_input: Input,
  continued_root_element_output: Output,
  new_element_output: Output,
  tx_mint: Value,
  additional_validations: fn(
    LovelaceChange,
    RootData,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
  ) ->
    Bool,
) -> Eval {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    let Input { output: root_element_input_utxo, .. } = root_element_input

    // 1. Each of the 3 element UTxOs must only contain single authentication
    //    NFTs.
    // 2. All their datums must be properly structured (i.e. `Element`).
    let
      root_element_asset_name,
      root_element_data,
      root_element_link,
      root_lovelace_change,
      cont_root_element_link,
      new_element_lovelace,
      new_element_asset_name,
      new_element_data,
      new_element_link,
    <-
      validate_three_elements(
        list_nft_policy_id,
        root_element_input_utxo,
        continued_root_element_output,
        new_element_output,
      )

    let new_element_key =
      bytearray.drop(new_element_asset_name, node_key_prefix_length)

    // 3. Anchor element's data must be `Root`.
    expect Root { data: root_data } = root_element_data

    // 4. New element's data must be `Node`.
    expect Node { data: new_node_data } = new_element_data

    and {
      // 5. New node's NFT must be the only asset minted under its policy.
      is_only_mint_under_policy(
        tx_mint,
        list_nft_policy_id,
        new_element_asset_name,
        1,
      ),
      // 6. Reproduced root element must point to the new node.
      cont_root_element_link == Some(new_element_key),
      // 7. The new node must point to root's link.
      new_element_link == root_element_link,
      // 8. The new node's asset name must start with the provided label.
      bytearray.take(new_element_asset_name, node_key_prefix_length) == node_key_prefix,
      // 9. Asset name of the root element must be identical to the constant
      //    `root_key`.
      root_element_asset_name == root_key,
      // 10. Custom validation against the spent root element and the new node
      //     must pass.
      additional_validations(
        root_lovelace_change,
        root_data,
        new_element_lovelace,
        new_element_key,
        new_node_data,
        new_element_link,
      ),
    }
  }
}

/// Remove a node. It expects two spent UTxOs: the node subject to removal, and
/// its previous element (i.e. anchor element).
///
/// `additional_validations` takes the same arguments as
/// [`insert_ascending`](#insert_ascending), the difference being last `NodeKey` and
/// `NodeData` are from the removing node.
pub fn remove(
  anchor_element_input: Input,
  removing_node_input: Input,
  continued_anchor_element_output: Output,
  tx_mint: Value,
  additional_validations: fn(
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
  ) ->
    Bool,
) -> Eval {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    let Input { output: anchor_element_input_utxo, .. } = anchor_element_input
    let Input { output: removing_node_input_utxo, .. } = removing_node_input

    // 1. Each of the 3 element UTxOs must only contain single authentication
    //    NFTs.
    // 2. All their datums must be properly structured (i.e. `Element`).
    let
      anchor_element_asset_name,
      anchor_element_data,
      anchor_element_link,
      anchor_element_lovelace_change,
      cont_anchor_element_link,
      removing_node_lovelace,
      removing_node_asset_name,
      removing_node_data,
      removing_node_link,
    <-
      validate_three_elements(
        list_nft_policy_id,
        anchor_element_input_utxo,
        continued_anchor_element_output,
        removing_node_input_utxo,
      )

    let removing_node_key =
      bytearray.drop(removing_node_asset_name, node_key_prefix_length)

    // 3. Removing element's data must be `Node`.
    expect Node { data: removing_node_data } = removing_node_data

    expect and {
        // 4. The removing node's NFT must be the only asset burnt under its
        //    policy.
        is_only_mint_under_policy(
          tx_mint,
          list_nft_policy_id,
          removing_node_asset_name,
          -1,
        ),
        // 5. Anchor element must point to the node being removed.
        anchor_element_link == Some(removing_node_key),
        // 6. Reproduced anchor element must point to what the removed node
        //    pointed to.
        cont_anchor_element_link == removing_node_link,
        // 7. Asset name of the removing node must have the expected label.
        bytearray.take(removing_node_asset_name, node_key_prefix_length) == node_key_prefix,
      }

    when anchor_element_data is {
      Root { data: root_data } -> and {
          // 8a. Token name of the anchor element must be identical to the
          //     constant `root_key`.
          anchor_element_asset_name == root_key,
          // 9a. The new node's asset name must start with the provided label.
          additional_validations(
            anchor_element_lovelace_change,
            None,
            root_data,
            removing_node_lovelace,
            removing_node_key,
            removing_node_data,
            removing_node_link,
          ),
        }
      Node { data: anchor_node_data } -> and {
          // 8b. The anchor node's key must start with the provided label.
          bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix,
          // 9b. Custom validation against the spent anchor element and the
          //     removing node must pass.
          additional_validations(
            anchor_element_lovelace_change,
            Some(
              bytearray.drop(anchor_element_asset_name, node_key_prefix_length),
            ),
            anchor_node_data,
            removing_node_lovelace,
            removing_node_key,
            removing_node_data,
            removing_node_link,
          ),
        }
    }
  }
}

// ## Fold Functions

/// Spend a root element and its link, reproduce the root while expecting the
/// node to be burnt. Additionally, performs an arbitrary validation on keys and
/// underlying data.
///
/// This function ensures:
/// - Authenticity of the UTxOs and root's continued counterpart
/// - The anchor is root, and that it correctly points to the folding node
/// - The addresses are the same for all 3 UTxOs
/// - Folded node is burnt
/// - Root's key is correct, and node's key is prefixed as expected
///
/// The function you define for `additional_validations` is provided with 7
/// values (in order):
/// 1. Change in Lovelace count from input root to output
/// 2. Underlying data of the root
/// 3. Lovelace count of the folding node
/// 4. Key (i.e. asset name) of the folding node
/// 5. Underlying data of the folding node
/// 6. `Link` of the folding node
/// 7. Underlying data of the reproduced/continued root
pub fn fold_from_root(
  anchor_root_input: Input,
  folding_node_input: Input,
  continued_anchor_root_output: Output,
  tx_mint: Value,
  additional_validations: fn(
    LovelaceChange,
    RootData,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
    RootData,
  ) ->
    Bool,
) -> Eval {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    let
      anchor_root_address,
      anchor_root_lovelace,
      anchor_root_asset_name,
      anchor_root_data,
      anchor_root_link,
    <-
      authenticate_element_utxo_and_get_info(
        anchor_root_input.output,
        list_nft_policy_id,
      )

    // 1. The anchor element has to be a `Root`.
    expect Root { .. }: GenericElementData = anchor_root_data

    let
      cont_anchor_root_address,
      cont_anchor_root_lovelace,
      cont_anchor_root_asset_name,
      cont_anchor_root_data,
      cont_anchor_root_link,
    <-
      authenticate_element_utxo_and_get_info(
        continued_anchor_root_output,
        list_nft_policy_id,
      )
    let
      folding_node_address,
      folding_node_lovelace,
      folding_node_asset_name,
      folding_node_data,
      folding_node_link,
    <-
      authenticate_element_utxo_and_get_info(
        folding_node_input.output,
        list_nft_policy_id,
      )
    let folding_node_key =
      folding_node_asset_name |> bytearray.drop(node_key_prefix_length)

    // 2. The folding element has to be a `Node`.
    expect Node { .. }: GenericElementData = folding_node_data

    and {
      // 3. Folding node's NFT must be the only asset burnt under its policy.
      is_only_mint_under_policy(
        tx_mint,
        list_nft_policy_id,
        folding_node_asset_name,
        -1,
      ),
      // 4. Anchor root is reproduced properly.
      anchor_root_address == cont_anchor_root_address,
      anchor_root_asset_name == cont_anchor_root_asset_name,
      // 5. Folding node is the anchor root's link.
      anchor_root_link == Some(folding_node_key),
      // 6. Anchor root and folding node come from the same payment credential.
      anchor_root_address.payment_credential == folding_node_address.payment_credential,
      // 7. Reproduced anchor node points to the link folding node pointed to.
      cont_anchor_root_link == folding_node_link,
      // 8. Asset name of the anchor node must match the `root_key`.
      anchor_root_asset_name == root_key,
      // 9. Asset name of the folding node must have the expected label.
      bytearray.take(folding_node_asset_name, node_key_prefix_length) == node_key_prefix,
      // 10. Custom validation passes.
      additional_validations(
        cont_anchor_root_lovelace - anchor_root_lovelace,
        anchor_root_data,
        folding_node_lovelace,
        folding_node_key,
        folding_node_data,
        folding_node_link,
        cont_anchor_root_data,
      ),
    }
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
/// with an updated data, without affecting the structure of the linked list.
///
/// The continuation provides you with:
/// 1. Change in Lovelace count from input to output (i.e. output minus input).
/// 2. A possible node key (i.e. its asset name without the prefix). It'll be
///    `None` if the spent element is root.
/// 3. Input underlying data.
/// 4. Updated data in the reproduced element.
/// 5. Element's link.
///
/// The transaction's mint is required to ensure no link list assets are minted
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
) -> Eval {
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
        // 4b. Element's data must remain as `Root`.
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
/// Unlike other helpers, this one returns an `ElementEval<a>`. This is very
/// similar to [`Eval`](#eval). However, the type variable `a` allows the final
/// evaluation to result in any type rather than being restricted to `Bool`.
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
          element_link
            |> option.map(
                fn(asset_name: AssetName) -> ByteArray {
                  asset_name |> bytearray.drop(node_key_prefix_length)
                },
              ),
        )
      }
    }
  }
}

// ## Internal Helpers

/// Validates that the given asset is the **only** one being minted or burnt
/// under its policy, with the expected quantity. This prevents an attacker from
/// sneaking additional NFTs into a transaction alongside a legitimate operation.
fn is_only_mint_under_policy(
  tx_mint: Value,
  policy_id: PolicyId,
  asset_name: AssetName,
  expected_quantity: Int,
) -> Bool {
  expect Some(actual_minted_assets) =
    assets.to_dict(tx_mint) |> dict.get(policy_id)
  expect [Pair(actual_asset_name, actual_quantity)] =
    dict.to_pairs(actual_minted_assets)
  and {
    actual_asset_name == asset_name,
    actual_quantity == expected_quantity,
  }
}

type GenericElement =
  Element<Data, Data>

type GenericElementData =
  ElementData<Data, Data>

type InternalElementInfo<result> =
  fn(Address, Lovelace, AssetName, GenericElementData, Link) -> result

/// Given an element UTxO (`Output`), this function authenticates it by
/// checking:
/// 1. A properly structured inline datum (as an `Element`) is attached
/// 2. It contains only one NFT (apart from ADA) whose policy ID matches the
///    provided one, and its quantity equals one
///
/// Upon successful authentication, it returns the following information about
/// the element:
/// - Its address
/// - Its Lovelace count
/// - Its NFT's asset name (i.e. element's key)
/// - Its underlying data
/// - Its link
fn authenticate_element_utxo_and_get_info(
  element_utxo: Output,
  nft_policy_id: PolicyId,
  return: InternalElementInfo<result>,
) -> result {
  // 1. Its datum must be inlined, and no script must be attached to it.
  expect Output {
    address: output_address,
    value,
    datum: InlineDatum(utxo_datum_data),
    reference_script: None,
  } = element_utxo

  // 2. UTxO's datum must be properly structured.
  expect Element { data, link }: GenericElement = utxo_datum_data

  // 3. Apart from ADA, only one NFT must be included in the UTxO, such that its
  //    policy ID matched the provided one, and its quantity equals one.
  expect [(_, _, lovelace_count),
    (nft_symbol, nft_name, nft_qty)] = assets.flatten(value)
  expect and {
      nft_symbol == nft_policy_id,
      nft_qty == 1,
    }

  return(output_address, lovelace_count, nft_name, data, link)
}

type ThreeElementInfo =
  fn(
    AssetName,
    GenericElementData,
    Link,
    LovelaceChange,
    Link,
    Lovelace,
    AssetName,
    GenericElementData,
    Link,
  ) ->
    Bool

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
) -> Bool {
  let
    elem_0_address,
    elem_0_lovelace,
    elem_0_asset_name,
    elem_0_data,
    elem_0_link,
  <- authenticate_element_utxo_and_get_info(elem_0, nft_policy_id)
  let
    cont_elem_0_address,
    cont_elem_0_lovelace,
    cont_elem_0_asset_name,
    cont_elem_0_data,
    cont_elem_0_link,
  <- authenticate_element_utxo_and_get_info(cont_elem_0, nft_policy_id)
  let
    elem_1_address,
    elem_1_lovelace,
    elem_1_asset_name,
    elem_1_data,
    elem_1_link,
  <- authenticate_element_utxo_and_get_info(elem_1, nft_policy_id)
  expect and {
      // 1. Anchor element must be reproduced at the same address.
      elem_0_address == cont_elem_0_address,
      // 2. New/removed element must go to / come from the same address as the
      //    anchor element.
      elem_0_address.payment_credential == elem_1_address.payment_credential,
      // 3. Anchor element must preserve its NFT.
      elem_0_asset_name == cont_elem_0_asset_name,
      // 4. Underlying data of the anchor element must remain unchanged.
      elem_0_data == cont_elem_0_data,
    }
  let elem_0_lovelace_change = cont_elem_0_lovelace - elem_0_lovelace
  return(
    elem_0_asset_name,
    elem_0_data,
    elem_0_link,
    elem_0_lovelace_change,
    cont_elem_0_link,
    elem_1_lovelace,
    elem_1_asset_name,
    elem_1_data,
    elem_1_link,
  )
}
