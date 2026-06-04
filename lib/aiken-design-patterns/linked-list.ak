//// Storing lists directly in datums is generally impractical: as the datum
//// grows, the UTxO can become too expensive or even impossible to spend.
////
//// A linked list stores an unbounded collection as many UTxOs. Each list
//// element is one UTxO with:
//// - some ADA,
//// - exactly one list NFT,
//// - an inline `Element` datum,
//// - and a link to its immediate successor.
////
//// ## Usage Guideline
////
//// Contracts using this module should keep the list controlled by one
//// dedicated spend script/payment credential and one list NFT minting policy:
////
//// 1. Define the spend script datum as an applied alias of `Element<a, b>`:
//// ```aiken
//// pub type Datum = linked_list.Element<RootType, NodeType>
//// ```
//// 2. Ensure the UTxO produced by `init` goes to that spend script credential.
//// 3. Implement list spend scripts so structural spends only use
////    `spend_for_adding_or_removing_an_element`, and non-structural updates
////    use `spend_for_updating_elements_data`.
//// 4. Implement the list minting policy so structural mint/burn branches only
////    succeed through this module's matching mint helpers for the exact
////    init/insert/remove/fold/deinit shape. This spend/mint split is a
////    deliberate budget compromise: the spend-side gate is not a standalone
////    structural proof.
//// 5. Choose root and node NFT names so their namespaces are disjoint: use a
////    non-empty `node_key_prefix`, non-empty node keys, and a `root_key` that
////    does not begin with the node prefix.
////
//// These rules preserve the invariant that list NFTs cannot leave the list
//// spend script/payment credential.
////
//// The guideline above implies a few important design constraints:
////
//// 1. The default API does not expose or validate reference scripts on element
////    UTxOs. Use `linked_list/advanced` if reference scripts must be preserved
////    or inspected by callbacks.
//// 2. Continued anchors are checked by full address equality. Newly minted
////    nodes only need to share the anchor payment credential, which allows
////    callers to choose staking parts for new nodes. If a callback does not
////    receive a produced element address directly, the corresponding `Output`
////    is an argument the caller supplied to the helper and can be captured by
////    the callback.
//// 3. Every `Output` passed to a minting helper must be selected from the
////    script context transaction outputs. The helpers authenticate those
////    outputs as linked-list UTxOs, but they intentionally do not prove how the
////    caller selected them. Callers may use redeemer indexes, filtering,
////    `list.find`, or any other method, as long as the final `Output` value
////    comes from `ScriptContext.transaction.outputs` and is not redeemer data or
////    a locally constructed output.
//// 4. The default mint helpers do not allow extra mint/burn changes under the
////    list NFT policy. Use `linked_list/advanced` when structural operations
////    also need unrelated same-policy assets outside the reserved root key and
////    node-key namespace.
//// 5. List operations assume the list script/payment credential is dedicated
////    to linked-list elements. "Dedicated" means a transaction using these
////    helpers must not spend unrelated inputs from that payment credential at
////    all, even if those inputs do not carry the list NFT. The helpers are
////    allowed to fail fast under that invalid construction and do not try to
////    classify arbitrary same-credential inputs.
//// 6. Root and node asset-name namespaces must be fixed and disjoint for the
////    deployed list. This is a soft precondition for budget reasons, not an
////    on-chain proof repeated by every branch. Agents wiring a contract must
////    choose a non-empty node prefix, non-empty node keys, and a root key that
////    cannot equal `node_key_prefix ++ node_key`.

use aiken/collection/dict
use aiken/crypto.{ScriptHash}
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list/internal.{
  authenticate_element_utxo_and_get_info_helper, is_only_mint_under_policy,
  key_fits_between, validate_dual_authentic_inputs_helper,
  validate_singular_authentic_input_helper,
}
use aiken_design_patterns/singular_utxo_indexer
use cardano/address.{Address}
use cardano/assets.{AssetName, Lovelace, PolicyId, Value}
use cardano/transaction.{Input, Output, OutputReference}

/// Asset name of the NFT held by the root element. It may be empty and can be
/// no longer than 32 bytes.
///
/// Choose this outside the node namespace: it must not begin with
/// `NodeKeyPrefix`. The usual low-budget setup is an empty root key, a
/// non-empty node prefix, and non-empty node keys.
///
/// > [!NOTE]
/// > Some visible UTF-8 characters occupy more than one byte. For example, the
/// > tree emoji (🌳) takes up 4 bytes, so `"🌳"` is not a 1-byte asset name.
pub type RootKey =
  AssetName

/// Key bytes of a linked-list node, without `NodeKeyPrefix`.
///
/// Node keys should be non-empty and unique under the list policy/prefix. A
/// common approach is to derive the key from an input output reference or some
/// other unique witness. If you allow duplicate keys, list integrity must be
/// preserved by some other invariant.
///
/// Ordered operations compare keys as bytearrays. That means integer-like keys
/// should be encoded with a fixed width if numeric ordering matters.
///
/// > [!NOTE]
/// > `255 < 256`, but `#"ff" > #"0100"` in bytearray comparison. Fixed-width
/// > encoding gives the intended order: `#"00ff" < #"0100"`.
pub type NodeKey =
  ByteArray

/// Bytes prefixing every node NFT asset name.
///
/// The full node asset name is `node_key_prefix ++ node_key`, and Cardano
/// asset names can be at most 32 bytes. For example, if the prefix takes 4
/// bytes, node keys can take at most 28 bytes.
///
/// The prefix should be non-empty and must not prefix `RootKey`; otherwise
/// root/node identity can collide.
pub type NodeKeyPrefix =
  ByteArray

/// Must equal `bytearray.length(node_key_prefix)`.
///
/// This is passed separately to avoid recomputing the prefix length on-chain.
/// Define it as a `const` so the compiler can inline it:
/// ```aiken
/// pub const node_key_prefix = "🔗"
///
/// pub const node_key_prefix_length =
///   bytearray.length(node_key_prefix)
/// ```
pub type NodeKeyPrefixLength =
  Int

/// Lovelace delta for a continued list element.
///
/// This is always computed as:
/// `continued_output_lovelace - spent_input_lovelace`.
///
/// A positive value means the operation added ADA to the continued element,
/// and a negative value means it removed ADA from it. The library does not
/// impose an application policy on this delta; operation callbacks receive it
/// so contracts can enforce their own deposit, fee, rent, or conservation
/// rules.
pub type LovelaceChange =
  Lovelace

/// Raw payload stored in a `Root` datum.
///
/// Operation callbacks receive raw `Data` rather than an application-specific
/// type so this module can remain generic. Callers should decode with `expect`
/// inside callbacks and let invalid application data reject the transaction.
pub type RootData =
  Data

/// Raw payload stored in a `Node` datum.
///
/// This has the same generic callback contract as `RootData`: the library
/// authenticates the list element and its structural role, while the caller
/// decides how to decode and validate the application payload.
pub type NodeData =
  Data

/// Successor pointer stored in an element datum.
///
/// `None` means the element is terminal. `Some(node_key)` stores the successor
/// node key without `NodeKeyPrefix`; the policy/prefix namespace is supplied by
/// the operation context rather than repeated in each datum link.
pub type Link =
  Option<NodeKey>

/// Reader alias for helpers that can validate either root elements or node
/// elements. These helpers need the list policy, the root asset name, and the
/// node asset-name namespace.
///
/// > [!NOTE]
/// > To reduce execution budget, readers receive `node_key_prefix_length`
/// > explicitly next to `node_key_prefix`; otherwise each operation would need
/// > to compute the length on-chain.
///
/// > [!NOTE]
/// > The length of `RootKey` can be at most 32 bytes. The length of any
/// > `NodeKey` can be at most `(32 - NodeKeyPrefixLength)`. "Length" here means
/// > bytes after decoding from the chosen encoding, not the number of visible
/// > characters.
pub type ElementEval<result> =
  fn(PolicyId, RootKey, NodeKeyPrefix, NodeKeyPrefixLength) -> result

/// Reader alias for helpers that only need the list policy and root asset name.
///
/// Use this for root-only operations such as initialization, deinitialization,
/// or root UTxO reads. These helpers do not validate node keys, so they do not
/// need node namespace constants.
pub type RootEval<result> =
  fn(PolicyId, RootKey) -> result

/// Reader alias for helpers that only need the list policy and node namespace.
///
/// Use this for node-only operations where the root key is irrelevant. These
/// helpers do not validate the root asset name, so passing only the node prefix
/// and prefix length keeps the caller surface narrower and avoids unused
/// constants in mint/spend branches.
pub type NodeEval<result> =
  fn(PolicyId, NodeKeyPrefix, NodeKeyPrefixLength) -> result

/// Callback for ordered insertion.
///
/// The library has already authenticated the anchor input, authenticated the
/// continued anchor output and new node output, checked the anchor continuation,
/// checked the node-key namespace, checked minting, and checked the requested
/// key ordering before this callback runs.
/// The produced node address is not repeated in this callback; callers that
/// need stake-credential or full-address checks can capture the `new_node_output`
/// they passed to the insertion helper.
///
/// Args: anchor input, anchor Lovelace change, anchor key (`None` for root),
/// anchor data, new node Lovelace, new node key, new node data, new node link.
/// Return `True` to accept the application-specific part of the insertion; use
/// `expect` or return `False` to reject.
pub type OrderedInsertValidation =
  fn(
    Input,
    LovelaceChange,
    Option<NodeKey>,
    Data,
    Lovelace,
    NodeKey,
    NodeData,
    Link,
  ) ->
    Bool

/// Callback for appending an unordered node.
///
/// The anchor and the new node have already been checked to be terminal, and
/// the continued anchor has already been checked to link to the new node.
/// Since this is unordered, the library does not prove anything about the new
/// key beyond its node namespace membership; enforce application-level
/// uniqueness or indexing here if needed.
/// The produced node address is available from the `new_node_output` supplied
/// to the helper.
///
/// Args: anchor input, anchor Lovelace change, anchor key (`None` for root),
/// anchor data, new node Lovelace, new node key, new node data.
pub type AppendValidation =
  fn(Input, LovelaceChange, Option<NodeKey>, Data, Lovelace, NodeKey, NodeData) ->
    Bool

/// Callback for prepending an unordered node.
///
/// The anchor has already been authenticated as the root. The continued root
/// links to the new node, and the new node links to the root's previous first
/// node. The callback is responsible only for application-specific root/new
/// node payload and Lovelace checks.
/// The produced node address is available from the `new_node_output` supplied
/// to the helper.
///
/// Args: root input, root Lovelace change, root data, new node Lovelace,
/// new node key, new node data, new node link.
pub type PrependValidation =
  fn(Input, LovelaceChange, RootData, Lovelace, NodeKey, NodeData, Link) -> Bool

/// Callback for removal.
///
/// The library has already selected the anchor by `anchor_input_outref`,
/// authenticated the removed node, proved that the anchor currently points to
/// that node, burned the removed node NFT, and checked that the continued
/// anchor skips over the removed node. The callback validates the
/// application-specific consequences of that removal.
///
/// Args: anchor input, anchor Lovelace change, anchor key (`None` for root),
/// anchor data, removing node input, removing node Lovelace, removing node key,
/// removing node data, removing node link.
pub type RemoveValidation =
  fn(
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
    Bool

/// Callback for folding the first node into the root.
///
/// The library has already authenticated the root, the first node, and the
/// continued root; proved that the root points to the folded node; burned the
/// folded node NFT; and moved the folded node's old link onto the continued
/// root. The callback decides whether the root data transition and folded node
/// contents are valid for the application.
///
/// Args: root input, root Lovelace change, root data, folding node input,
/// folding node Lovelace, folding node key, folding node data, folding node
/// link, continued root data.
pub type FoldValidation =
  fn(
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
    Bool

/// Callback for non-structural element continuations.
///
/// The updater preserves address, NFT, constructor, and link; this callback
/// controls the Lovelace change and data transition.
///
/// Args: Address, Lovelace change, element key (`None` for root), old data, new
/// data, preserved link. Return `True` to accept the application-specific update.
pub type UpdateValidation =
  fn(Address, LovelaceChange, Option<NodeKey>, Data, Data, Link) -> Bool

// ## Finalization Functions

/// Finalize an `ElementEval` by supplying the list policy, root key, and node
/// namespace constants.
///
/// In most validators, this becomes a small helper:
/// ```aiken
/// use aiken_design_patterns/linked_list
///
/// const root_key = #""
///
/// const node_key_prefix = "NODE"
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
/// Then your minting policy can validate an operation like this:
/// ```aiken
/// let linked_list_eval = {
///   let
///     anchor_input,
///     anchor_lovelace_change,
///     // etc.
///   <-
///     linked_list.insert_ascending(...)
///
///   expect anchor_lovelace_change >= 0
///
///   // other validations
/// }
///
/// expect linked_list_eval |> finalize_linked_list(own_policy_id)
/// ```
///
/// If a redeemer branch can only handle a root or only handle a node, use
/// [`run_root_with`](#run_root_with) or [`run_node_with`](#run_node_with) with
/// the narrower set of constants.
pub fn run_element_with(
  reader: ElementEval<a>,
  list_nft_policy_id: PolicyId,
  root_key: RootKey,
  node_key_prefix: NodeKeyPrefix,
  node_key_prefix_length: NodeKeyPrefixLength,
) -> a {
  reader(list_nft_policy_id, root_key, node_key_prefix, node_key_prefix_length)
}

/// Finalize a `RootEval` by supplying the list policy and root key.
///
/// Root-only helpers return this reader shape when they do not need the node
/// namespace. Keeping those constants out of the helper avoids requiring every
/// root branch to know the node prefix.
pub fn run_root_with(
  reader: RootEval<a>,
  list_nft_policy_id: PolicyId,
  root_key: RootKey,
) -> a {
  reader(list_nft_policy_id, root_key)
}

/// Finalize a `NodeEval` by supplying the list policy and node namespace
/// constants.
///
/// Node-only helpers return this reader shape when they never inspect or
/// validate the root key. The caller is still responsible for supplying the
/// exact prefix length that corresponds to `node_key_prefix`.
pub fn run_node_with(
  reader: NodeEval<a>,
  list_nft_policy_id: PolicyId,
  node_key_prefix: NodeKeyPrefix,
  node_key_prefix_length: NodeKeyPrefixLength,
) -> a {
  reader(list_nft_policy_id, node_key_prefix, node_key_prefix_length)
}

/// Datum stored at each list UTxO: either the root or a node, plus its
/// successor link.
///
/// Terminology:
/// - `Root` is the first element of the list.
/// - `Node` is any non-root list element.
/// - `Element` is the umbrella term for either a root or a node.
///
/// Contracts using this library must define their datums as an applied datum
/// alias:
/// ```aiken
/// pub type Datum = linked_list.Element<RootType, NodeType>
/// ```
///
/// Where `RootType` and `NodeType` are application-specific custom types.
pub type Element<root_data, node_data> {
  data: ElementData<root_data, node_data>,
  link: Link,
}

/// Root or node payload carried by an `Element`.
///
/// Operation callbacks usually provide the element key alongside the raw
/// payload data. `None` for the key means the data came from a `Root`;
/// `Some(key)` means it came from a `Node`.
pub type ElementData<root_data, node_data> {
  Root { data: root_data }
  Node { data: node_data }
}

/// Raw `Data` element alias used by low-level authentication/read helpers.
///
/// This is not an application datum type. It is the authenticated structural
/// shape that lets the library decode `Root` versus `Node` before passing raw
/// payload data to caller callbacks.
pub type GenericElement =
  Element<Data, Data>

/// Raw `Data` element-data alias used by low-level authentication/read helpers.
///
/// `Root { data }` and `Node { data }` identify the structural role of an
/// authenticated element, while the inner `data` remains caller-defined.
pub type GenericElementData =
  ElementData<Data, Data>

// ## Initialization and De-initialization

/// Initialize a linked-list root UTxO with the root NFT and `Root` datum. The
/// output must contain exactly ADA plus that one root NFT.
///
/// `nonce_validated` must prove a unique consumed nonce or equivalent one-time
/// authorization. Passing literal `True` is only appropriate in tests and
/// fixtures.
///
/// `root_validator` receives the produced address, Lovelace quantity, and raw
/// root data. The address is passed explicitly even though callers could inspect
/// `produced_element_output`, so callbacks can validate the destination without
/// destructuring the output again.
///
/// `produced_element_output` must be an output selected from
/// `ScriptContext.transaction.outputs`. This helper authenticates the selected
/// output as a singleton root UTxO, but leaves the selection method to the
/// caller so contracts can use indexes, filtering, or any other shape that fits
/// their redeemer/API.
///
/// It is up to callers to ensure this address has a script payment credential
/// controlled by a script that only uses the spend helpers from this library. In
/// other words, the destination script must ensure list NFTs never leave its
/// custody.
pub fn init(
  nonce_validated: Bool,
  produced_element_output: Output,
  tx_mint: Value,
  root_validator: fn(Address, Lovelace, Data) -> Bool,
) -> RootEval<Bool> {
  // 1. The caller must prove the one-time initialization authorization.
  expect nonce_validated

  fn(list_nft_policy_id: PolicyId, root_key: RootKey) -> Bool {
    // 2. The produced output must be an authentic singleton list element.
    let
      element_address,
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

    // 3. The produced datum must be a root datum.
    expect Root { data: root_data } = element_data

    // 4. The singleton NFT must use the configured root key.
    expect element_asset_name == root_key

    // 5. Initialization must mint exactly that root NFT.
    expect
      is_only_mint_under_policy(
        tx_mint,
        list_nft_policy_id,
        element_asset_name,
        1,
      )

    // 6. A new list starts empty.
    expect element_link == None

    // 7. Delegate application-specific root checks to the caller.
    expect root_validator(element_address, element_lovelace, root_data)

    // Done.
    True
  }
}

/// Deinitialize an empty list.
///
/// `root_validator` args: spent root input, root Lovelace, raw root data.
pub fn deinit(
  inputs: List<Input>,
  tx_mint: Value,
  root_validator: fn(Input, Lovelace, Data) -> Bool,
) -> RootEval<Bool> {
  fn(list_nft_policy_id: PolicyId, root_key: RootKey) -> Bool {
    // 1. The transaction must spend exactly one authentic list element.
    let
      element_input,
      element_lovelace,
      element_asset_name,
      element_data,
      element_link,
    <- validate_singular_authentic_input(inputs, list_nft_policy_id)

    // 2. The spent element must be the root.
    expect Root { data: root_data }: GenericElementData = element_data

    // 3. Deinitialization must burn exactly the root NFT.
    expect
      is_only_mint_under_policy(
        tx_mint,
        list_nft_policy_id,
        element_asset_name,
        -1,
      )

    // 4. The root NFT asset name must match the configured root key.
    expect element_asset_name == root_key

    // 5. The root must have no successor.
    expect element_link == None

    // 6. Delegate application-specific root checks to the caller.
    expect root_validator(element_input, element_lovelace, root_data)

    // Done.
    True
  }
}

// ## Element Addition and Removal

/// Insert a new node into an ascending ordered list.
///
/// The anchor element is inferred from `inputs` by requiring exactly one
/// authentic linked-list element input. Its continued output must preserve the
/// spent anchor address and data, and the new node must use the anchor payment
/// credential.
///
/// Ordering rule:
/// - root anchor: `new < old_first`
/// - node anchor: `anchor < new < old_next`
///
/// `additional_validations` receives:
/// 1. anchor input
/// 2. anchor Lovelace change
/// 3. anchor key (`None` for root, `Some(key)` for node)
/// 4. anchor data
/// 5. new node Lovelace
/// 6. new node key
/// 7. new node data
/// 8. new node link
///
/// The default module preserves anchor data. Use `linked_list/advanced` when
/// insertion should allow caller-validated anchor data changes.
///
/// `continued_anchor_element_output` and `new_node_output` must both be
/// selected from `ScriptContext.transaction.outputs`. The caller controls how
/// they are selected, for example by redeemer indexes or by filtering outputs.
pub fn insert_ascending(
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: OrderedInsertValidation,
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

/// Like [`insert_ascending`](#insert_ascending), but the ordering is reversed:
///
/// - root anchor: `new > old_first`
/// - node anchor: `anchor > new > old_next`
///
/// `continued_anchor_element_output` and `new_node_output` must both be
/// selected from `ScriptContext.transaction.outputs`; this helper validates the
/// selected outputs, not the selection method.
pub fn insert_descending(
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: OrderedInsertValidation,
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

/// Append a new terminal node to an unordered list.
///
/// The single authentic input is the current terminal anchor. The continued
/// anchor links to the new node, and the new node must be terminal too.
///
/// There is no key-order comparison for unordered appends; callers are still
/// responsible for maintaining any application-specific uniqueness or indexing
/// invariant in `additional_validations`.
///
/// `additional_validations` receives:
/// 1. anchor input
/// 2. anchor Lovelace change
/// 3. anchor key (`None` for root, `Some(key)` for node)
/// 4. anchor data
/// 5. new node Lovelace
/// 6. new node key
/// 7. new node data
///
/// The default module preserves anchor data. Use `linked_list/advanced` when
/// appending should allow caller-validated anchor data changes.
///
/// `continued_anchor_element_output` and `new_node_output` must both be
/// selected from `ScriptContext.transaction.outputs`. The caller may choose any
/// deterministic selection method that suits the surrounding validator.
pub fn append_unordered(
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: AppendValidation,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    // 1. Run the shared insertion checks.
    let
      anchor_element_input,
      anchor_element_lovelace_change,
      anchor_element_asset_name,
      anchor_element_data,
      anchor_element_link,
      new_node_lovelace,
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

    // 2. The anchor must be terminal.
    expect anchor_element_link == None

    // 3. The appended node must also be terminal.
    expect new_node_link == None

    when anchor_element_data is {
      Root { data: root_data } -> {
        // 4a. A root anchor must use the configured root key.
        expect anchor_element_asset_name == root_key

        // 5a. Delegate application-specific append checks.
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
        // 4b. A node anchor must stay inside the node namespace.
        expect
          bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix

        // 5b. Delegate application-specific append checks.
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

/// Prepend a new first node to an unordered list.
///
/// The single authentic input must be the root. The continued root links to the
/// new node, and the new node links to the root's old first node.
///
/// `additional_validations` receives:
/// 1. root input
/// 2. root Lovelace change
/// 3. root data
/// 4. new node Lovelace
/// 5. new node key
/// 6. new node data
/// 7. new node link
///
/// The default module preserves root data. Use `linked_list/advanced` when
/// prepending should allow caller-validated root data changes.
///
/// `continued_root_element_output` and `new_node_output` must both be selected
/// from `ScriptContext.transaction.outputs`. The helper authenticates the
/// selected outputs and leaves indexing/filtering strategy to the caller.
pub fn prepend_unordered(
  continued_root_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: PrependValidation,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    // 1. Run the shared insertion checks.
    let
      root_element_input,
      root_lovelace_change,
      root_element_asset_name,
      root_element_data,
      _root_element_link,
      new_node_lovelace,
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

    // 2. The anchor must be the root.
    expect Root { data: root_data } = root_element_data

    // 3. The root NFT asset name must match the configured root key.
    expect root_element_asset_name == root_key

    // 4. Delegate application-specific prepend checks.
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

/// Remove the node linked by the selected anchor.
///
/// The anchor is identified by `anchor_input_outref`; the anchor and removing
/// node are inferred from the transaction inputs. The removed node must be the
/// node named by the selected anchor's current link, and the continued anchor's
/// link becomes the removed node's old link.
///
/// This operation assumes the list script/payment credential is dedicated to
/// list elements. Transaction builders must not include unrelated inputs at the
/// same payment credential, even if those inputs do not carry a list NFT; such
/// inputs are outside the API contract rather than something the helper must
/// classify and ignore.
///
/// `additional_validations` receives:
/// 1. anchor input
/// 2. anchor Lovelace change
/// 3. anchor key (`None` for root, `Some(key)` for node)
/// 4. anchor data
/// 5. removing node input
/// 6. removing node Lovelace
/// 7. removing node key
/// 8. removing node data
/// 9. removing node link
///
/// The default module preserves anchor data. Use `linked_list/advanced` when
/// removal should allow caller-validated anchor data changes.
pub fn remove(
  anchor_input_outref: OutputReference,
  continued_anchor_element_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: RemoveValidation,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    // 1. Locate the selected anchor input and the node linked from it.
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

    let Input { output: Output { address: anchor_address, .. }, .. } =
      anchor_input

    // 2. Authenticate the continued anchor output.
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

    // 3. The removed asset must live in the node namespace.
    expect
      bytearray.take(removing_node_asset_name, node_key_prefix_length) == node_key_prefix

    let removing_node_key =
      bytearray.drop(removing_node_asset_name, node_key_prefix_length)

    // 4. The continued anchor must preserve address, NFT, and data.
    expect cont_anchor_address == anchor_address
    expect cont_anchor_asset_name == anchor_asset_name
    expect cont_anchor_element_data == anchor_element_data

    // 5. The non-anchor authentic input must be a node.
    expect Node { data: removing_node_data } = removing_node_element_data

    // 6. Removal must burn exactly the removed node NFT.
    expect
      is_only_mint_under_policy(
        tx_mint,
        list_nft_policy_id,
        removing_node_asset_name,
        -1,
      )

    // 7. The anchor must currently point to the removed node.
    expect anchor_link == Some(removing_node_key)

    // 8. The continued anchor must skip over the removed node.
    expect cont_anchor_link == removing_node_link

    when anchor_element_data is {
      Root { data: root_data } -> {
        // 9a. A root anchor must use the configured root key.
        expect anchor_asset_name == root_key

        // 10a. Delegate application-specific remove checks.
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
        // 9b. A node anchor must stay inside the node namespace.
        expect
          bytearray.take(anchor_asset_name, node_key_prefix_length) == node_key_prefix

        // 10b. Delegate application-specific remove checks.
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

/// Fold the root's first node into the root.
///
/// The root is identified by its output reference. The helper authenticates the
/// root, the linked node, and the continued root; preserves the root
/// address/key; burns the folding node NFT; and enforces the root/node
/// namespace checks.
///
/// This traverses `inputs` and expects exactly two authentic list inputs at the
/// list payment credential: the root input and the folding node input.
/// Unrelated inputs at the same payment credential are invalid transaction
/// construction, even if they do not carry the list NFT; the helper is not a
/// classifier for those inputs.
///
/// `additional_validations` receives:
/// 1. root input
/// 2. root Lovelace change
/// 3. root data
/// 4. folding node input
/// 5. folding node Lovelace
/// 6. folding node key
/// 7. folding node data
/// 8. folding node link
/// 9. continued root data
pub fn fold_from_root(
  anchor_root_input_outref: OutputReference,
  continued_anchor_root_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: FoldValidation,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    // 1. Locate the root input and the node linked from it.
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

    let Input { output: Output { address: anchor_root_address, .. }, .. } =
      anchor_root_input

    // 2. The anchor input must be a root.
    expect Root { data: anchor_root_data }: GenericElementData =
      anchor_root_element_data

    // 3. Authenticate the continued root output.
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

    // 4. The folded asset must live in the node namespace.
    expect
      bytearray.take(folding_node_asset_name, node_key_prefix_length) == node_key_prefix

    let folding_node_key =
      folding_node_asset_name
        |> bytearray.drop(node_key_prefix_length)

    // 5. The non-anchor authentic input must be a node.
    expect Node { data: folding_node_data }: GenericElementData =
      folding_node_element_data

    // 6. The continued anchor must remain a root.
    expect Root { data: cont_anchor_root_data }: GenericElementData =
      cont_anchor_root_element_data

    // 7. Folding must burn exactly the folded node NFT.
    expect
      is_only_mint_under_policy(
        tx_mint,
        list_nft_policy_id,
        folding_node_asset_name,
        -1,
      )

    // 8. The continued root must preserve address and NFT.
    expect anchor_root_address == cont_anchor_root_address
    expect anchor_root_asset_name == cont_anchor_root_asset_name

    // 9. The root must currently point to the folded node.
    expect anchor_root_link == Some(folding_node_key)

    // 10. The continued root must adopt the folded node's old link.
    expect cont_anchor_root_link == folding_node_link

    // 11. The root NFT asset name must match the configured root key.
    expect anchor_root_asset_name == root_key

    // 12. Delegate application-specific fold checks.
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
    True
  }
}

// ## Spending Script Helpers

/// Spend-side gate for structural operations.
///
/// This function is intentionally not a structural validator by itself. It
/// must only be used in a spend script whose paired list minting policy accepts
/// structural mint/burns exclusively through this module's matching mint
/// helpers (`init`, `insert_*`, `remove`, `fold_from_root`, `deinit`, etc.).
///
/// The security invariant is split across scripts:
/// - the spend script uses this gate to permit structural list spends only when
///   a list-policy mint/burn is present;
/// - the minting policy proves the exact linked-list transition with the
///   corresponding mint helper.
///
/// Do not use this as standalone authorization for moving a list UTxO.
///
/// Use this for spend branches that allow adding/removing list elements. Use
/// [`spend_for_updating_elements_data`](#spend_for_updating_elements_data) for
/// non-structural continuations where the element is reproduced and no
/// list-policy mint/burn occurs.
pub fn spend_for_adding_or_removing_an_element(
  list_nft_policy_id: PolicyId,
  tx_mint: Value,
) -> Bool {
  !(assets.tokens(tx_mint, list_nft_policy_id) |> dict.is_empty)
}

/// Continue an individual element without changing the linked-list structure.
///
/// No list-policy mint/burn is allowed; address, NFT, constructor, and link are
/// preserved before `UpdateValidation` decides the Lovelace and data change.
///
/// `additional_validations` receives:
/// 1. preserved element address
/// 2. Lovelace change
/// 3. element key (`None` for root, `Some(key)` for node)
/// 4. old data
/// 5. new data
/// 6. preserved link
pub fn spend_for_updating_elements_data(
  element_input_index: Int,
  continued_element_output_index: Int,
  element_input_outref: OutputReference,
  inputs: List<Input>,
  outputs: List<Output>,
  tx_mint: Value,
  additional_validations: UpdateValidation,
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

    // 1. The continuation must preserve address, NFT, and link.
    expect elem_address == cont_elem_address
    expect elem_asset_name == cont_elem_asset_name
    expect elem_link == cont_elem_link

    let lovelace_change = cont_elem_lovelace - elem_lovelace
    when elem_data is {
      Root { data } -> {
        // 2a. The continued datum must remain a root.
        expect Root { data: continued_data } = cont_elem_data

        // 3a. A root update must use the configured root key.
        expect elem_asset_name == root_key

        // 4a. Delegate application-specific update checks.
        expect
          additional_validations(
            elem_address,
            lovelace_change,
            None,
            data,
            continued_data,
            elem_link,
          )
        True
      }
      Node { data } -> {
        // 2b. The continued datum must remain a node.
        expect Node { data: continued_data } = cont_elem_data

        // 3b. A node update must stay inside the node namespace.
        expect
          bytearray.take(elem_asset_name, node_key_prefix_length) == node_key_prefix

        // 4b. Delegate application-specific update checks.
        expect
          additional_validations(
            elem_address,
            lovelace_change,
            Some(bytearray.drop(elem_asset_name, node_key_prefix_length)),
            data,
            continued_data,
            elem_link,
          )
        True
      }
    }
  }
}

// ## Exposed Helpers

/// `get_element_info` continuation.
///
/// Args: Address, Lovelace, element key (`None` for root, `Some(key)` for node),
/// data, link.
pub type ElementInfo<a> =
  fn(Address, Lovelace, Option<NodeKey>, Data, Link) -> a

/// `get_root_element_info` continuation.
///
/// Args: Address, Lovelace, root data, link.
pub type RootElementInfo<a> =
  fn(Address, Lovelace, RootData, Link) -> a

/// `get_node_element_info` continuation.
///
/// Args: Address, Lovelace, node key, node data, link.
pub type NodeElementInfo<a> =
  fn(Address, Lovelace, NodeKey, NodeData, Link) -> a

/// Authenticate a root or node UTxO and pass its info to `info_validations`.
///
/// The UTxO must be an inline-datum singleton list element under the supplied
/// policy. The returned key is `None` for the root and `Some(node_key)` for a
/// node, where `node_key` excludes `NodeKeyPrefix`. Root keys and node-prefix
/// membership are checked before the callback runs.
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
      element_address,
      element_lovelace,
      element_asset_name,
      element_data,
      element_link,
      _element_ref_script,
    <- authenticate_element_utxo_and_get_info(element_utxo, list_nft_policy_id)

    when element_data is {
      Root { data: root_data } -> {
        expect element_asset_name == root_key
        info_validations(
          element_address,
          element_lovelace,
          None,
          root_data,
          element_link,
        )
      }
      Node { data: node_data } -> {
        expect
          bytearray.take(element_asset_name, node_key_prefix_length) == node_key_prefix
        info_validations(
          element_address,
          element_lovelace,
          Some(bytearray.drop(element_asset_name, node_key_prefix_length)),
          node_data,
          element_link,
        )
      }
    }
  }
}

/// Authenticate a root UTxO and pass its info to `info_validations`.
///
/// The UTxO must carry the configured root NFT and a `Root` datum. The callback
/// receives address, Lovelace, raw root payload data, and the root link. Use
/// this when a script only accepts roots and should reject node UTxOs
/// immediately.
pub fn get_root_element_info(
  element_utxo: Output,
  info_validations: RootElementInfo<a>,
) -> RootEval<a> {
  fn(list_nft_policy_id: PolicyId, root_key: RootKey) -> a {
    let
      element_address,
      element_lovelace,
      element_asset_name,
      element_data,
      element_link,
      _element_ref_script,
    <- authenticate_element_utxo_and_get_info(element_utxo, list_nft_policy_id)

    expect element_asset_name == root_key
    expect Root { data: root_data } = element_data

    info_validations(element_address, element_lovelace, root_data, element_link)
  }
}

/// Authenticate a node UTxO and pass its info to `info_validations`.
///
/// The UTxO must carry a list NFT whose asset name starts with
/// `node_key_prefix` and must contain a `Node` datum. The callback receives
/// address, the node key with the prefix stripped, raw node payload data, and
/// the node link.
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
      element_address,
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

    info_validations(
      element_address,
      element_lovelace,
      node_key,
      node_data,
      element_link,
    )
  }
}

// ## Low-level Helpers
//
// The functions below are intentionally public for composition and testing.
// Prefer the operation helpers above unless another script needs to inspect
// linked-list elements directly.

/// Authenticate an element UTxO, requiring exactly ADA plus one list NFT, then
/// decode its datum as `Element<Data, Data>` and pass address, Lovelace, asset
/// name, data, link, and reference script to the continuation.
///
/// This is mostly an internal helper. You most likely don't want to use this
/// function.
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

  expect Element { data, link }: GenericElement = utxo_datum_data

  return(output_address, lovelace_count, nft_name, data, link, utxo_ref_script)
}

/// Validate exactly one authentic list input while scanning all transaction
/// inputs.
///
/// After one is found, this only rejects a second singleton list-shaped input
/// under the same policy. Malformed or unrelated shapes rely on the API
/// precondition that the list payment credential is dedicated to list UTxOs and
/// transactions do not include unrelated same-credential inputs.
///
/// Args: callback receives input, Lovelace, asset name, data, link.
///
/// Another internal helper, you probably don't need this.
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

/// Validate exactly two authentic list inputs while scanning all transaction
/// inputs.
///
/// This assumes the list payment credential is dedicated to list inputs: a
/// transaction must not spend unrelated same-credential inputs at all. This
/// helper is optimized for that contract and is not a robust classifier for
/// arbitrary same-credential inputs.
///
/// Args: callback receives anchor input, anchor Lovelace, anchor asset name,
/// anchor data, anchor link, removing input, removing Lovelace, removing asset
/// name, removing data, removing link.
///
/// Another internal helper, you probably don't need this.
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

fn insert_ordered(
  required_neighbor_ordering: Ordering,
  continued_anchor_element_output: Output,
  new_node_output: Output,
  inputs: List<Input>,
  tx_mint: Value,
  additional_validations: OrderedInsertValidation,
) -> ElementEval<Bool> {
  fn(
    list_nft_policy_id: PolicyId,
    root_key: RootKey,
    node_key_prefix: NodeKeyPrefix,
    node_key_prefix_length: NodeKeyPrefixLength,
  ) -> Bool {
    // 1. Run the shared insertion checks.
    let
      anchor_element_input,
      anchor_element_lovelace_change,
      anchor_element_asset_name,
      anchor_element_data,
      anchor_element_link,
      new_node_lovelace,
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
        // 2a. A root anchor must use the configured root key.
        expect anchor_element_asset_name == root_key

        // 3a. The new key must fit before/after the old first node.
        expect
          key_fits_between(
            required_neighbor_ordering,
            None,
            new_node_key,
            anchor_element_link,
          )

        // 4a. Delegate application-specific ordered-insert checks.
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
        True
      }
      Node { data: anchor_node_data } -> {
        // 2b. A node anchor must stay inside the node namespace.
        expect
          bytearray.take(anchor_element_asset_name, node_key_prefix_length) == node_key_prefix

        let anchor_node_key =
          bytearray.drop(anchor_element_asset_name, node_key_prefix_length)

        // 3b. The new key must fit between the anchor and its old successor.
        expect
          key_fits_between(
            required_neighbor_ordering,
            Some(anchor_node_key),
            new_node_key,
            anchor_element_link,
          )

        // 4b. Delegate application-specific ordered-insert checks.
        expect
          additional_validations(
            anchor_element_input,
            anchor_element_lovelace_change,
            Some(anchor_node_key),
            anchor_node_data,
            new_node_lovelace,
            new_node_key,
            new_node_data,
            new_node_link,
          )
        True
      }
    }
  }
}

// Shared insertion precheck: authenticate the anchor continuation and new node,
// preserve anchor identity/data, and wire anchor -> new node -> previous link.
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
    NodeKey,
    NodeData,
    Link,
  ) ->
    Bool,
) -> Bool {
  // 1. The transaction must spend exactly one authentic anchor input.
  let
    anchor_element_input,
    anchor_element_lovelace,
    anchor_element_asset_name,
    anchor_element_data,
    anchor_element_link,
  <- validate_singular_authentic_input(inputs, list_nft_policy_id)

  let Input { output: Output { address: anchor_element_address, .. }, .. } =
    anchor_element_input
  let Address { payment_credential: anchor_payment_credential, .. } =
    anchor_element_address

  // 2. The continued anchor output must be authentic.
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

  // 3. The new node output must be authentic.
  let
    new_node_address,
    new_node_lovelace,
    new_node_asset_name,
    new_node_element_data,
    new_node_link,
    _new_node_ref_script,
  <- authenticate_element_utxo_and_get_info(new_node_output, list_nft_policy_id)
  let Address { payment_credential: new_node_payment_credential, .. } =
    new_node_address

  // 4. The continued anchor must preserve the full address.
  expect anchor_element_address == cont_anchor_element_address

  // 5. The new node must share the anchor payment credential.
  expect anchor_payment_credential == new_node_payment_credential

  // 6. The continued anchor must preserve the anchor NFT.
  expect anchor_element_asset_name == cont_anchor_element_asset_name

  // 7. The default module preserves anchor data during insertion.
  expect anchor_element_data == cont_anchor_element_data

  let anchor_element_lovelace_change =
    cont_anchor_element_lovelace - anchor_element_lovelace

  // 8. The new node asset must live in the node namespace.
  expect
    bytearray.take(new_node_asset_name, node_key_prefix_length) == node_key_prefix

  let new_node_key = bytearray.drop(new_node_asset_name, node_key_prefix_length)

  // 9. Insertion must mint exactly the new node NFT.
  expect
    is_only_mint_under_policy(
      tx_mint,
      list_nft_policy_id,
      new_node_asset_name,
      1,
    )

  // 10. The continued anchor must point to the new node.
  expect cont_anchor_element_link == Some(new_node_key)

  // 11. The new node must point to the anchor's previous successor.
  expect new_node_link == anchor_element_link

  // 12. The produced node datum must be a `Node`.
  expect Node { data: new_node_data } = new_node_element_data

  // 13. Delegate operation-specific insertion checks.
  expect
    callback(
      anchor_element_input,
      anchor_element_lovelace_change,
      anchor_element_asset_name,
      anchor_element_data,
      anchor_element_link,
      new_node_lovelace,
      new_node_key,
      new_node_data,
      new_node_link,
    )

  // Done.
  True
}
