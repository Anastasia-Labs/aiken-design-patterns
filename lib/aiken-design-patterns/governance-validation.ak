//// # Governance-authenticated protocol update pattern
////
//// `AddProposal` atomically inserts a proposal node and submits exactly one
//// matching protocol-parameter governance action. The proposal authenticates a
//// complete live cost model as a splice around one selected builtin. Passage is
//// later witnessed by the complete accepted model appearing in the live
//// language view for the Plutus language this contract compiles to. This proves
//// the approved value is live; it does not identify which governance action
//// enacted that value.
////
//// ## Governance-address custody
////
//// The governance validator address is dedicated to the root, proposal-node,
//// and passed-proposal UTxOs created by this pattern. Its spending endpoint is
//// a paired minting-policy gate for those state transitions; it does not
//// independently protect unrelated UTxOs at that address. Do not use the
//// address as a general-purpose payment destination.
////
//// Proposal insertion reconstructs Conway transaction-body bytes from the
//// Plutus context plus witnesses for information the context omits. Values
//// serialized by the module use the hardware-wallet canonical CBOR profile:
//// shortest integers and lengths, definite arrays and maps, canonical map-key
//// ordering, and tag 258 on sets. This is a serialization profile, not the
//// hardware-wallet body-field allowlist; insertion necessarily includes the
//// proposal procedure. Certificates, voting procedures, and collateral-related
//// regions are supplied as opaque CBOR fragments and inserted verbatim. They are
//// not decoded or interpreted as independent semantic evidence by this module.
//// The authenticated insertion body always includes its validity-interval start
//// and excludes the optional transaction-body network ID entry.
////
//// The supported shape has exactly one proposal procedure: a protocol-parameter
//// update containing only the cost model for this contract's Plutus language.
//// Context-visible ordinary no-datum outputs use the two-element array form;
//// ordinary inline datums use the three-key map form. Redeemers use the definite
//// list or definite map representation selected by the authorizing redeemer's
//// encoding flag; entries remain in ascending ledger-pointer order. Language
//// views contain the authenticated model for that language plus opaque
//// cost-model values for any other live languages.
//// Plutus Data byte strings longer than 64 bytes retain the ledger-mandated
//// indefinite chunked form.
////
//// ## Unsupported transaction features
////
//// To reduce complexity of transaction reconstruction, proposal insertion does
//// not support:
////
//// - additional proposal procedures, other governance-action kinds, or protocol
////   parameter updates containing anything beyond that cost model;
//// - datum-hash ordinary outputs or datum witnesses in the script-data hash;
//// - reference scripts on ordinary transaction outputs;
//// - Byron/bootstrap spending inputs, reference inputs, or ordinary outputs:
////   the ledger does not pass bootstrap-address UTxOs into Plutus script
////   contexts, so their presence prevents this policy from executing;
//// - execution of Plutus scripts whose language view uses the ledger's legacy
////   double-wrapped language key and indefinite cost-model list.
////
//// Here, `ordinary output` means an entry in the transaction body's normal
//// output field, as opposed to a collateral return output. Collateral-related
//// fields are supplied as opaque CBOR and inserted verbatim; this module does
//// not classify them.
////
//// Unsupported governance-proposal shapes fail the insertion invariants.
//// Datum-hash ordinary outputs fail directly. Opaque witness fragments are not
//// parsed independently; normal ledger validation remains responsible for the
//// well-formedness and consistency of the transaction components they encode.
////
//// Collateral inputs commit only output references. Their resolved outputs are
//// absent from ScriptContext, so this module cannot classify their address
//// family.
////
//// Other transitions retain their narrower body shapes. All shared collection
//// serializers nevertheless use general shortest-form length headers.

use aiken/builtin
use aiken/cbor
use aiken/collection/dict
use aiken/collection/list
use aiken/collection/pairs
use aiken/crypto.{ScriptHash, VerificationKeyHash}
use aiken/interval.{Finite, Interval, IntervalBound}
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list
use aiken_design_patterns/linked_list/advanced as advanced_linked_list
use aiken_design_patterns/linked_list/internal.{
  validate_singular_authentic_input_helper,
}
use aiken_design_patterns/stake_validator
use cardano/address.{
  Address, Credential, Inline, Pointer, Script, VerificationKey,
}
use cardano/assets.{AssetName, Lovelace, PolicyId, Value}
use cardano/certificate.{Certificate}
use cardano/governance.{
  GovernanceActionId, ProposalProcedure, ProtocolParameters, Vote, Voter,
}
use cardano/governance/protocol_parameters
use cardano/transaction.{
  DatumHash, InlineDatum, Input, Mint, NoDatum, Output, OutputReference,
  Redeemer, ScriptPurpose, Transaction,
}

const root_key: linked_list.RootKey = "PROPOSALS_ROOT"

const node_key_prefix: linked_list.NodeKeyPrefix = "BUILTIN_INDEX_"

const node_key_prefix_length: linked_list.NodeKeyPrefixLength =
  bytearray.length(node_key_prefix)

/// Asset name of the configuration NFT that carries the governance-action
/// lifespan in its inline integer datum.
pub const gov_action_lifespan_asset_name: AssetName = "GOV_ACTION_LIFESPAN"

/// Namespace for proposals that show their target builtin cost has gone live.
/// This out-of-list UTxO is needed to free up the spot for other proposals,
/// since there is no guarantee their required scripts succeed or not.
const passed_proposal_prefix: ByteArray = "PASS"

const passed_proposal_prefix_length: Int =
  bytearray.length(passed_proposal_prefix)

/// This determines the supported number of builtins carried in a cost model.
/// Four bytes allow more entries than any currently defined cost model.
const node_key_byte_count: Int = 4

/// Ten minutes maximum validity range span to prevent upper bounds too far in
/// the future.
const max_validity_range_span: Int = 10 * 60 * 1_000

/// Cost models in protocol parameters are a map from Plutus language
/// identifiers to ordered lists of integer costs. This is the map key for the
/// language this contract compiles to and must track its compilation target.
const plutus_language_id = 2

const serialised_plutus_language_id = cbor.serialise(plutus_language_id)

const set_cbor_tag = serialise_cbor_tag(258)

const singleton_cbor_list = serialise_cbor_head(4, 1)

const mint_cbor_key = cbor.serialise(9)

/// CBOR tag 102 marks the general Plutus Data constructor representation.
const general_plutus_data_constructor_cbor_tag = serialise_cbor_tag(102)

pub type Empty =
  ByteArray

/// Exact encoding of the transaction redeemer collection authenticated by
/// script-data-hash reconstruction. The flag is itself part of the authorizing
/// redeemer's Data. Ledger validation still determines whether the selected
/// representation is permitted by the active protocol version.
pub type RedeemerEncoding {
  ListEncoding
  MapEncoding
}

/// Transaction-body data carried by the `AddProposal` redeemer. `certificates`,
/// `voting_procedures`, and the collateral fields are opaque CBOR fragments
/// inserted verbatim during body-hash reconstruction; they are not independently
/// decoded as standalone field values. All other fields, including the flattened
/// proposal anchor, contain semantic values omitted from ScriptContext. The body
/// profile always includes `validity_start` and excludes the optional network ID
/// entry.
pub type AddProposalBodyWitness {
  ttl: Int,
  certificates: ByteArray,
  auxiliary_data_hash: Option<ByteArray>,
  validity_start: Int,
  collateral_inputs: ByteArray,
  collateral_return: ByteArray,
  total_collateral: ByteArray,
  voting_procedures: ByteArray,
  proposal_anchor_url: ByteArray,
  proposal_anchor_data_hash: ByteArray,
}

/// Missing ledger-pointer and execution-budget data for one context redeemer.
/// `context_index` selects its purpose and Data; the purpose determines its tag.
pub type RedeemerMetadata {
  context_index: Int,
  ledger_index: Int,
  mem: Int,
  cpu: Int,
}

/// A live cost-model witness for another Plutus language used by the insertion
/// transaction. `cost_model` is inserted verbatim into language-view hash
/// reconstruction and is not independently decoded.
pub type LanguageCostModel {
  language_id: Int,
  cost_model: ByteArray,
}

/// `cost_model_prefix` includes the cost model's definite-array CBOR header and
/// exactly the complete integer entries before the builtin selected by the node
/// key. `cost_model_postfix` starts immediately after that builtin's integer
/// and preserves the rest of the model byte-for-byte. The insertion redeemer's
/// transient `initial_builtin_cost` reconstructs the live model. The proposal
/// inserts `cbor.serialise(acceptance_builtin_cost)` between them.
///
/// `subject_script_hash` identifies a stable withdrawal script to which the
/// subject contract delegates authorization. Its 28-byte hash is encoded after
/// `PASS` in the resulting token name. `required_script_for_final_burn` is a
/// distinct, proposal-specific withdrawal script that enforces the final action.
pub type Proposal {
  proposer: Address,
  gov_action_script_data_hash: ByteArray,
  cost_model_prefix: ByteArray,
  acceptance_builtin_cost: Int,
  cost_model_postfix: ByteArray,
  valid_until: Int,
  subject_script_hash: ScriptHash,
  required_script_for_final_burn: ScriptHash,
}

pub type Datum =
  linked_list.Element<Empty, Proposal>

/// Linked list `Element` occupies constructor ID 0. Its first field contains
/// the nested `Root` or `Node` element-data constructor. Keep passed proposals
/// disjoint from list elements at the outer datum level.
@tag(1)
pub type PassedProposal {
  proposer: Address,
  passed_proposal_script_data_hash: ByteArray,
  required_script_for_final_burn: ScriptHash,
}

pub type SpendRedeemer {
  // Spend script delegates its logic to the minting script and performs no
  // other validations.
  DelegateToMint
}

pub type MintRedeemer {
  // Initializing the list for proposals.
  Init { nonce_input_index: Int, root_output_index: Int }
  // Atomically inserting a proposal node and submitting its corresponding
  // governance action. The redeemer selects the configuration reference input
  // carrying the governance-action lifespan, then carries the live cost at
  // insertion, pointer/budget metadata, other live language cost models, and
  // transaction body data needed for hash reconstruction.
  AddProposal {
    gov_action_lifespan_reference_input_index: Int,
    redeemer_encoding: RedeemerEncoding,
    anchor_output_index: Int,
    proposal_node_output_index: Int,
    initial_builtin_cost: Int,
    redeemer_metadata: List<RedeemerMetadata>,
    other_language_cost_models: List<LanguageCostModel>,
    body_witness: AddProposalBodyWitness,
  }
  // Removing a proposal whose target builtin has gone live. This endpoint
  // carries the ledger pointers and execution budgets required to authenticate
  // its script-data hash, and mints a subject-withdrawal-bound `PASS` token
  // outside the list namespace.
  MintPassedProposal {
    redeemer_encoding: RedeemerEncoding,
    anchor_input_outref: OutputReference,
    anchor_output_index: Int,
    passed_proposal_output_index: Int,
    anchor_spend_redeemer_index: Int,
    proposal_spend_redeemer_index: Int,
    anchor_spend_cpu: Int,
    anchor_spend_mem: Int,
    node_spend_cpu: Int,
    node_spend_mem: Int,
    mint_cpu: Int,
    mint_mem: Int,
    ttl: Int,
    collateral_inputs: ByteArray,
    collateral_output: ByteArray,
    collateral_fee: ByteArray,
  }
  // Burning a `PassedProposal` UTxO and executing the declared withdrawal
  // script. These UTxOs sit outside the list namespace, and therefore failure
  // of their withdrawals scripts won't block a given builtin for future
  // proposals.
  FinalizePassedProposal {
    proposer_output_index: Int,
    subject_withdrawal_index: Int,
    required_script_withdrawal_index: Int,
  }
  // Removing an expired proposal and reimbursing its proposer. Anyone may
  // perform this transition after the proposal's deadline.
  RemoveExpiredProposal {
    anchor_input_outref: OutputReference,
    anchor_output_index: Int,
    proposer_output_index: Int,
  }
}

/// Validator for initializing the linked list that all proposals live within.
/// The list permits at most one live proposal per builtin index. Each node key
/// is exactly the index's four-byte big-endian encoding. The assumption is that
/// there will be a single canonical list for all protocols to utilize.
pub fn init(
  nonce: OutputReference,
  nonce_input_index: Int,
  root_output_index: Int,
  governance_nft_policy: PolicyId,
  tx: Transaction,
) -> Bool {
  let Transaction { inputs, outputs, mint, .. } = tx
  {
    let
      root_address,
      _root_lovelace,
      root_data,
    <-
      linked_list.init(
        nonce_validated: {
          let input = inputs |> list.expect_at(nonce_input_index)
          input.output_reference == nonce
        },
        produced_element_output: outputs |> list.expect_at(root_output_index),
        tx_mint: mint,
      )

    // 1. The root UTxO must be produced at an address which its payment cred
    //    is a script with the same hash as the list NFT's.
    expect root_address.payment_credential == Script(governance_nft_policy)

    // 2. An empty bytearray is the expected root data.
    expect builtin.un_b_data(root_data) == #""

    // Done.
    True
  }
    |> linked_list.run_root_with(governance_nft_policy, root_key)
}

pub fn add_proposal(
  network_tag: Int,
  governance_nft_policy: PolicyId,
  gov_action_lifespan_policy: PolicyId,
  //
  gov_action_lifespan_reference_input_index: Int,
  redeemer_encoding: RedeemerEncoding,
  anchor_output_index: Int,
  proposal_node_output_index: Int,
  initial_builtin_cost: Int,
  redeemer_metadata: List<RedeemerMetadata>,
  other_language_cost_models: List<LanguageCostModel>,
  body_witness: AddProposalBodyWitness,
  //
  tx: Transaction,
) -> Bool {
  let Transaction {
    inputs,
    reference_inputs,
    outputs,
    fee,
    mint,
    certificates: tx_certificates,
    withdrawals,
    validity_range,
    extra_signatories,
    redeemers,
    proposal_procedures: tx_proposal_procedures,
    id,
    votes: tx_votes,
    current_treasury_amount,
    treasury_donation,
    ..
  } = tx
  let AddProposalBodyWitness {
    ttl,
    certificates,
    auxiliary_data_hash,
    validity_start,
    collateral_inputs,
    collateral_return,
    total_collateral,
    voting_procedures,
    proposal_anchor_url,
    proposal_anchor_data_hash,
  } = body_witness

  expect Input {
    output: Output {
      value: gov_action_lifespan_value,
      datum: InlineDatum(gov_action_lifespan_data),
      ..
    },
    ..
  } =
    reference_inputs
      |> list.expect_at(gov_action_lifespan_reference_input_index)

  expect
    gov_action_lifespan_value
      |> assets.has_nft_strict(
          gov_action_lifespan_policy,
          gov_action_lifespan_asset_name,
        )
  expect gov_action_lifespan: Int = gov_action_lifespan_data

  // 1. Transaction's validity interval must be bound with a short span.
  expect Interval {
    lower_bound: IntervalBound {
      bound_type: Finite(validity_range_lower_bound),
      ..
    },
    upper_bound: IntervalBound {
      bound_type: Finite(validity_range_upper_bound),
      ..
    },
  } = validity_range
  expect
    validity_range_upper_bound - validity_range_lower_bound <= max_validity_range_span

  {
    let
      _anchor_input,
      anchor_lovelace_change,
      _anchor_key,
      _anchor_data,
      _proposal_node_lovelace,
      proposal_key,
      proposal_data,
      _link,
    <-
      linked_list.insert_ascending(
        outputs |> list.expect_at(anchor_output_index),
        outputs |> list.expect_at(proposal_node_output_index),
        inputs,
        mint,
      )

    // 2. Lovelace of the anchor element must be preserved.
    expect anchor_lovelace_change >= 0

    // 3. Proposal node's underlying data must be valid. No meaningful
    //    validations can be performed on subject and required wihtdrawal
    //    scripts, and are ignored. Minting PASS tokens outside the list
    //    namespace prevents these scripts from blocking their builtin indexes.
    expect Proposal {
      proposer,
      gov_action_script_data_hash,
      cost_model_prefix,
      acceptance_builtin_cost,
      cost_model_postfix,
      valid_until,
      subject_script_hash: _,
      required_script_for_final_burn: _,
    } = proposal_data

    // 4. The proposer's address must have an inline staking credential so it
    //    can match the governance action's return credential.
    expect Address {
      stake_credential: Some(Inline(proposer_stake_credential)),
      ..
    } = proposer

    // 5. The new cost must be the initial cost incremented or decremented by 1.
    expect or {
        acceptance_builtin_cost == initial_builtin_cost + 1,
        acceptance_builtin_cost == initial_builtin_cost - 1,
      }

    // 6. Expiry of the proposal node is determined by the lifespan in the
    //    multisig-controlled configuration UTxO selected as a reference input.
    expect valid_until == validity_range_upper_bound + gov_action_lifespan

    // 7. Only one proposal procedure must exist in the transaction.
    expect [ProposalProcedure { deposit, return_address, governance_action }] =
      tx_proposal_procedures

    // 8. The deposit reward address must match the stake credential of the
    //    proposer's address.
    expect return_address == proposer_stake_credential

    expect ProtocolParameters { ancestor, new_parameters, guardrails } =
      governance_action

    // 9. The builtin's index is derived from the node's key. The array header
    //    must declare an element at that index, and the prefix must end exactly
    //    after all complete integer entries preceding it.
    let builtin_index = builtin_index_from_node_key(proposal_key)
    expect validate_cost_model_prefix(cost_model_prefix, builtin_index)

    // 10. The proposed cost model for this contract's Plutus language must
    //     preserve every non-target entry and replace only the selected builtin
    //     cost.
    expect Some(raw_cost_models) =
      protocol_parameters.cost_models(new_parameters)
    let expected_proposed_cost_model =
      splice_cost_model(
        cost_model_prefix,
        acceptance_builtin_cost,
        cost_model_postfix,
      )
    expect
      raw_cost_models_to_ledger_encoding(raw_cost_models, cost_model_prefix) == expected_proposed_cost_model

    // 11. Reconstruct the sole ledger proposal procedure. Its anchor is absent
    //     from the script context and supplied by the insertion redeemer.
    let serialised_reward_account =
      serialise_reward_account(network_tag, return_address)
    let serialised_ancestor =
      when ancestor is {
        None -> #"f6"
        Some(action_id) -> serialise_governance_action_id(action_id)
      }
    // The reconstructed action contains exactly one parameter update: the
    // singleton cost-model map at protocol-parameter index 18.
    // Any other shape produces a different transaction ID.
    let serialised_new_parameters =
      #"a112a1"
        |> bytearray.concat(serialised_plutus_language_id)
        |> bytearray.concat(expected_proposed_cost_model)
    let serialised_guardrails =
      when guardrails is {
        None -> #"f6"
        Some(script_hash) -> cbor.serialise(script_hash)
      }
    let serialised_anchor =
      serialise_list_of_two(
        serialise_cbor_text(proposal_anchor_url),
        serialise_cbor_bytes(proposal_anchor_data_hash),
      )
    let serialised_proposal_procedures =
      set_cbor_tag
        |> bytearray.concat(singleton_cbor_list)
        |> bytearray.concat(#"84")
        |> bytearray.concat(cbor.serialise(deposit))
        |> bytearray.concat(serialised_reward_account)
        |> bytearray.concat(#"8400")
        |> bytearray.concat(serialised_ancestor)
        |> bytearray.concat(serialised_new_parameters)
        |> bytearray.concat(serialised_guardrails)
        |> bytearray.concat(serialised_anchor)

    // 12. Reconstruct the live baseline model and validate the claimed script
    //     data hash from the proposal datum.
    let baseline_cost_model =
      splice_cost_model(
        cost_model_prefix,
        initial_builtin_cost,
        cost_model_postfix,
      )
    expect
      validate_script_data_hash_from_metadata(
        gov_action_script_data_hash,
        baseline_cost_model,
        redeemers,
        redeemer_metadata,
        redeemer_encoding,
        other_language_cost_models,
      )

    // 13. Validate `gov_action_script_data_hash` leads to the current
    //     transaction ID.
    expect
      validate_tx_id_from_script_data_hash_with_proposal_procedures(
        id,
        gov_action_script_data_hash,
        inputs,
        reference_inputs,
        outputs,
        network_tag,
        fee,
        mint,
        tx_certificates,
        withdrawals,
        extra_signatories,
        tx_votes,
        current_treasury_amount,
        treasury_donation,
        ttl,
        certificates,
        auxiliary_data_hash,
        validity_start,
        collateral_inputs,
        collateral_return,
        total_collateral,
        voting_procedures,
        serialised_proposal_procedures,
      )

    // Done.
    True
  }
    |> linked_list.run_element_with(
        governance_nft_policy,
        root_key,
        node_key_prefix,
        node_key_prefix_length,
      )
}

pub fn mint_passed_proposal(
  network_tag: Int,
  governance_nft_policy: PolicyId,
  //
  redeemer_encoding: RedeemerEncoding,
  anchor_input_outref: OutputReference,
  anchor_output_index: Int,
  passed_proposal_output_index: Int,
  anchor_spend_redeemer_index: Int,
  proposal_spend_redeemer_index: Int,
  anchor_spend_cpu: Int,
  anchor_spend_mem: Int,
  node_spend_cpu: Int,
  node_spend_mem: Int,
  mint_cpu: Int,
  mint_mem: Int,
  ttl: Int,
  collateral_inputs: ByteArray,
  collateral_output: ByteArray,
  collateral_fee: ByteArray,
  //
  redeemer: MintRedeemer,
  tx: Transaction,
) -> Bool {
  let Transaction {
    inputs,
    outputs,
    mint,
    reference_inputs,
    extra_signatories,
    fee,
    id,
    validity_range,
    ..
  } = tx

  let continued_anchor_output = outputs |> list.expect_at(anchor_output_index)

  expect Output {
    address: passed_proposal_address,
    value: passed_proposal_value,
    datum: InlineDatum(passed_proposal_data),
    reference_script: None,
  } = outputs |> list.expect_at(passed_proposal_output_index)

  // 1. Produced passed UTxO must have a properly shaped datum attached.
  expect PassedProposal {
    proposer,
    passed_proposal_script_data_hash,
    required_script_for_final_burn: passed_required_script_for_final_burn,
  } = passed_proposal_data

  {
    let
      _anchor_input,
      anchor_element_lovelace_change,
      _anchor_key,
      root_data,
      cont_root_data,
      removing_node_input,
      removing_node_lovelace,
      _removing_node_key,
      removing_node_data,
      _removing_node_link,
      other_list_asset_changes,
    <-
      advanced_linked_list.remove(
        anchor_input_outref,
        continued_anchor_output,
        inputs,
        mint,
      )

    let Input { output: Output { address: removing_node_address, .. }, .. } =
      removing_node_input

    // 2. The new `PASS` UTxO must go to the same address as its proposal UTxO.
    expect removing_node_address == passed_proposal_address

    // 3. ADA of the anchor must be preserved.
    expect anchor_element_lovelace_change >= 0

    // 4. Underlying data of the anchor must not change.
    expect root_data == cont_root_data

    // 5. There must be exactly one other mint under list policy (aside from the
    //    node's burn).
    expect [Pair(minted_pass_token_name, 1)] =
      other_list_asset_changes |> dict.to_pairs

    // 6. The new UTxO must carry the subject-withdrawal-bound `PASS` token, plus
    //    some ADA greater than or equal to the removing node's (no other tokens
    //    are allowed).
    expect
      passed_proposal_value
        |> assets.has_nft_strict(governance_nft_policy, minted_pass_token_name)
    expect assets.lovelace_of(passed_proposal_value) >= removing_node_lovelace

    // 7. The authenticated removed proposal supplies the stable subject
    //    withdrawal. The PASS name must not be derived from the node key,
    //    redeemer, or new output.
    expect Proposal {
      proposer: original_proposer,
      subject_script_hash,
      cost_model_prefix,
      acceptance_builtin_cost,
      cost_model_postfix,
      valid_until,
      required_script_for_final_burn,
      ..
    } = removing_node_data
    expect
      minted_pass_token_name == passed_proposal_asset_name(subject_script_hash)

    // 8. The new builtin cost must match the initially stated approval
    //    criteria. The proposer and dynamic final-action withdrawal must also
    //    carry over to the new UTxO.
    expect original_proposer == proposer
    let accepted_cost_model =
      splice_cost_model(
        cost_model_prefix,
        acceptance_builtin_cost,
        cost_model_postfix,
      )
    expect
      required_script_for_final_burn == passed_required_script_for_final_burn
    expect validity_range |> interval.is_entirely_before(valid_until)

    // 9. Validate the specified script data match the hash.
    expect
      validate_pass_script_data_hash(
        passed_proposal_script_data_hash,
        accepted_cost_model,
        anchor_spend_cpu,
        anchor_spend_mem,
        node_spend_cpu,
        node_spend_mem,
        mint_cpu,
        mint_mem,
        anchor_spend_redeemer_index,
        proposal_spend_redeemer_index,
        redeemer_encoding,
        redeemer,
      )

    // 10. Validate `passed_proposal_script_data_hash` leads to the current
    //     transaction ID.
    expect
      id
        |> validate_tx_id_from_script_data_hash_with_mint(
            passed_proposal_script_data_hash,
            inputs,
            reference_inputs,
            outputs,
            network_tag,
            fee,
            ttl,
            mint,
            extra_signatories,
            collateral_inputs,
            collateral_output,
            collateral_fee,
          )

    // Done.
    True
  }
    |> linked_list.run_element_with(
        governance_nft_policy,
        root_key,
        node_key_prefix,
        node_key_prefix_length,
      )
}

pub fn finalize_passed_proposal(
  governance_nft_policy: PolicyId,
  //
  proposer_output_index: Int,
  subject_withdrawal_index: Int,
  required_script_withdrawal_index: Int,
  //
  tx: Transaction,
) -> Bool {
  let Transaction { inputs, outputs, mint, withdrawals, .. } = tx

  // 1. There must be exactly one input carrying a token under the governance
  //    list policy. It must be a strict singleton policy-token UTxO with an
  //    inline datum.
  let
    _passed_input,
    passed_utxo_lovelace,
    passed_proposal_token_name,
    passed_proposal_datum_data,
  <- validate_singular_authentic_input_helper(inputs, governance_nft_policy)

  // 2. The token name must be `PASS` followed by one canonical script hash.
  //    No other paths allow minting of `PASS` tokens, so we can rely on the
  //    assumption that the rest of the asset name is indeed 28 bytes.
  expect
    bytearray.take(passed_proposal_token_name, passed_proposal_prefix_length) == passed_proposal_prefix
  let subject_script_hash =
    bytearray.drop(passed_proposal_token_name, passed_proposal_prefix_length)

  // 3. The `PASS` token must be burnt, with no other minting or burning under
  //    the governance policy. Other policies remain unrestricted.
  expect [Pair(burnt_token_name, burn_quantity)] =
    mint |> assets.tokens(governance_nft_policy) |> dict.to_pairs
  expect and {
      burn_quantity == -1,
      burnt_token_name == passed_proposal_token_name,
    }

  // 4. The `PASS` UTxO datum provides the proposer and the dynamic final-action
  //    withdrawal script.
  expect PassedProposal { proposer, required_script_for_final_burn, .. } =
    passed_proposal_datum_data

  // 5. The final action must execute independently of the stable subject
  //    authorization.
  expect required_script_for_final_burn != subject_script_hash

  // 6. The proposer must receive a pure ADA output carrying at least the
  //    finalized `PASS` UTxO's lovelace. No datum, no reference script.
  expect
    outputs
      |> list.expect_at(proposer_output_index)
      |> validate_proposer_reimbursement(proposer, passed_utxo_lovelace)

  // 7. The stable subject withdrawal encoded after `PASS` must execute.
  expect
    stake_validator.validate_withdraw_minimal(
      withdraw_script_hash: subject_script_hash,
      withdrawals: withdrawals,
      withdrawal_index: subject_withdrawal_index,
    )

  // 8. The proposal-specific final-action withdrawal must also execute.
  expect
    stake_validator.validate_withdraw_minimal(
      withdraw_script_hash: required_script_for_final_burn,
      withdrawals: withdrawals,
      withdrawal_index: required_script_withdrawal_index,
    )

  // Done.
  True
}

pub fn remove_expired_proposal(
  anchor_input_outref: OutputReference,
  anchor_output_index: Int,
  proposer_output_index: Int,
  governance_nft_policy: PolicyId,
  tx: Transaction,
) -> Bool {
  let Transaction { inputs, outputs, mint, validity_range, .. } = tx

  {
    let
      _anchor_input,
      anchor_element_lovelace_change,
      _anchor_key,
      _anchor_data,
      _removing_node_input,
      removing_node_lovelace,
      _removing_node_key,
      removing_node_data,
      _removing_node_link,
    <-
      linked_list.remove(
        anchor_input_outref,
        outputs |> list.expect_at(anchor_output_index),
        inputs,
        mint,
      )

    // 1. Anchor element's ADA must be preserved.
    expect anchor_element_lovelace_change >= 0

    // 2. The proposal's deadline must have passed.
    expect Proposal { proposer, valid_until, .. } = removing_node_data
    expect validity_range |> interval.is_entirely_after(valid_until)

    // 3. The proposer must receive a pure-ADA output carrying at least the
    //    removed proposal's lovelace, with no datum or reference script.
    expect
      outputs
        |> list.expect_at(proposer_output_index)
        |> validate_proposer_reimbursement(proposer, removing_node_lovelace)

    // Done.
    True
  }
    |> linked_list.run_element_with(
        governance_nft_policy,
        root_key,
        node_key_prefix,
        node_key_prefix_length,
      )
}

fn validate_proposer_reimbursement(
  proposer_output: Output,
  proposer: Address,
  minimum_lovelace: Lovelace,
) -> Bool {
  // 1. The reimbursement output must have no datum or reference script.
  expect Output {
    address: proposer_output_address,
    value: proposer_output_value,
    datum: NoDatum,
    reference_script: None,
  } = proposer_output

  let proposer_output_lovelace = assets.lovelace_of(proposer_output_value)

  // 2. The reimbursement must go to the proposer.
  expect proposer_output_address == proposer

  // 3. The reimbursement output must contain only ADA.
  expect proposer_output_value == assets.from_lovelace(proposer_output_lovelace)

  // 4. The reimbursement must cover the removed UTxO's lovelace.
  expect proposer_output_lovelace >= minimum_lovelace

  // Done.
  True
}

/// Decode a builtin index from an enforced four-byte node key (big-endian).
fn builtin_index_from_node_key(node_key: linked_list.NodeKey) -> Int {
  expect node_key_byte_count == bytearray.length(node_key)
  bytearray.to_int_big_endian(node_key)
}

/// Construct the exact subject-withdrawal-bound asset name for a passed
/// proposal. Proposal admission ensures the supplied script hash is 28 bytes.
pub fn passed_proposal_asset_name(subject_script_hash: ScriptHash) -> AssetName {
  bytearray.concat(passed_proposal_prefix, subject_script_hash)
}

/// Require a passed-proposal burn whose suffix is a withdrawal script
/// recognized by the subject contract. Minting and burning under every other
/// policy remain unrestricted.
pub fn validate_recognized_pass_burn(
  governance_nft_policy: PolicyId,
  recognized_script_hash: ScriptHash,
  governance_finalize_redeemer_index: Int,
  mint: Value,
  redeemers: Pairs<ScriptPurpose, Redeemer>,
) -> Bool {
  // 1. There must be exactly 1 NFT being burnt under the governance policy,
  //    with its asset name being under the `PASS` namespace.
  expect [Pair(burnt_token_name, burn_quantity)] =
    mint |> assets.tokens(governance_nft_policy) |> dict.to_pairs
  expect burn_quantity == -1
  expect burnt_token_name == passed_proposal_asset_name(recognized_script_hash)

  // 2. The specified context index must point to the governance finalization
  //    endpoint. Passage execution witnesses are authenticated by the
  //    governance minting transition and are not needed here.
  expect Pair(Mint(invoked_mint_script_hash), governance_finalize_redeemer_data) =
    redeemers |> list.expect_at(governance_finalize_redeemer_index)
  expect invoked_mint_script_hash == governance_nft_policy
  expect FinalizePassedProposal { .. } = governance_finalize_redeemer_data

  // Done.
  True
}

fn validate_script_data_hash_from_metadata(
  script_data_hash: ByteArray,
  cost_model: ByteArray,
  tx_redeemers: Pairs<ScriptPurpose, Data>,
  redeemer_metadata: List<RedeemerMetadata>,
  redeemer_encoding: RedeemerEncoding,
  other_language_cost_models: List<LanguageCostModel>,
) -> Bool {
  let entries = collect_redeemer_entries(redeemer_metadata, tx_redeemers, [])
  let serialised_redeemers =
    serialise_redeemer_entries(entries, redeemer_encoding)
  let language_views =
    serialise_language_views(cost_model, other_language_cost_models)

  builtin.blake2b_256(bytearray.concat(serialised_redeemers, language_views)) == script_data_hash
}

fn serialise_language_views(
  cost_model: ByteArray,
  other_language_cost_models: List<LanguageCostModel>,
) -> ByteArray {
  let entries =
    list.foldl(
      other_language_cost_models,
      [Pair(serialised_plutus_language_id, cost_model)],
      fn(language_cost_model, entries) {
        let LanguageCostModel { language_id, cost_model: other_cost_model } =
          language_cost_model
        entries
          |> insert_stable_canonical_map_entry(
              cbor.serialise(language_id),
              other_cost_model,
            )
      },
    )

  serialise_canonical_map_entries(entries)
}

fn collect_redeemer_entries(
  metadata: List<RedeemerMetadata>,
  tx_redeemers: Pairs<ScriptPurpose, Data>,
  entries: Pairs<ByteArray, Pair<ByteArray, ByteArray>>,
) -> Pairs<ByteArray, Pair<ByteArray, ByteArray>> {
  when metadata is {
    [] -> entries
    [RedeemerMetadata { context_index, ledger_index, mem, cpu }, ..tail] -> {
      let Pair(purpose, data) = tx_redeemers |> list.expect_at(context_index)
      let tag = redeemer_tag(purpose)

      collect_redeemer_entries(
        tail,
        tx_redeemers,
        entries
          |> insert_redeemer_entry(
              tag,
              ledger_index,
              serialise_plutus_data(data),
              serialise_budget(mem, cpu),
            ),
      )
    }
  }
}

fn redeemer_tag(purpose: ScriptPurpose) -> Int {
  when purpose is {
    transaction.Spend(_) -> 0
    transaction.Mint(_) -> 1
    transaction.Publish { .. } -> 2
    transaction.Withdraw(_) -> 3
    transaction.Vote(_) -> 4
    transaction.Propose { .. } -> 5
  }
}

fn validate_script_data_hash(
  script_data_hash: ByteArray,
  cost_model: ByteArray,
  redeemers: ByteArray,
) -> Bool {
  let language_views =
    #"a1"
      |> bytearray.concat(serialised_plutus_language_id)
      |> bytearray.concat(cost_model)

  builtin.blake2b_256(bytearray.concat(redeemers, language_views)) == script_data_hash
}

pub fn validate_pass_script_data_hash(
  script_data_hash: ByteArray,
  cost_model: ByteArray,
  anchor_spend_cpu: Int,
  anchor_spend_mem: Int,
  proposal_spend_cpu: Int,
  proposal_spend_mem: Int,
  mint_cpu: Int,
  mint_mem: Int,
  anchor_spend_redeemer_index: Int,
  proposal_spend_redeemer_index: Int,
  redeemer_encoding: RedeemerEncoding,
  mint_redeemer: MintRedeemer,
) -> Bool {
  let spend_redeemer: SpendRedeemer = DelegateToMint
  let spend_redeemer_data = serialise_plutus_data(spend_redeemer)
  let anchor_spend_budget = serialise_budget(anchor_spend_mem, anchor_spend_cpu)
  let proposal_spend_budget =
    serialise_budget(proposal_spend_mem, proposal_spend_cpu)

  let redeemers =
    []
      |> insert_redeemer_entry(
          0,
          anchor_spend_redeemer_index,
          spend_redeemer_data,
          anchor_spend_budget,
        )
      |> insert_redeemer_entry(
          0,
          proposal_spend_redeemer_index,
          spend_redeemer_data,
          proposal_spend_budget,
        )
      |> insert_redeemer_entry(
          1,
          0,
          serialise_plutus_data(mint_redeemer),
          serialise_budget(mint_mem, mint_cpu),
        )
      |> serialise_redeemer_entries(redeemer_encoding)

  validate_script_data_hash(script_data_hash, cost_model, redeemers)
}

/// Transaction-body reconstruction is primarily referenced from Effectstream's
/// inverse-whirlpool implementation at:
/// https://github.com/effectstream/effectstream/blob/0b70d63a217676ce52748a2cd267f5cbed1109e4/packages/cardano-contracts/inverse-whirlpool/validators/whirl.ak#L261-L291
/// https://github.com/effectstream/effectstream/blob/0b70d63a217676ce52748a2cd267f5cbed1109e4/packages/cardano-contracts/inverse-whirlpool/lib/inverse_whirlpool/conversion.ak#L12-L126
/// `network_tag` is the four-bit tag encoded in every reconstructed output
/// address.
pub fn validate_tx_id_from_script_data_hash_with_mint(
  tx_id: ByteArray,
  script_data_hash: ByteArray,
  inputs: List<Input>,
  reference_inputs: List<Input>,
  outputs: List<Output>,
  network_tag: Int,
  fee: Lovelace,
  ttl: Int,
  mint: Value,
  extra_signatories: List<VerificationKeyHash>,
  collateral_inputs: ByteArray,
  collateral_output: ByteArray,
  collateral_fee: ByteArray,
) -> Bool {
  let fields_before_script_data_hash =
    mint_cbor_key |> bytearray.concat(cbor.serialise(assets.to_dict(mint)))
  let fields_after_collateral_inputs =
    #"0e"
      |> bytearray.concat(serialise_extra_signatories(extra_signatories))
      |> bytearray.concat(#"10")
      |> bytearray.concat(collateral_output)
      |> bytearray.concat(#"11")
      |> bytearray.concat(collateral_fee)
      |> bytearray.concat(#"12")
      |> bytearray.concat(serialise_tx_inputs(reference_inputs))

  do_validate_tx_id_from_script_data_hash(
    tx_id,
    script_data_hash,
    inputs,
    outputs,
    network_tag,
    fee,
    ttl,
    #"ab",
    fields_before_script_data_hash,
    collateral_inputs,
    fields_after_collateral_inputs,
  )
}

pub fn validate_tx_id_from_script_data_hash_with_proposal_procedures(
  tx_id: ByteArray,
  script_data_hash: ByteArray,
  inputs: List<Input>,
  reference_inputs: List<Input>,
  outputs: List<Output>,
  network_tag: Int,
  fee: Lovelace,
  mint: Value,
  tx_certificates: List<Certificate>,
  withdrawals: Pairs<Credential, Lovelace>,
  extra_signatories: List<VerificationKeyHash>,
  tx_votes: Pairs<Voter, Pairs<GovernanceActionId, Vote>>,
  current_treasury_amount: Option<Lovelace>,
  treasury_donation: Option<Lovelace>,
  ttl: Int,
  certificates: ByteArray,
  auxiliary_data_hash: Option<ByteArray>,
  validity_start: Int,
  collateral_inputs: ByteArray,
  collateral_return: ByteArray,
  total_collateral: ByteArray,
  voting_procedures: ByteArray,
  serialised_proposal_procedures: ByteArray,
) -> Bool {
  let
    field_4_count,
    field_4,
  <- serialise_nonempty_list_field(4, tx_certificates, fn(_) { certificates })
  let
    field_5_count,
    field_5,
  <-
    serialise_nonempty_list_field(
      5,
      withdrawals,
      fn(withdrawals) { serialise_withdrawals(withdrawals, network_tag) },
    )
  let
    field_7_count,
    field_7,
  <-
    serialise_optional_field(
      7,
      auxiliary_data_hash,
      fn(hash) { serialise_cbor_bytes(hash) },
    )
  let field_8 = #"08" |> bytearray.concat(cbor.serialise(validity_start))
  let
    field_9_count,
    field_9,
  <-
    if mint == assets.zero {
      fn(return) { return(0, "") }
    } else {
      fn(return) {
        return(1, mint_cbor_key |> bytearray.concat(serialise_mint(mint)))
      }
    }
  let
    field_14_count,
    field_14,
  <-
    serialise_nonempty_list_field(
      14,
      extra_signatories,
      fn(extra_signatories) { serialise_extra_signatories(extra_signatories) },
    )
  let
    field_18_count,
    field_18,
  <-
    serialise_nonempty_list_field(
      18,
      reference_inputs,
      fn(reference_inputs) { serialise_tx_inputs(reference_inputs) },
    )
  let
    field_19_count,
    field_19,
  <- serialise_nonempty_list_field(19, tx_votes, fn(_) { voting_procedures })
  let
    field_21_count,
    field_21,
  <-
    serialise_optional_field(
      21,
      current_treasury_amount,
      fn(value) { cbor.serialise(value) },
    )
  let
    field_22_count,
    field_22,
  <-
    serialise_optional_field(
      22,
      treasury_donation,
      fn(value) { cbor.serialise(value) },
    )

  let body_field_count =
    10 + field_4_count + field_5_count + field_7_count + field_9_count + field_14_count + field_18_count + field_19_count + field_21_count + field_22_count
  let fields_before_script_data_hash =
    field_4
      |> bytearray.concat(field_5)
      |> bytearray.concat(field_7)
      |> bytearray.concat(field_8)
      |> bytearray.concat(field_9)
  let fields_after_collateral_inputs =
    field_14
      |> bytearray.concat(#"10")
      |> bytearray.concat(collateral_return)
      |> bytearray.concat(#"11")
      |> bytearray.concat(total_collateral)
      |> bytearray.concat(field_18)
      |> bytearray.concat(field_19)
      |> bytearray.concat(#"14")
      |> bytearray.concat(serialised_proposal_procedures)
      |> bytearray.concat(field_21)
      |> bytearray.concat(field_22)

  do_validate_tx_id_from_script_data_hash(
    tx_id,
    script_data_hash,
    inputs,
    outputs,
    network_tag,
    fee,
    ttl,
    serialise_cbor_head(5, body_field_count),
    fields_before_script_data_hash,
    collateral_inputs,
    fields_after_collateral_inputs,
  )
}

/// Reconstruct the transaction-body fields common to the supported mint and
/// proposal transaction shapes. Callers provide the CBOR regions between TTL
/// and the script-data hash, and after the collateral-inputs field.
fn do_validate_tx_id_from_script_data_hash(
  tx_id: ByteArray,
  script_data_hash: ByteArray,
  inputs: List<Input>,
  outputs: List<Output>,
  network_tag: Int,
  fee: Lovelace,
  ttl: Int,
  tx_body_map_header: ByteArray,
  fields_before_script_data_hash: ByteArray,
  collateral_inputs: ByteArray,
  fields_after_collateral_inputs: ByteArray,
) -> Bool {
  expect network_tag >= 0 && network_tag <= 15

  let serialised_inputs = serialise_tx_inputs(inputs)
  let serialised_outputs = serialise_tx_outputs(outputs, network_tag)
  let serialised_fee = cbor.serialise(fee)
  let serialised_script_data_hash = cbor.serialise(script_data_hash)

  let tx_body =
    tx_body_map_header
      |> bytearray.concat(#"00")
      |> bytearray.concat(serialised_inputs)
      |> bytearray.concat(#"01")
      |> bytearray.concat(serialised_outputs)
      |> bytearray.concat(#"02")
      |> bytearray.concat(serialised_fee)
      |> bytearray.concat(#"03")
      |> bytearray.concat(cbor.serialise(ttl))
      |> bytearray.concat(fields_before_script_data_hash)
      |> bytearray.concat(#"0b")
      |> bytearray.concat(serialised_script_data_hash)
      |> bytearray.concat(#"0d")
      |> bytearray.concat(collateral_inputs)
      |> bytearray.concat(fields_after_collateral_inputs)

  builtin.blake2b_256(tx_body) == tx_id
}

// ## Internal Helpers

fn serialise_list_of_two(
  serialised_elem_0: ByteArray,
  serialised_elem_1: ByteArray,
) -> ByteArray {
  #"82"
    |> bytearray.concat(serialised_elem_0)
    |> bytearray.concat(serialised_elem_1)
}

fn serialise_budget(mem: Int, cpu: Int) -> ByteArray {
  serialise_list_of_two(cbor.serialise(mem), cbor.serialise(cpu))
}

fn insert_redeemer_entry(
  entries: Pairs<ByteArray, Pair<ByteArray, ByteArray>>,
  tag: Int,
  index: Int,
  redeemer_data: ByteArray,
  budget: ByteArray,
) -> Pairs<ByteArray, Pair<ByteArray, ByteArray>> {
  let serialised_tag = cbor.serialise(tag)
  let serialised_index = cbor.serialise(index)
  let pointer = serialise_list_of_two(serialised_tag, serialised_index)

  // Tags are single-byte values 0 through 5, and ledger indices are
  // non-negative shortest-form integers, so bytewise key order is the
  // ledger's tag-then-index pointer order.
  entries
    |> pairs.insert_by_ascending_key(
        pointer,
        Pair(redeemer_data, budget),
        bytearray.compare,
      )
}

fn serialise_redeemer_entries(
  entries: Pairs<ByteArray, Pair<ByteArray, ByteArray>>,
  redeemer_encoding: RedeemerEncoding,
) -> ByteArray {
  when redeemer_encoding is {
    ListEncoding -> {
      // The pointer is `82 || tag || index`; list entries replace that
      // two-element-array header with their four-element-array header.
      let
        length,
        body,
      <-
        list.foldr2(
          entries,
          0,
          "",
          fn(entry, length, body, return) {
            let Pair(pointer, Pair(redeemer_data, budget)) = entry
            return(
              length + 1,
              #"84"
                |> bytearray.concat(bytearray.drop(pointer, 1))
                |> bytearray.concat(redeemer_data)
                |> bytearray.concat(budget)
                |> bytearray.concat(body),
            )
          },
        )

      serialise_definite_list(length, body)
    }
    MapEncoding -> {
      let
        length,
        body,
      <-
        list.foldr2(
          entries,
          0,
          "",
          fn(entry, length, body, return) {
            let Pair(pointer, Pair(redeemer_data, budget)) = entry
            return(
              length + 1,
              pointer
                |> bytearray.concat(
                    serialise_list_of_two(redeemer_data, budget),
                  )
                |> bytearray.concat(body),
            )
          },
        )

      serialise_cbor_head(5, length) |> bytearray.concat(body)
    }
  }
}

fn serialise_optional_field(
  key: Int,
  value: Option<a>,
  serialise: fn(a) -> ByteArray,
  return: fn(Int, ByteArray) -> result,
) -> result {
  when value is {
    None -> return(0, "")
    Some(value) ->
      return(1, cbor.serialise(key) |> bytearray.concat(serialise(value)))
  }
}

fn serialise_nonempty_list_field(
  key: Int,
  values: List<a>,
  serialise: fn(List<a>) -> ByteArray,
  return: fn(Int, ByteArray) -> result,
) -> result {
  when values is {
    [] -> return(0, "")
    _ -> return(1, cbor.serialise(key) |> bytearray.concat(serialise(values)))
  }
}

fn canonical_cbor_key_compare(left: ByteArray, right: ByteArray) -> Ordering {
  let left_length = bytearray.length(left)
  let right_length = bytearray.length(right)

  if left_length < right_length {
    Less
  } else if left_length > right_length {
    Greater
  } else {
    bytearray.compare(left, right)
  }
}

fn insert_canonical_map_entry(
  entries: Pairs<ByteArray, ByteArray>,
  key: ByteArray,
  value: ByteArray,
) -> Pairs<ByteArray, ByteArray> {
  entries
    |> pairs.insert_by_ascending_key(key, value, canonical_cbor_key_compare)
}

fn insert_canonical_set_entry(
  entries: Pairs<ByteArray, ByteArray>,
  item: ByteArray,
) -> Pairs<ByteArray, ByteArray> {
  when entries is {
    [] -> [Pair(item, "")]
    [entry, ..tail] -> {
      let Pair(entry_item, _) = entry
      when bytearray.compare(item, entry_item) is {
        Less -> [Pair(item, ""), ..entries]
        Equal -> entries
        Greater -> [entry, ..insert_canonical_set_entry(tail, item)]
      }
    }
  }
}

/// Plutus maps preserve duplicate entries. Sort by canonical CBOR key while
/// retaining the source order of entries whose encoded keys are equal.
fn insert_stable_canonical_map_entry(
  entries: Pairs<ByteArray, ByteArray>,
  key: ByteArray,
  value: ByteArray,
) -> Pairs<ByteArray, ByteArray> {
  when entries is {
    [] -> [Pair(key, value)]
    [entry, ..tail] -> {
      let Pair(entry_key, _) = entry
      when canonical_cbor_key_compare(key, entry_key) is {
        Less -> [Pair(key, value), ..entries]
        _ -> [entry, ..insert_stable_canonical_map_entry(tail, key, value)]
      }
    }
  }
}

fn serialise_canonical_map_entries(
  entries: Pairs<ByteArray, ByteArray>,
) -> ByteArray {
  let
    length,
    body,
  <-
    list.foldr2(
      entries,
      0,
      "",
      fn(entry, length, body, return) {
        return(
          length + 1,
          entry.1st
            |> bytearray.concat(entry.2nd)
            |> bytearray.concat(body),
        )
      },
    )

  serialise_cbor_head(5, length) |> bytearray.concat(body)
}

fn serialise_tx_inputs(inputs: List<Input>) -> ByteArray {
  let
    length,
    body,
  <-
    list.foldr2(
      inputs,
      0,
      "",
      fn(input, length, body, return) {
        return(
          length + 1,
          bytearray.concat(
            serialise_output_reference(input.output_reference),
            body,
          ),
        )
      },
    )

  set_cbor_tag
    |> bytearray.concat(serialise_definite_list(length, body))
}

fn serialise_output_reference(ref: OutputReference) -> ByteArray {
  let OutputReference { transaction_id, output_index } = ref

  #"82"
    |> bytearray.concat(cbor.serialise(transaction_id))
    |> bytearray.concat(cbor.serialise(output_index))
}

fn serialise_tx_outputs(outputs: List<Output>, network_tag: Int) -> ByteArray {
  let
    length,
    body,
  <-
    list.foldr2(
      outputs,
      0,
      "",
      fn(output, length, body, return) {
        return(
          length + 1,
          bytearray.concat(serialise_tx_output(output, network_tag), body),
        )
      },
    )

  serialise_definite_list(length, body)
}

fn serialise_tx_output(output: Output, network_tag: Int) -> ByteArray {
  let Output { address, value, datum, .. } = output
  let serialised_address = serialise_address(address, network_tag)
  let serialised_value = serialise_output_value(value)

  when datum is {
    NoDatum ->
      #"82"
        |> bytearray.concat(serialised_address)
        |> bytearray.concat(serialised_value)
    DatumHash(_) -> fail @"datum hashes are unsupported"
    InlineDatum(data) ->
      #"a3"
        |> bytearray.concat(#"00")
        |> bytearray.concat(serialised_address)
        |> bytearray.concat(#"01")
        |> bytearray.concat(serialised_value)
        |> bytearray.concat(
            serialise_inline_output_datum(serialise_plutus_data(data)),
          )
  }
}

fn serialise_verification_key_hash_set(
  hashes: List<VerificationKeyHash>,
) -> ByteArray {
  let entries =
    list.foldl(
      hashes,
      [],
      fn(hash, entries) {
        insert_canonical_set_entry(entries, serialise_cbor_bytes(hash))
      },
    )
  let length, body <- serialise_set_entries(entries)
  set_cbor_tag
    |> bytearray.concat(serialise_definite_list(length, body))
}

fn serialise_set_entries(
  entries: Pairs<ByteArray, ByteArray>,
  return: fn(Int, ByteArray) -> result,
) -> result {
  list.foldr2(
    entries,
    0,
    "",
    fn(entry, length, body, next) {
      next(length + 1, entry.1st |> bytearray.concat(body))
    },
    return,
  )
}

fn serialise_cbor_text(text: ByteArray) -> ByteArray {
  serialise_cbor_head(3, bytearray.length(text)) |> bytearray.concat(text)
}

fn serialise_reward_account(
  network_tag: Int,
  credential: Credential,
) -> ByteArray {
  let bytes =
    when credential is {
      VerificationKey(hash) -> builtin.cons_bytearray(0xe0 + network_tag, hash)
      Script(hash) -> builtin.cons_bytearray(0xf0 + network_tag, hash)
    }
  serialise_cbor_bytes(bytes)
}

fn serialise_withdrawals(
  withdrawals: Pairs<Credential, Lovelace>,
  network_tag: Int,
) -> ByteArray {
  let entries =
    list.foldl(
      withdrawals,
      [],
      fn(withdrawal, entries) {
        let Pair(credential, amount) = withdrawal
        entries
          |> insert_canonical_map_entry(
              serialise_reward_account(network_tag, credential),
              cbor.serialise(amount),
            )
      },
    )
  serialise_canonical_map_entries(entries)
}

fn serialise_governance_action_id(action_id: GovernanceActionId) -> ByteArray {
  let GovernanceActionId { transaction, proposal_procedure } = action_id
  serialise_list_of_two(
    serialise_cbor_bytes(transaction),
    cbor.serialise(proposal_procedure),
  )
}

fn serialise_inline_output_datum(data: ByteArray) -> ByteArray {
  #"02"
    |> bytearray.concat(#"8201")
    |> bytearray.concat(#"d818")
    |> bytearray.concat(serialise_cbor_bytes(data))
}

fn serialise_plutus_data(data: Data) -> ByteArray {
  builtin.choose_data(
    data,
    serialise_plutus_constr_data(data),
    serialise_plutus_map_data(data),
    serialise_plutus_list_data(data),
    cbor.serialise(builtin.un_i_data(data)),
    serialise_plutus_bytearray(builtin.un_b_data(data)),
  )
}

fn serialise_plutus_constr_data(data: Data) -> ByteArray {
  let Pair(constructor, fields) = builtin.un_constr_data(data)
  let serialised_fields = serialise_plutus_data_list(fields)

  if constructor < 7 {
    serialise_cbor_tag(121 + constructor)
      |> bytearray.concat(serialised_fields)
  } else if constructor < 128 {
    serialise_cbor_tag(1280 + constructor - 7)
      |> bytearray.concat(serialised_fields)
  } else {
    general_plutus_data_constructor_cbor_tag
      |> bytearray.concat(
          serialise_list_of_two(cbor.serialise(constructor), serialised_fields),
        )
  }
}

fn serialise_plutus_list_data(data: Data) -> ByteArray {
  serialise_plutus_data_list(builtin.un_list_data(data))
}

fn serialise_plutus_map_data(data: Data) -> ByteArray {
  let entries =
    list.foldl(
      builtin.un_map_data(data),
      [],
      fn(pair, entries) {
        entries
          |> insert_stable_canonical_map_entry(
              serialise_plutus_data(pair.1st),
              serialise_plutus_data(pair.2nd),
            )
      },
    )

  serialise_canonical_map_entries(entries)
}

fn serialise_plutus_data_list(items: List<Data>) -> ByteArray {
  let
    length,
    body,
  <-
    list.foldr2(
      items,
      0,
      "",
      fn(item, length, body, return) {
        return(
          length + 1,
          serialise_plutus_data(item) |> bytearray.concat(body),
        )
      },
    )

  serialise_cbor_head(4, length) |> bytearray.concat(body)
}

fn serialise_plutus_bytearray(bytes: ByteArray) -> ByteArray {
  let length = bytearray.length(bytes)

  if length <= 64 {
    serialise_cbor_bytes(bytes)
  } else {
    #"5f"
      |> bytearray.concat(serialise_plutus_bytearray_chunks(bytes, 0, length))
      |> bytearray.concat(#"ff")
  }
}

fn serialise_plutus_bytearray_chunks(
  bytes: ByteArray,
  cursor: Int,
  length: Int,
) -> ByteArray {
  if cursor >= length {
    ""
  } else {
    let chunk_length =
      if length - cursor > 64 {
        64
      } else {
        length - cursor
      }

    serialise_cbor_bytes(builtin.slice_bytearray(cursor, chunk_length, bytes))
      |> bytearray.concat(
          serialise_plutus_bytearray_chunks(
            bytes,
            cursor + chunk_length,
            length,
          ),
        )
  }
}

fn serialise_cbor_bytes(bytes: ByteArray) -> ByteArray {
  serialise_cbor_head(2, bytearray.length(bytes)) |> bytearray.concat(bytes)
}

fn serialise_cbor_tag(tag: Int) -> ByteArray {
  serialise_cbor_head(6, tag)
}

fn serialise_cbor_head(major_type: Int, argument: Int) -> ByteArray {
  let major = major_type * 32

  if argument < 24 {
    builtin.cons_bytearray(major + argument, #"")
  } else if argument <= 255 {
    builtin.cons_bytearray(
      major + 24,
      bytearray.from_int_big_endian(argument, 1),
    )
  } else if argument <= 65535 {
    builtin.cons_bytearray(
      major + 25,
      bytearray.from_int_big_endian(argument, 2),
    )
  } else if argument <= 4294967295 {
    builtin.cons_bytearray(
      major + 26,
      bytearray.from_int_big_endian(argument, 4),
    )
  } else {
    builtin.cons_bytearray(
      major + 27,
      bytearray.from_int_big_endian(argument, 8),
    )
  }
}

fn serialise_output_value(value: Value) -> ByteArray {
  let lovelace = value |> assets.lovelace_of |> cbor.serialise
  let non_ada = value |> assets.without_lovelace

  if non_ada == assets.zero {
    lovelace
  } else {
    #"82"
      |> bytearray.concat(lovelace)
      |> bytearray.concat(serialise_multiasset(non_ada))
  }
}

fn serialise_mint(mint: Value) -> ByteArray {
  serialise_multiasset(mint)
}

fn serialise_multiasset(value: Value) -> ByteArray {
  let entries =
    value
      |> assets.to_dict
      |> dict.to_pairs
      |> list.foldl(
          [],
          fn(policy_entry, entries) {
            let Pair(policy, tokens) = policy_entry
            entries
              |> insert_canonical_map_entry(
                  serialise_cbor_bytes(policy),
                  tokens |> dict.to_pairs |> serialise_asset_quantities,
                )
          },
        )
  serialise_canonical_map_entries(entries)
}

fn serialise_asset_quantities(tokens: Pairs<AssetName, Int>) -> ByteArray {
  let entries =
    list.foldl(
      tokens,
      [],
      fn(token, entries) {
        let Pair(asset_name, quantity) = token
        entries
          |> insert_canonical_map_entry(
              serialise_cbor_bytes(asset_name),
              cbor.serialise(quantity),
            )
      },
    )
  serialise_canonical_map_entries(entries)
}

fn serialise_address(address: Address, network_tag: Int) -> ByteArray {
  let Address { payment_credential, stake_credential } = address

  let payment_header, payment_credential_bytes <-
    when payment_credential is {
      Script(credential) ->
        fn(return) { return(16, credential) }
      VerificationKey(credential) ->
        fn(return) { return(0, credential) }
    }

  let stake_header, stake_credential_bytes <-
    when stake_credential is {
      None ->
        fn(return) { return(96, "") }
      Some(Inline(VerificationKey(credential))) ->
        fn(return) { return(0, credential) }
      Some(Inline(Script(credential))) ->
        fn(return) { return(32, credential) }
      Some(Pointer { slot_number, transaction_index, certificate_index }) ->
        fn(return) {
          return(
            64,
            serialise_variable_length_uint(slot_number)
              |> bytearray.concat(
                  serialise_variable_length_uint(transaction_index),
                )
              |> bytearray.concat(
                  serialise_variable_length_uint(certificate_index),
                ),
          )
        }
    }

  builtin.cons_bytearray(
    payment_header + stake_header + network_tag,
    bytearray.concat(payment_credential_bytes, stake_credential_bytes),
  )
    |> cbor.serialise
}

fn serialise_variable_length_uint(value: Int) -> ByteArray {
  do_serialise_variable_length_uint(value, True, "")
}

fn do_serialise_variable_length_uint(
  value: Int,
  is_last_group: Bool,
  suffix: ByteArray,
) -> ByteArray {
  let group = value % 128
  let remaining = value / 128
  let byte =
    if is_last_group {
      group
    } else {
      group + 128
    }
  let bytes = builtin.cons_bytearray(byte, suffix)

  if remaining == 0 {
    bytes
  } else {
    do_serialise_variable_length_uint(remaining, False, bytes)
  }
}

fn serialise_extra_signatories(
  extra_signatories: List<VerificationKeyHash>,
) -> ByteArray {
  serialise_verification_key_hash_set(extra_signatories)
}

fn serialise_definite_list(length: Int, body: ByteArray) -> ByteArray {
  serialise_cbor_head(4, length) |> bytearray.concat(body)
}

/// Convert the raw `Data<Pairs<Int, List<Int>>>` cost models retrieved using
/// `protocol_parameters.cost_models()` to the exact definite array encoding
/// used by the ledger language view. It is expected that only one cost model
/// array is present within the map under this contract's Plutus language ID. The
/// authenticated prefix supplies that array's header without another traversal
/// of the model. Cost models are assumed non-empty, so their Plutus Data
/// serialization is always wrapped as an indefinite list (`9f ... ff`).
fn raw_cost_models_to_ledger_encoding(
  raw_cost_models: Data,
  cost_model_prefix: ByteArray,
) -> ByteArray {
  expect [Pair(language_id, cost_model)]: Pairs<Int, Data> = raw_cost_models
  expect language_id == plutus_language_id
  let serialised_cost_model = cbor.serialise(cost_model)
  let
    _cost_model_length,
    header_length,
  <- process_cost_model_header(cost_model_prefix)
  bytearray.take(cost_model_prefix, header_length)
    |> bytearray.concat(
        builtin.slice_bytearray(
          1,
          bytearray.length(serialised_cost_model) - 2,
          serialised_cost_model,
        ),
      )
}

fn splice_cost_model(
  cost_model_prefix: ByteArray,
  builtin_cost: Int,
  cost_model_postfix: ByteArray,
) -> ByteArray {
  cost_model_prefix
    |> bytearray.concat(cbor.serialise(builtin_cost))
    |> bytearray.concat(cost_model_postfix)
}

fn validate_cost_model_prefix(
  cost_model_prefix: ByteArray,
  builtin_index: Int,
) -> Bool {
  let _length, cursor <- process_cost_model_header(cost_model_prefix)

  do_validate_cost_model_prefix(cost_model_prefix, cursor, 0, builtin_index)
}

fn do_validate_cost_model_prefix(
  cost_model_prefix: ByteArray,
  cursor: Int,
  current_index: Int,
  target_index: Int,
) -> Bool {
  if current_index == target_index {
    cursor == bytearray.length(cost_model_prefix)
  } else {
    do_validate_cost_model_prefix(
      cost_model_prefix,
      next_cost_model_int_cursor(cost_model_prefix, cursor),
      current_index + 1,
      target_index,
    )
  }
}

fn process_cost_model_header(
  cost_model: ByteArray,
  return: fn(Int, Int) -> result,
) -> result {
  let header = bytearray.at(cost_model, 0)

  if header >= 0x80 && header <= 0x97 {
    return(header - 0x80, 1)
  } else if header == 0x98 {
    return(bytearray.at(cost_model, 1), 2)
  } else if header == 0x99 {
    return(bytearray.slice(cost_model, 1, 2) |> bytearray.to_int_big_endian, 3)
  } else {
    fail @"invalid cost model array"
  }
}

fn next_cost_model_int_cursor(cost_model: ByteArray, cursor: Int) -> Int {
  let additional_info = bytearray.at(cost_model, cursor) % 32

  if additional_info < 24 {
    cursor + 1
  } else if additional_info == 24 {
    cursor + 2
  } else if additional_info == 25 {
    cursor + 3
  } else if additional_info == 26 {
    cursor + 5
  } else if additional_info == 27 {
    cursor + 9
  } else {
    fail @"invalid cost model integer"
  }
}
