//// # Governance-authenticated protocol update pattern
////
//// `AddProposal` atomically inserts a proposal node and submits exactly one
//// matching protocol-parameter governance action. The proposal authenticates a
//// complete live cost model as a splice around one selected cost-model
//// parameter. Passage is later witnessed by the complete accepted model
//// appearing in the live language view for the Plutus language this contract
//// compiles to. This proves the approved value is live; it does not identify
//// which governance action enacted that value.
////
//// ## Approval-signal identity
////
//// The motion authenticated by this pattern is the complete target cost model,
//// not a `GovernanceActionId`. Every enacted governance action that produces
//// exactly that model is deliberately equivalent evidence that Cardano
//// governance ratified the motion. `MintPassedProposal` neither identifies nor
//// needs to identify which action produced it.
////
//// The single global registry associates that motion with its application
//// payload and prevents two active proposals from using the same cost-model
//// parameter. The governance premise is that participants review and support the
//// motion through that association. If an identical motion is enacted through
//// another action, the validator intentionally treats it as approval of the
//// active proposal. This is the defined approval model, not a separate
//// action-identity guarantee.
////
//// This hard assumption is considered practical because the global list is
//// intended to become the socially canonical channel for this signal, for
//// example through a future CIP or comparable agreement among governance
//// participants. An action outside that convention would need to change exactly
//// one cost-model entry by `+1` or `-1`, preserve every other entry, and do so
//// without the application purpose recorded in the list. It would then still
//// need enough DRep support to be ratified and enacted before the active
//// proposal expires. The combined likelihood of an otherwise purposeless exact
//// duplicate clearing those governance thresholds is assumed low enough to make
//// cost-model equality a sensible passage proof.
////
//// ## Governance-address custody
////
//// The governance validator address is dedicated to the root, proposal-node,
//// and passed-proposal UTxOs created by this pattern. Its spending endpoint is
//// a paired minting-policy gate for those state transitions; it does not
//// independently protect unrelated UTxOs at that address. Do not use the
//// address as a general-purpose payment destination.
////
//// ## Digest-based transaction authentication
////
//// Proposal insertion reconstructs Conway transaction-body bytes from the
//// Plutus context plus witnesses for information the context omits. Equality
//// with `Transaction.id` binds the entire reconstructed body byte-for-byte,
//// including every opaque CBOR fragment, under the hash's collision resistance.
//// Script-data-hash reconstruction similarly binds the executed redeemers,
//// budgets, and language views. The ledger has already validated the syntax and
//// ledger semantics of the committed transaction. Parsing opaque fragments
//// again would add no assurance for the properties this module uses; a caller
//// only needs additional decoding if its own application assigns independent
//// meaning to one of those fields.
////
//// Values serialized by the module use the hardware-wallet canonical CBOR
//// profile: shortest integers and lengths, definite arrays and maps, canonical
//// map-key ordering, and tag 258 on sets. This is a serialization profile, not
//// the hardware-wallet body-field allowlist; insertion necessarily includes the
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
////
//// ## Finalization responsibility split
////
//// A `PASS` burn proves authorization by a stable subject withdrawal, while the
//// proposal-specific required withdrawal enforces the actual state transition.
//// Both scripts inspect the full transaction. The governance policy therefore
//// restricts its own `PASS` burn and reimbursement but deliberately leaves
//// unrelated-policy minting, other transaction effects, and application state
//// rules to those two scripts. Finalization is permissionless because caller
//// identity is not part of that authorization.
////
//// Withdrawal quantities are not authorization data and are intentionally not
//// checked. In a ledger-valid transaction, the presence of a script withdrawal
//// necessarily executes that credential, so a second lookup in the redeemer
//// collection would add no authorization. The example withdrawal scripts
//// permit registration but reject delegation certificates, so they are not
//// intended to accrue pool-delegation rewards. Under the current ledger rules,
//// a non-empty reward account must be withdrawn in full; the transaction cannot
//// choose a smaller amount. If a subject needs constraints on the resulting
//// value flow, its stable or required withdrawal script is the correct place to
//// enforce them. Revisit this boundary if the ledger enables partial
//// withdrawals for Plutus-backed credentials.
////
//// Proposal script hashes are likewise not length-checked at admission. A valid
//// finalization must use each value as an actual ledger withdrawal credential,
//// and the stable subject must recognize the complete `PASS || script_hash`
//// asset name. A malformed value therefore cannot impersonate a valid script;
//// it can only prevent passage or finalization. Any passed-proposal UTxO it
//// strands is outside the root/node namespace, so the failure cannot corrupt or
//// permanently occupy a proposal-list position.

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
  Redeemer, ScriptPurpose, Spend, Transaction,
}

const root_key: linked_list.RootKey = "PROPOSALS_ROOT"

const node_key_prefix: linked_list.NodeKeyPrefix = "CM_PARAM_INDEX_"

const node_key_prefix_length: linked_list.NodeKeyPrefixLength =
  bytearray.length(node_key_prefix)

/// Asset name of the configuration NFT that carries the governance-action
/// lifespan in its inline integer datum. The validator that controls this NFT
/// selects the lifespan as trusted configuration; this module authenticates and
/// uses that value but does not derive or semantically bound it. The baseline
/// lifespan must be the current governance-action ratification period plus one
/// epoch for enactment, observation, and `PASS` minting. Thus a six-epoch
/// ratification period requires a seven-epoch lifespan, before any additional
/// allowance for delaying-action extensions.
pub const gov_action_lifespan_asset_name: AssetName = "GOV_ACTION_LIFESPAN"

/// Namespace for proposals whose target cost-model parameter value has gone live.
/// This out-of-list UTxO is needed to free up the parameter position for other
/// proposals, since there is no guarantee their required scripts succeed or not.
const passed_proposal_prefix: ByteArray = "PASS"

const passed_proposal_prefix_length: Int =
  bytearray.length(passed_proposal_prefix)

/// Four bytes can index more parameter positions than any currently defined cost
/// model contains.
const cost_model_parameter_index_byte_count: Int = 4

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
/// exactly the complete integer entries before the cost-model parameter selected
/// by the node key. `cost_model_postfix` starts immediately after that parameter's
/// integer and preserves the rest of the model byte-for-byte. The insertion
/// redeemer's transient `initial_cost_model_parameter_value` reconstructs the live
/// model. The proposal inserts
/// `cbor.serialise(acceptance_cost_model_parameter_value)` between them.
///
/// `subject_script_hash` identifies a stable withdrawal script to which the
/// subject contract delegates authorization. Its hash is encoded after `PASS`
/// in the resulting token name. `required_script_for_final_burn` is a distinct,
/// proposal-specific withdrawal script that enforces the final action.
///
/// These byte arrays are not length-checked when the proposal enters the list.
/// Finalization proves their validity by requiring the corresponding ledger
/// withdrawal credentials to execute. A malformed value can only prevent
/// passage or finalization; it cannot authenticate as another script. Any
/// passed-proposal UTxO it strands is outside the proposal list.
pub type Proposal {
  proposer: Address,
  gov_action_script_data_hash: ByteArray,
  cost_model_prefix: ByteArray,
  acceptance_cost_model_parameter_value: Int,
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
    initial_cost_model_parameter_value: Int,
    redeemer_metadata: List<RedeemerMetadata>,
    other_language_cost_models: List<LanguageCostModel>,
    body_witness: AddProposalBodyWitness,
  }
  // Removing a proposal whose target cost-model parameter value has gone live.
  // This endpoint carries the ledger pointers and execution budgets required to
  // authenticate its script-data hash, and mints a subject-withdrawal-bound
  // `PASS` token outside the list namespace.
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
  // script. These UTxOs sit outside the list namespace, and therefore failure of
  // their withdrawals scripts won't block a given cost-model parameter for
  // future proposals.
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
/// The list permits at most one live proposal per cost-model parameter index.
/// Each node key is exactly the index's four-byte big-endian encoding. The
/// assumption is that there will be a single canonical list for all protocols to
/// utilize.
pub fn init(
  nonce: OutputReference,
  nonce_input_index: Int,
  root_output_index: Int,
  governance_nft_policy: PolicyId,
  tx: Transaction,
) -> Bool {
  let Transaction { inputs, outputs, mint, .. } = tx
  {
    let root_address, _root_lovelace, root_data <- linked_list.init(
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
  initial_cost_model_parameter_value: Int,
  redeemer_metadata: List<RedeemerMetadata>,
  other_language_cost_models: List<LanguageCostModel>,
  body_witness: AddProposalBodyWitness,
  //
  tx: Transaction,
) -> Bool {
  let  
      Transaction {
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
      }
    = tx
  let  
      AddProposalBodyWitness {
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
      }
    = body_witness

  expect  
      Input {
        output: Output {
          value: gov_action_lifespan_value,
          datum: InlineDatum(gov_action_lifespan_data),
          ..
        },
        ..
      }
    = reference_inputs
    |> list.expect_at(gov_action_lifespan_reference_input_index)

  expect
    gov_action_lifespan_value
      |> assets.has_nft_strict(
          gov_action_lifespan_policy,
          gov_action_lifespan_asset_name,
        )
  expect gov_action_lifespan: Int = gov_action_lifespan_data

  // 1. Transaction's validity interval must be bound with a short span.
  expect  
      Interval {
        lower_bound: IntervalBound {
          bound_type: Finite(validity_range_lower_bound),
          ..
        },
        upper_bound: IntervalBound {
          bound_type: Finite(validity_range_upper_bound),
          ..
        },
      }
    = validity_range
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
        _link
      <- linked_list.insert_ascending(
      outputs |> list.expect_at(anchor_output_index),
      outputs |> list.expect_at(proposal_node_output_index),
      inputs,
      mint,
    )

    // 2. Lovelace of the anchor element must be preserved.
    expect anchor_lovelace_change >= 0

    // 3. Proposal node's underlying data must be valid. Subject and required
    //    withdrawal hashes are authenticated when those ledger credentials
    //    execute at finalization, rather than by byte-length checks here. PASS
    //    UTxOs live outside the list namespace, so a script that cannot execute
    //    cannot block its cost-model parameter index.
    expect  
        Proposal {
          proposer,
          gov_action_script_data_hash,
          cost_model_prefix,
          acceptance_cost_model_parameter_value,
          cost_model_postfix,
          valid_until,
          subject_script_hash: _,
          required_script_for_final_burn: _,
        }
      = proposal_data

    // 4. The proposer's address must have an inline staking credential so it
    //    can match the governance action's return credential.
    expect  
        Address {
          stake_credential: Some(Inline(proposer_stake_credential)),
          ..
        }
      = proposer

    // 5. The new cost must be the initial cost incremented or decremented by 1.
    expect or {
        acceptance_cost_model_parameter_value == initial_cost_model_parameter_value + 1,
        acceptance_cost_model_parameter_value == initial_cost_model_parameter_value - 1,
      }

    // 6. Expiry is determined by trusted lifespan configuration in the
    //    controller-authenticated reference input. The example controller is a
    //    multisig; its baseline value must be the current ratification period
    //    plus one epoch for enactment, observation, and PASS minting. A six-epoch
    //    ratification period therefore requires a seven-epoch lifespan, before
    //    any additional allowance for delaying-action extensions.
    expect valid_until == validity_range_upper_bound + gov_action_lifespan

    // 7. Only one proposal procedure must exist in the transaction.
    expect [ProposalProcedure { deposit, return_address, governance_action }] = tx_proposal_procedures

    // 8. The deposit reward address must match the stake credential of the
    //    proposer's address.
    expect return_address == proposer_stake_credential

    expect ProtocolParameters { ancestor, new_parameters, guardrails } = governance_action

    // 9. The cost-model parameter index is derived from the node's key. The array
    //    header must declare an element at that index, and the prefix must end
    //    exactly after all complete integer entries preceding it.
    let cost_model_parameter_index = cost_model_parameter_index_from_node_key(
      proposal_key,
    )
    expect
      validate_cost_model_prefix(cost_model_prefix, cost_model_parameter_index)

    // 10. The proposed cost model for this contract's Plutus language must
    //     preserve every non-target entry and replace only the selected
    //     cost-model parameter value.
    expect Some(raw_cost_models) = protocol_parameters.cost_models(
      new_parameters,
    )
    let expected_proposed_cost_model = splice_cost_model(
      cost_model_prefix,
      acceptance_cost_model_parameter_value,
      cost_model_postfix,
    )
    expect
      raw_cost_models_to_ledger_encoding(raw_cost_models, cost_model_prefix) == expected_proposed_cost_model

    // 11. Reconstruct the sole ledger proposal procedure. Its anchor is absent
    //     from the script context and supplied by the insertion redeemer.
    let serialised_proposal_procedures = serialise_add_proposal_proposal_procedures(
      network_tag,
      deposit,
      return_address,
      ancestor,
      expected_proposed_cost_model,
      guardrails,
      proposal_anchor_url,
      proposal_anchor_data_hash,
    )

    // 12. Reconstruct the live baseline model and validate the claimed script
    //     data hash from the proposal datum.
    let baseline_cost_model = splice_cost_model(
      cost_model_prefix,
      initial_cost_model_parameter_value,
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
  let  
      Transaction {
        inputs,
        outputs,
        mint,
        reference_inputs,
        extra_signatories,
        fee,
        id,
        validity_range,
        ..
      }
    = tx

  let continued_anchor_output = outputs |> list.expect_at(anchor_output_index)

  expect  
      Output {
        address: passed_proposal_address,
        value: passed_proposal_value,
        datum: InlineDatum(passed_proposal_data),
        reference_script: None,
      }
    = outputs |> list.expect_at(passed_proposal_output_index)

  // 1. Produced passed UTxO must have a properly shaped datum attached.
  expect  
      PassedProposal {
        proposer,
        passed_proposal_script_data_hash,
        required_script_for_final_burn: passed_required_script_for_final_burn,
      }
    = passed_proposal_data

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
        other_list_asset_changes
      <- advanced_linked_list.remove(
      anchor_input_outref,
      continued_anchor_output,
      inputs,
      mint,
    )

    let Input { output: Output { address: removing_node_address, .. }, .. } = removing_node_input

    // 2. The new `PASS` UTxO must go to the same address as its proposal UTxO.
    expect removing_node_address == passed_proposal_address

    // 3. ADA of the anchor must be preserved.
    expect anchor_element_lovelace_change >= 0

    // 4. Underlying data of the anchor must not change.
    expect root_data == cont_root_data

    // 5. There must be exactly one other mint under list policy (aside from the
    //    node's burn).
    expect [Pair(minted_pass_token_name, 1)] = other_list_asset_changes
      |> dict.to_pairs

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
    expect  
        Proposal {
          proposer: original_proposer,
          subject_script_hash,
          cost_model_prefix,
          acceptance_cost_model_parameter_value,
          cost_model_postfix,
          valid_until,
          required_script_for_final_burn,
          ..
        }
      = removing_node_data
    expect
      minted_pass_token_name == passed_proposal_asset_name(subject_script_hash)

    // 8. The new cost-model parameter value must match the initially stated
    //    approval criteria. The proposer and dynamic final-action withdrawal must
    //    also carry over to the new UTxO.
    expect original_proposer == proposer
    let accepted_cost_model = splice_cost_model(
      cost_model_prefix,
      acceptance_cost_model_parameter_value,
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

/// Burn one out-of-list passed-proposal token and require both authorization
/// layers to execute.
///
/// Withdrawal amounts are deliberately irrelevant here: presence of the stable
/// subject credential proves subject authorization, and presence of the
/// proposal-specific credential enforces the final action. Under current Cardano
/// ledger rules, any accumulated reward balance must be withdrawn in full, so
/// the transaction cannot select a smaller partial amount. Either withdrawal
/// script may impose application-specific value-flow rules when needed.
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
      passed_proposal_datum_data
    <- validate_singular_authentic_input_helper(inputs, governance_nft_policy)

  // 2. The token name must use the out-of-list `PASS` namespace. Its suffix is
  //    authenticated below by requiring that exact ledger withdrawal
  //    credential to execute; a separate byte-length check would add no
  //    authority.
  expect
    bytearray.take(passed_proposal_token_name, passed_proposal_prefix_length) == passed_proposal_prefix
  let subject_script_hash = bytearray.drop(
    passed_proposal_token_name,
    passed_proposal_prefix_length,
  )

  // 3. The `PASS` token must be burnt, with no other minting or burning under
  //    the governance policy. Other policies remain unrestricted.
  expect [Pair(burnt_token_name, burn_quantity)] = mint
    |> assets.tokens(governance_nft_policy)
    |> dict.to_pairs
  expect and {
      burn_quantity == -1,
      burnt_token_name == passed_proposal_token_name,
    }

  // 4. The `PASS` UTxO datum provides the proposer and the dynamic final-action
  //    withdrawal script.
  expect PassedProposal { proposer, required_script_for_final_burn, .. } = passed_proposal_datum_data

  // 5. The final action must execute independently of the stable subject
  //    authorization. The contents of both scripts remain application-defined.
  expect required_script_for_final_burn != subject_script_hash

  // 6. The proposer must receive a pure ADA output carrying at least the
  //    finalized `PASS` UTxO's lovelace. No datum, no reference script.
  expect
    outputs
      |> list.expect_at(proposer_output_index)
      |> validate_proposer_reimbursement(proposer, passed_utxo_lovelace)

  // 7. The stable subject withdrawal encoded after `PASS` must execute. Its
  //    amount is deliberately not part of the authorization proof.
  expect
    stake_validator.validate_withdraw_minimal(
      withdraw_script_hash: subject_script_hash,
      withdrawals: withdrawals,
      withdrawal_index: subject_withdrawal_index,
    )

  // 8. The proposal-specific final-action withdrawal must also execute. It sees
  //    the full transaction and is responsible for the proposed state change
  //    and any application-specific restrictions on unrelated effects.
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
        _removing_node_link
      <- linked_list.remove(
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
  expect  
      Output {
        address: proposer_output_address,
        value: proposer_output_value,
        datum: NoDatum,
        reference_script: None,
      }
    = proposer_output

  let proposer_output_lovelace = assets.lovelace_of(proposer_output_value)

  // 2. The reimbursement must go to the proposer.
  expect proposer_output_address == proposer

  // 3. The reimbursement output must contain only ADA.
  expect proposer_output_value == assets.from_lovelace(proposer_output_lovelace)

  // 4. The reimbursement must cover the removed UTxO's lovelace. A larger
  //    output is an externally funded top-up under transaction value
  //    conservation, so equality is neither required nor safer.
  expect proposer_output_lovelace >= minimum_lovelace

  // Done.
  True
}

/// Decode a cost-model parameter index from an enforced four-byte node key.
fn cost_model_parameter_index_from_node_key(
  node_key: linked_list.NodeKey,
) -> Int {
  expect cost_model_parameter_index_byte_count == bytearray.length(node_key)
  bytearray.to_int_big_endian(node_key)
}

/// Construct the exact subject-withdrawal-bound asset name for a passed
/// proposal. The ledger withdrawal credential authenticates the suffix during
/// finalization; proposal admission does not duplicate that with a length check.
fn passed_proposal_asset_name(subject_script_hash: ScriptHash) -> AssetName {
  bytearray.concat(passed_proposal_prefix, subject_script_hash)
}

/// Require a passed-proposal burn whose suffix is a withdrawal script
/// recognized by the subject contract. Minting and burning under every other
/// policy remain unrestricted.
///
/// This helper is the stable subject's authorization hook, not the
/// proposal-specific state-transition validator. The required withdrawal script
/// inspects the same transaction and is responsible for the final action and any
/// restrictions on otherwise unrelated transaction effects.
pub fn validate_recognized_pass_burn(
  governance_nft_policy: PolicyId,
  recognized_script_hash: ScriptHash,
  governance_finalize_redeemer_index: Int,
  mint: Value,
  redeemers: Pairs<ScriptPurpose, Redeemer>,
) -> Bool {
  // 1. There must be exactly 1 NFT being burnt under the governance policy,
  //    with its asset name being under the `PASS` namespace.
  expect [Pair(burnt_token_name, burn_quantity)] = mint
    |> assets.tokens(governance_nft_policy)
    |> dict.to_pairs
  expect burn_quantity == -1
  expect burnt_token_name == passed_proposal_asset_name(recognized_script_hash)

  // 2. The specified context index must point to the governance finalization
  //    endpoint. Passage execution witnesses are authenticated by the
  //    governance minting transition and are not needed here.
  expect Pair(Mint(invoked_mint_script_hash), governance_finalize_redeemer_data)
    = redeemers |> list.expect_at(governance_finalize_redeemer_index)
  expect invoked_mint_script_hash == governance_nft_policy
  expect FinalizePassedProposal { .. } = governance_finalize_redeemer_data

  // Done.
  True
}

/// Reconstruct a script-data hash from context redeemers and their missing
/// ledger pointers and execution budgets.
fn validate_script_data_hash_from_metadata(
  script_data_hash: ByteArray,
  cost_model: ByteArray,
  tx_redeemers: Pairs<ScriptPurpose, Data>,
  redeemer_metadata: List<RedeemerMetadata>,
  redeemer_encoding: RedeemerEncoding,
  other_language_cost_models: List<LanguageCostModel>,
) -> Bool {
  let entries = collect_redeemer_entries(redeemer_metadata, tx_redeemers, [])
  let serialised_redeemers = serialise_redeemer_entries(
    entries,
    redeemer_encoding,
  )
  let language_views = serialise_language_views(
    cost_model,
    other_language_cost_models,
  )

  builtin.blake2b_256(bytearray.concat(serialised_redeemers, language_views)) == script_data_hash
}

fn serialise_language_views(
  cost_model: ByteArray,
  other_language_cost_models: List<LanguageCostModel>,
) -> ByteArray {
  let entries = list.foldl(
    other_language_cost_models,
    [Pair(serialised_plutus_language_id, cost_model)],
    fn(language_cost_model, entries) {
      let LanguageCostModel { language_id, cost_model: other_cost_model } = language_cost_model
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
  let language_views = #"a1"
    |> bytearray.concat(serialised_plutus_language_id)
    |> bytearray.concat(cost_model)

  builtin.blake2b_256(bytearray.concat(redeemers, language_views)) == script_data_hash
}

fn validate_pass_script_data_hash(
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
  let proposal_spend_budget = serialise_budget(
    proposal_spend_mem,
    proposal_spend_cpu,
  )

  let redeemers = []
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
fn validate_tx_id_from_script_data_hash_with_mint(
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
  let fields_before_script_data_hash = mint_cbor_key
    |> bytearray.concat(cbor.serialise(assets.to_dict(mint)))
  let fields_after_collateral_inputs = #"0e"
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

fn validate_tx_id_from_script_data_hash_with_proposal_procedures(
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
  let field_4_count, field_4 <- serialise_nonempty_list_field(
    4,
    tx_certificates,
    fn(_) { certificates },
  )
  let field_5_count, field_5 <- serialise_nonempty_list_field(
    5,
    withdrawals,
    fn(withdrawals) { serialise_withdrawals(withdrawals, network_tag) },
  )
  let field_7_count, field_7 <- serialise_optional_field(
    7,
    auxiliary_data_hash,
    fn(hash) { serialise_cbor_bytes(hash) },
  )
  let field_8 = #"08" |> bytearray.concat(cbor.serialise(validity_start))
  let field_9_count, field_9 <- if mint == assets.zero {
    fn(return) { return(0, "") }
  } else {
    fn(return) {
      return(1, mint_cbor_key |> bytearray.concat(serialise_mint(mint)))
    }
  }
  let field_14_count, field_14 <- serialise_nonempty_list_field(
    14,
    extra_signatories,
    fn(extra_signatories) { serialise_extra_signatories(extra_signatories) },
  )
  let field_18_count, field_18 <- serialise_nonempty_list_field(
    18,
    reference_inputs,
    fn(reference_inputs) { serialise_tx_inputs(reference_inputs) },
  )
  let field_19_count, field_19 <- serialise_nonempty_list_field(
    19,
    tx_votes,
    fn(_) { voting_procedures },
  )
  let field_21_count, field_21 <- serialise_optional_field(
    21,
    current_treasury_amount,
    fn(value) { cbor.serialise(value) },
  )
  let field_22_count, field_22 <- serialise_optional_field(
    22,
    treasury_donation,
    fn(value) { cbor.serialise(value) },
  )

  let body_field_count = 10 + field_4_count + field_5_count + field_7_count + field_9_count + field_14_count + field_18_count + field_19_count + field_21_count + field_22_count
  let fields_before_script_data_hash = field_4
    |> bytearray.concat(field_5)
    |> bytearray.concat(field_7)
    |> bytearray.concat(field_8)
    |> bytearray.concat(field_9)
  let fields_after_collateral_inputs = field_14
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

  let tx_body = tx_body_map_header
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
      let length, body <- list.foldr2(
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
      let length, body <- list.foldr2(
        entries,
        0,
        "",
        fn(entry, length, body, return) {
          let Pair(pointer, Pair(redeemer_data, budget)) = entry
          return(
            length + 1,
            pointer
              |> bytearray.concat(serialise_list_of_two(redeemer_data, budget))
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
  let length, body <- list.foldr2(
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
  let length, body <- list.foldr2(
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
  let length, body <- list.foldr2(
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
  let entries = list.foldl(
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
  let bytes = when credential is {
    VerificationKey(hash) -> builtin.cons_bytearray(0xe0 + network_tag, hash)
    Script(hash) -> builtin.cons_bytearray(0xf0 + network_tag, hash)
  }
  serialise_cbor_bytes(bytes)
}

fn serialise_withdrawals(
  withdrawals: Pairs<Credential, Lovelace>,
  network_tag: Int,
) -> ByteArray {
  let entries = list.foldl(
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
  let entries = list.foldl(
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
  let length, body <- list.foldr2(
    items,
    0,
    "",
    fn(item, length, body, return) {
      return(length + 1, serialise_plutus_data(item) |> bytearray.concat(body))
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
    let chunk_length = if length - cursor > 64 {
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
  let entries = value
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
  let entries = list.foldl(
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

  let payment_header, payment_credential_bytes <- when payment_credential is {
    Script(credential) ->
      fn(return) { return(16, credential) }
    VerificationKey(credential) ->
      fn(return) { return(0, credential) }
  }

  let stake_header, stake_credential_bytes <- when stake_credential is {
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
  let byte = if is_last_group {
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
  let _cost_model_length, header_length <- process_cost_model_header(
    cost_model_prefix,
  )
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
  cost_model_parameter_value: Int,
  cost_model_postfix: ByteArray,
) -> ByteArray {
  cost_model_prefix
    |> bytearray.concat(cbor.serialise(cost_model_parameter_value))
    |> bytearray.concat(cost_model_postfix)
}

fn validate_cost_model_prefix(
  cost_model_prefix: ByteArray,
  cost_model_parameter_index: Int,
) -> Bool {
  let _length, cursor <- process_cost_model_header(cost_model_prefix)

  do_validate_cost_model_prefix(
    cost_model_prefix,
    cursor,
    0,
    cost_model_parameter_index,
  )
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

fn serialise_add_proposal_proposal_procedures(
  network_tag: Int,
  deposit: Lovelace,
  return_address: Credential,
  ancestor: Option<GovernanceActionId>,
  expected_proposed_cost_model: ByteArray,
  guardrails: Option<ScriptHash>,
  proposal_anchor_url: ByteArray,
  proposal_anchor_data_hash: ByteArray,
) -> ByteArray {
  let serialised_ancestor = when ancestor is {
    None -> #"f6"
    Some(action_id) -> serialise_governance_action_id(action_id)
  }
  // The reconstructed action contains exactly one parameter update: the
  // singleton cost-model map at protocol-parameter index 18.
  // Any other shape produces a different transaction ID.
  let serialised_new_parameters = #"a112a1"
    |> bytearray.concat(serialised_plutus_language_id)
    |> bytearray.concat(expected_proposed_cost_model)
  let serialised_guardrails = when guardrails is {
    None -> #"f6"
    Some(script_hash) -> cbor.serialise(script_hash)
  }
  let serialised_anchor = serialise_list_of_two(
    serialise_cbor_text(proposal_anchor_url),
    serialise_cbor_bytes(proposal_anchor_data_hash),
  )
  set_cbor_tag
    |> bytearray.concat(singleton_cbor_list)
    |> bytearray.concat(#"84")
    |> bytearray.concat(cbor.serialise(deposit))
    |> bytearray.concat(serialise_reward_account(network_tag, return_address))
    |> bytearray.concat(#"8400")
    |> bytearray.concat(serialised_ancestor)
    |> bytearray.concat(serialised_new_parameters)
    |> bytearray.concat(serialised_guardrails)
    |> bytearray.concat(serialised_anchor)
}

// === Tests ===================================================================

const governance_script_hash =
  #"af9ca4b510313a72f74846809e5dcae6a73632c3b8703d95516ef2b9"

const add_proposal_signed_tx_cbor =
  #"84ad00d9010282825820000000000000000000000000000000000000000000000000000000000000000004825820abc1eb37a2307e0da1a0b06c630fe0978bc9e6d8a43e1f4b5c21c70db423ffe5000183a300581d70af9ca4b510313a72f74846809e5dcae6a73632c3b8703d95516ef2b901821a004c4b40a1581caf9ca4b510313a72f74846809e5dcae6a73632c3b8703d95516ef2b9a14e50524f504f53414c535f524f4f5401028201d8184fd87982d8798140d87981440000002aa300581d70af9ca4b510313a72f74846809e5dcae6a73632c3b8703d95516ef2b901821a005f299aa1581caf9ca4b510313a72f74846809e5dcae6a73632c3b8703d95516ef2b9a153434d5f504152414d5f494e4445585f0000002a01028201d8185904a2d87982d87a81d87988d87982d87981581c49be9b0865bae1acc2bc8096a390340cc9792b49073751a1f2bc3c52d87981d87981d87981581c648985806b9229ba1387f314e323beee40f3f670dd0c82b07da517395820cea6b65a0d649163bc01a84bc4c8eab4e91f34501923f25d0e4bf201670b23fa5f584099015e1a000189b41901a401011903e818ad00011903e819ea350401192baf18201a000312591920a404193e801864193e801864193e801864193e801864193e582b801864193e80186418641864193e8018641a000170a718201a00020782182019f016041a0001194a18b200ff025f584019568718201a0001643519030104021a00014f581a0001e143191c893903831906b41903c018391a00014f580001011903e819a7a9040219779f197053184b0158401a000db464196a8f0119ca3f19022e011999101903e819ecb2011a00022a4718201a000144ce1820193bc318201a0001291101193371041956540a197147184a584001197147184a0119a9151902280119aecd19021d0119843c18201a00010a9618201a00011aaa1820191c4b1820191cdf1820192d1a18201a00014f581a0001e1584043191c893903831906b41903c018391a00014f5800011a0001614219020700011a000122c118201a00014f581a0001e143191c893903831906b41903c018391a584000014f580001011a00014f581a0001e143191c893903831906b41903c018391a00014f5800011a000e94721a0003414000021a0004213c19583c041a00163cad584019fc3604194ff30104001a00022aa818201a000189b41901a401011a00013eff182019e86a1820194eae182019600c1820195108182019654d182019602f182058401a0290f1e70a1a032e93af1937fd0a1a0298e40b1966c40a193e801864193e8018641a000eaf1f121a002a6e06061a0006be98011a0321aac7190eac121a000458401699121a048e466e1922a4121a0327ec9a121a001e743c18241a0031410f0c1a000dbf9e011a09f2f6d31910d318241a0004578218241a096e44021967b5182458401a0473cee818241a13e62472011a0f23d40118481a00212c5618481a0022814619fc3b041a00032b00192076041a0013be0419702c183f00011a000f59d919aa58406718fb00011a000187551902d61902cf00011a000187551902d61902cf00011a000187551902d61902cf00011a0001a5661902a800011a00017468011a00044a5840391949a000011a0002bfe2189f01011a00026b371922ee00011a00026e9219226d00011a0001a3e2190ce2011a00019e4919028f011a001df8bb195fc8031a0058400943b11a0003891119cf9800011a0001c7e71907a5041a000389cb0a1903e819610607011a00038a4a18201a132ed9841a017eceb5121a24d436c71a0402f5a8584018241a0005723c1947ed182d151a00035b2f1924e4011903e81a0002a0541a0002cb6e061818151a000341231a00096fa11907ce196e62011903e819950f0216551903e81a000176bd01010b1903e81a00043c490c15ff1b000001a043005778581cf7841fc32e5b232a80de73defd562300864d84dbe315581dd5885cb4581cc7844876a8a45ed7e3eae2becffa18cef557d9d36618ac8010a7ed13d87a808258390049be9b0865bae1acc2bc8096a390340cc9792b49073751a1f2bc3c52648985806b9229ba1387f314e323beee40f3f670dd0c82b07da517391b000000742e4d889e021a000b0bc8031a07b8db5b081a07b8da2f09a1581caf9ca4b510313a72f74846809e5dcae6a73632c3b8703d95516ef2b9a153434d5f504152414d5f494e4445585f0000002a010b5820cea6b65a0d649163bc01a84bc4c8eab4e91f34501923f25d0e4bf201670b23fa0dd90102818258200000000000000000000000000000000000000000000000000000000000000000040ed9010281581c49be9b0865bae1acc2bc8096a390340cc9792b49073751a1f2bc3c52108258390049be9b0865bae1acc2bc8096a390340cc9792b49073751a1f2bc3c52648985806b9229ba1387f314e323beee40f3f670dd0c82b07da517391b000000746a063cc0111a004c4b4012d90102828258204922df5f87f1bdadd7d4c3b1f945f5723e8ef2c4304c7d895cdc05c162c3bd370082582088ccadaf218315d5f61858c25a9f169e76337364bdc434f0e2734de0b750f3110014d9010281841a3b9aca00581de0648985806b9229ba1387f314e323beee40f3f670dd0c82b07da517398400f6a112a10299015e1a000189b41901a401011903e818ad00011903e819ea350401192baf18201a000312591920a404193e801864193e801864193e801864193e801864193e801864193e80186418641864193e8018641a000170a718201a00020782182019f016041a0001194a18b2000219568718201a0001643519030104021a00014f581a0001e143191c893903831906b41903c018391a00014f580001011903e819a7a9040219779f197053184b011a000db464196a8f0119ca3f19022e011999101903e819ecb2011a00022a4718201a000144ce1820193bc318201a0001291101193371041956540a197147184a01197147184a0119a9151902280119aecd19021d0119843c18201a00010a9618201a00011aaa1820191c4b1820191cdf1820192d1a18201a00014f581a0001e143191c893903831906b41903c018391a00014f5800011a0001614219020700011a000122c118201a00014f581a0001e143191c893903831906b41903c018391a00014f580001011a00014f581a0001e143191c893903831906b41903c018391a00014f5800011a000e94721a0003414000021a0004213c19583c041a00163cad19fc3604194ff30104001a00022aa818201a000189b41901a401011a00013eff182019e86a1820194eae182019600c1820195108182019654d182019602f18201a0290f1e70a1a032e93af1937fd0a1a0298e40b1966c40a193e801864193e8018641a000eaf1f121a002a6e06061a0006be98011a0321aac7190eac121a00041699121a048e466e1922a4121a0327ec9a121a001e743c18241a0031410f0c1a000dbf9e011a09f2f6d31910d318241a0004578218241a096e44021967b518241a0473cee818241a13e62472011a0f23d40118481a00212c5618481a0022814619fc3b041a00032b00192076041a0013be0419702c183f00011a000f59d919aa6718fb00011a000187551902d61902cf00011a000187551902d61902cf00011a000187551902d61902cf00011a0001a5661902a800011a00017468011a00044a391949a000011a0002bfe2189f01011a00026b371922ee00011a00026e9219226d00011a0001a3e2190ce2011a00019e4919028f011a001df8bb195fc8031a000943b11a0003891119cf9800011a0001c7e71907a5041a000389cb0a1903e819610607011a00038a4a18201a132ed9841a017eceb5121a24d436c71a0402f5a818241a0005723c1947ed182d151a00035b2f1924e4011903e81a0002a0541a0002cb6e061818151a000341231a00096fa11907ce196e62011903e819950f02161903e81a000176bd01010b1903e81a00043c490c15f682782d68747470733a2f2f6578616d706c652e746573742f676f7665726e616e63652f636f73742d6d6f64656c2d343258200000000000000000000000000000000000000000000000000000000000000000a200d9010281825820899a0fe3dfeb7d188f4c75ce57472c77dd24eb1e3375d51020615056c2caf75958404dc3f61bac28237629a0fc355701ca824eb95077f413d20192acddf46e6a00321d60789f787cb6ebe268e77a713db65c5499e3eb10c79be660504323c60a8f000582840001d87980821991501a00da077a840100d87a8800d8798000010182d8798400011991501a00da077ad8798401001a002545891a47fddb4880d8798a1a07b8db5b40d87a801a07b8da2f5828d90102818258200000000000000000000000000000000000000000000000000000000000000000045f58408258390049be9b0865bae1acc2bc8096a390340cc9792b49073751a1f2bc3c52648985806b9229ba1387f314e323beee40f3f670dd0c82b07da517391b00000045746a063cc0ff451a004c4b4040582d68747470733a2f2f6578616d706c652e746573742f676f7665726e616e63652f636f73742d6d6f64656c2d343258200000000000000000000000000000000000000000000000000000000000000000821a002545891a47fddb48f5f6"

const add_proposal_tx_id =
  #"3c4c51068f1d086a1bbdd559dde8499a38b8b6373005cad8dd65bf529dfec86d"

const add_proposal_script_data_hash =
  #"cea6b65a0d649163bc01a84bc4c8eab4e91f34501923f25d0e4bf201670b23fa"

const cost_model_prefix =
  #"99015e1a000189b41901a401011903e818ad00011903e819ea350401192baf18201a000312591920a404193e801864193e801864193e801864193e801864193e801864193e80186418641864193e8018641a000170a718201a00020782182019f016041a0001194a18b200"

const cost_model_postfix =
  #"19568718201a0001643519030104021a00014f581a0001e143191c893903831906b41903c018391a00014f580001011903e819a7a9040219779f197053184b011a000db464196a8f0119ca3f19022e011999101903e819ecb2011a00022a4718201a000144ce1820193bc318201a0001291101193371041956540a197147184a01197147184a0119a9151902280119aecd19021d0119843c18201a00010a9618201a00011aaa1820191c4b1820191cdf1820192d1a18201a00014f581a0001e143191c893903831906b41903c018391a00014f5800011a0001614219020700011a000122c118201a00014f581a0001e143191c893903831906b41903c018391a00014f580001011a00014f581a0001e143191c893903831906b41903c018391a00014f5800011a000e94721a0003414000021a0004213c19583c041a00163cad19fc3604194ff30104001a00022aa818201a000189b41901a401011a00013eff182019e86a1820194eae182019600c1820195108182019654d182019602f18201a0290f1e70a1a032e93af1937fd0a1a0298e40b1966c40a193e801864193e8018641a000eaf1f121a002a6e06061a0006be98011a0321aac7190eac121a00041699121a048e466e1922a4121a0327ec9a121a001e743c18241a0031410f0c1a000dbf9e011a09f2f6d31910d318241a0004578218241a096e44021967b518241a0473cee818241a13e62472011a0f23d40118481a00212c5618481a0022814619fc3b041a00032b00192076041a0013be0419702c183f00011a000f59d919aa6718fb00011a000187551902d61902cf00011a000187551902d61902cf00011a000187551902d61902cf00011a0001a5661902a800011a00017468011a00044a391949a000011a0002bfe2189f01011a00026b371922ee00011a00026e9219226d00011a0001a3e2190ce2011a00019e4919028f011a001df8bb195fc8031a000943b11a0003891119cf9800011a0001c7e71907a5041a000389cb0a1903e819610607011a00038a4a18201a132ed9841a017eceb5121a24d436c71a0402f5a818241a0005723c1947ed182d151a00035b2f1924e4011903e81a0002a0541a0002cb6e061818151a000341231a00096fa11907ce196e62011903e819950f02161903e81a000176bd01010b1903e81a00043c490c15"

const initial_cost_model_parameter_value = 1

const acceptance_cost_model_parameter_value = 2

const baseline_cost_model =
  splice_cost_model(
    cost_model_prefix,
    initial_cost_model_parameter_value,
    cost_model_postfix,
  )

const acceptance_cost_model =
  splice_cost_model(
    cost_model_prefix,
    acceptance_cost_model_parameter_value,
    cost_model_postfix,
  )

const add_proposal_redeemer_metadata: List<RedeemerMetadata> =
  [
    RedeemerMetadata {
      context_index: 0,
      ledger_index: 1,
      mem: 37200,
      cpu: 14288762,
    },
    RedeemerMetadata {
      context_index: 1,
      ledger_index: 0,
      mem: 2442633,
      cpu: 1207819080,
    },
  ]

const add_proposal_redeemer_encdoding: RedeemerEncoding = ListEncoding

const add_proposal_other_language_cost_models: List<LanguageCostModel> = []

const add_proposal_spend_purpose: ScriptPurpose =
  Spend(
    output_reference(
      #"abc1eb37a2307e0da1a0b06c630fe0978bc9e6d8a43e1f4b5c21c70db423ffe5",
      0,
    ),
  )

const add_proposal_spend_redeemer_data: Data = DelegateToMint

const add_proposal_mint_purpose: ScriptPurpose = Mint(governance_script_hash)

const add_proposal_mint_redeemer_data: Data =
  AddProposal {
    gov_action_lifespan_reference_input_index: 0,
    redeemer_encoding: add_proposal_redeemer_encdoding,
    anchor_output_index: 0,
    proposal_node_output_index: 1,
    initial_cost_model_parameter_value: 1,
    redeemer_metadata: add_proposal_redeemer_metadata,
    other_language_cost_models: add_proposal_other_language_cost_models,
    body_witness: AddProposalBodyWitness {
      ttl: 129555291,
      certificates: "",
      auxiliary_data_hash: None,
      validity_start: 129554991,
      collateral_inputs: #"d9010281825820000000000000000000000000000000000000000000000000000000000000000004",
      collateral_return: #"8258390049be9b0865bae1acc2bc8096a390340cc9792b49073751a1f2bc3c52648985806b9229ba1387f314e323beee40f3f670dd0c82b07da517391b000000746a063cc0",
      total_collateral: #"1a004c4b40",
      voting_procedures: #"",
      proposal_anchor_url: #"68747470733a2f2f6578616d706c652e746573742f676f7665726e616e63652f636f73742d6d6f64656c2d3432",
      proposal_anchor_data_hash: #"0000000000000000000000000000000000000000000000000000000000000000",
    },
  }

fn add_proposal_redeemers() -> Pairs<ScriptPurpose, Redeemer> {
  let spend_redeemer: Redeemer = add_proposal_spend_redeemer_data
  let mint_redeemer: Redeemer = add_proposal_mint_redeemer_data

  [
    Pair(add_proposal_spend_purpose, spend_redeemer),
    Pair(add_proposal_mint_purpose, mint_redeemer),
  ]
}

test success__add_proposal_script_data_hash() {
  validate_script_data_hash_from_metadata(
    add_proposal_script_data_hash,
    baseline_cost_model,
    add_proposal_redeemers(),
    add_proposal_redeemer_metadata,
    add_proposal_redeemer_encdoding,
    add_proposal_other_language_cost_models,
  )
}

const fixture_wallet_payment_hash =
  #"49be9b0865bae1acc2bc8096a390340cc9792b49073751a1f2bc3c52"

const fixture_wallet_stake_hash =
  #"648985806b9229ba1387f314e323beee40f3f670dd0c82b07da51739"

const fixture_root_asset_name = #"50524f504f53414c535f524f4f54"

const fixture_cost_model_parameter_42_asset_name =
  #"434d5f504152414d5f494e4445585f0000002a"

const fixture_lifespan_configuration_policy_id =
  #"36df784425072acf1d3f85e018b2e7ce270642ea2d90f78d606fe1e5"

const fixture_governance_reference_script_owner =
  #"65a8dffad746b3924946bc0e06dd45d4d15fd01c48b09895441c42d3"

const fixture_governance_address: Address =
  Address {
    payment_credential: Script(governance_script_hash),
    stake_credential: None,
  }

const fixture_governance_reference_script_owner_address: Address =
  Address {
    payment_credential: VerificationKey(
      fixture_governance_reference_script_owner,
    ),
    stake_credential: None,
  }

const fixture_lifespan_configuration_address: Address =
  Address {
    payment_credential: Script(fixture_lifespan_configuration_policy_id),
    stake_credential: None,
  }

const fixture_wallet_address: Address =
  Address {
    payment_credential: VerificationKey(fixture_wallet_payment_hash),
    stake_credential: Some(Inline(VerificationKey(fixture_wallet_stake_hash))),
  }

fn output_reference(
  transaction_id: ByteArray,
  output_index: Int,
) -> OutputReference {
  OutputReference { transaction_id, output_index }
}

fn output_with_only_ada(address: Address, lovelace: Int) -> Output {
  Output {
    address,
    value: assets.from_lovelace(lovelace),
    datum: NoDatum,
    reference_script: None,
  }
}

fn output_with_inline_datum(
  address: Address,
  lovelace: Int,
  datum: Data,
  value: assets.Value,
) -> Output {
  Output {
    address,
    value: assets.from_lovelace(lovelace) |> assets.merge(value),
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

fn governance_value(asset_name: ByteArray, quantity: Int) -> assets.Value {
  assets.zero |> assets.add(governance_script_hash, asset_name, quantity)
}

const fixture_lifespan_configuration_value: assets.Value =
  assets.zero
    |> assets.add(
        fixture_lifespan_configuration_policy_id,
        gov_action_lifespan_asset_name,
        1,
      )

fn governance_root_datum(link: Option<ByteArray>) -> Datum {
  linked_list.Element { data: linked_list.Root(#""), link }
}

const fixture_proposal_datum: Datum =
  linked_list.Element {
    data: linked_list.Node(
      Proposal {
        proposer: fixture_wallet_address,
        gov_action_script_data_hash: add_proposal_script_data_hash,
        cost_model_prefix,
        acceptance_cost_model_parameter_value: 2,
        cost_model_postfix,
        valid_until: 1_787_830_491_000,
        subject_script_hash: #"f7841fc32e5b232a80de73defd562300864d84dbe315581dd5885cb4",
        required_script_for_final_burn: #"c7844876a8a45ed7e3eae2becffa18cef557d9d36618ac8010a7ed13",
      },
    ),
    link: None,
  }

const fixture_governance_reference_input: Input =
  Input {
    output_reference: output_reference(
      #"88ccadaf218315d5f61858c25a9f169e76337364bdc434f0e2734de0b750f311",
      0,
    ),
    output: Output {
      address: fixture_governance_reference_script_owner_address,
      value: assets.from_lovelace(55_099_040),
      datum: NoDatum,
      reference_script: Some(governance_script_hash),
    },
  }

const fixture_lifespan_configuration_reference_input: Input =
  Input {
    output_reference: output_reference(
      #"4922df5f87f1bdadd7d4c3b1f945f5723e8ef2c4304c7d895cdc05c162c3bd37",
      0,
    ),
    output: output_with_inline_datum(
      fixture_lifespan_configuration_address,
      5_000_000,
      2_592_000_000,
      fixture_lifespan_configuration_value,
    ),
  }

const add_proposal_inputs: List<Input> =
  [
    Input {
      output_reference: output_reference(
        #"0000000000000000000000000000000000000000000000000000000000000000",
        4,
      ),
      output: output_with_only_ada(fixture_wallet_address, 500_000_000_000),
    },
    Input {
      output_reference: output_reference(
        #"abc1eb37a2307e0da1a0b06c630fe0978bc9e6d8a43e1f4b5c21c70db423ffe5",
        0,
      ),
      output: output_with_inline_datum(
        fixture_governance_address,
        5_000_000,
        governance_root_datum(None),
        governance_value(fixture_root_asset_name, 1),
      ),
    },
  ]

const add_proposal_reference_inputs: List<Input> =
  [
    fixture_lifespan_configuration_reference_input,
    fixture_governance_reference_input,
  ]

const add_proposal_outputs: List<Output> =
  [
    output_with_inline_datum(
      fixture_governance_address,
      5_000_000,
      governance_root_datum(Some(#"0000002a")),
      governance_value(fixture_root_asset_name, 1),
    ),
    output_with_inline_datum(
      fixture_governance_address,
      6_236_570,
      fixture_proposal_datum,
      governance_value(fixture_cost_model_parameter_42_asset_name, 1),
    ),
    output_with_only_ada(fixture_wallet_address, 498_993_039_518),
  ]

const add_proposal_tx_fee: Int = 723_912

test success__add_proposal_tx_id_from_script_data_hash_with_proposal_procedures() {
  trace add_proposal_signed_tx_cbor

  expect AddProposal { body_witness, .. } = add_proposal_mint_redeemer_data
  let  
      AddProposalBodyWitness {
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
      }
    = body_witness

  let serialised_proposal_procedures = serialise_add_proposal_proposal_procedures(
    0,
    1_000_000_000,
    VerificationKey(fixture_wallet_stake_hash),
    None,
    acceptance_cost_model,
    None,
    proposal_anchor_url,
    proposal_anchor_data_hash,
  )

  validate_tx_id_from_script_data_hash_with_proposal_procedures(
    add_proposal_tx_id,
    add_proposal_script_data_hash,
    add_proposal_inputs,
    add_proposal_reference_inputs,
    add_proposal_outputs,
    0,
    add_proposal_tx_fee,
    governance_value(fixture_cost_model_parameter_42_asset_name, 1),
    [],
    [],
    [fixture_wallet_payment_hash],
    [],
    None,
    None,
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
}

const mint_passed_proposal_script_data_hash =
  #"440035938f04f33f30704c1dfd092138310189d6f00447d29c3e91efde3a3acf"

const mint_passed_proposal_signed_tx_cbor =
  #"84ab00d90102838258200000000000000000000000000000000000000000000000000000000000000000058258203c4c51068f1d086a1bbdd559dde8499a38b8b6373005cad8dd65bf529dfec86d008258203c4c51068f1d086a1bbdd559dde8499a38b8b6373005cad8dd65bf529dfec86d010183a300581d70af9ca4b510313a72f74846809e5dcae6a73632c3b8703d95516ef2b901821a004c4b40a1581caf9ca4b510313a72f74846809e5dcae6a73632c3b8703d95516ef2b9a14e50524f504f53414c535f524f4f5401028201d8184ad87982d8798140d87a80a300581d70af9ca4b510313a72f74846809e5dcae6a73632c3b8703d95516ef2b901821a005f299aa1581caf9ca4b510313a72f74846809e5dcae6a73632c3b8703d95516ef2b9a1582050415353f7841fc32e5b232a80de73defd562300864d84dbe315581dd5885cb401028201d818588ed87a83d87982d87981581c49be9b0865bae1acc2bc8096a390340cc9792b49073751a1f2bc3c52d87981d87981d87981581c648985806b9229ba1387f314e323beee40f3f670dd0c82b07da517395820440035938f04f33f30704c1dfd092138310189d6f00447d29c3e91efde3a3acf581cc7844876a8a45ed7e3eae2becffa18cef557d9d36618ac8010a7ed138258390049be9b0865bae1acc2bc8096a390340cc9792b49073751a1f2bc3c52648985806b9229ba1387f314e323beee40f3f670dd0c82b07da517391b000000746a4a68a4021a00081f5c031a07b8db6f09a1581caf9ca4b510313a72f74846809e5dcae6a73632c3b8703d95516ef2b9a253434d5f504152414d5f494e4445585f0000002a20582050415353f7841fc32e5b232a80de73defd562300864d84dbe315581dd5885cb4010b5820440035938f04f33f30704c1dfd092138310189d6f00447d29c3e91efde3a3acf0dd90102818258200000000000000000000000000000000000000000000000000000000000000000050ed9010281581c49be9b0865bae1acc2bc8096a390340cc9792b49073751a1f2bc3c52108258390049be9b0865bae1acc2bc8096a390340cc9792b49073751a1f2bc3c52648985806b9229ba1387f314e323beee40f3f670dd0c82b07da517391b000000746a063cc0111a004c4b4012d901028182582088ccadaf218315d5f61858c25a9f169e76337364bdc434f0e2734de0b750f31100a200d9010281825820899a0fe3dfeb7d188f4c75ce57472c77dd24eb1e3375d51020615056c2caf75958405a66045192442d4adeb7ecffb71de38b934ac8c69a22f75744291f44fc77746a3943b2173aacbfabb778556f571ab23e4c1d4206479e84aac88abe224ed1dc090583840001d87980821991501a00da077a840002d8798082199daa1a00fd9ebd840100d87b90d87980d8798258203c4c51068f1d086a1bbdd559dde8499a38b8b6373005cad8dd65bf529dfec86d00000101021a00da077a1991501a00fd9ebd199daa1a218032681a0016f1631a07b8db6f5828d90102818258200000000000000000000000000000000000000000000000000000000000000000055f58408258390049be9b0865bae1acc2bc8096a390340cc9792b49073751a1f2bc3c52648985806b9229ba1387f314e323beee40f3f670dd0c82b07da517391b00000045746a063cc0ff451a004c4b40821a0016f1631a21803268f5f6"

const mint_passed_proposal_redeemer: MintRedeemer = {
    expect AddProposal { body_witness, .. } = add_proposal_mint_redeemer_data
    let AddProposalBodyWitness { collateral_return, total_collateral, .. } = body_witness

    MintPassedProposal {
      redeemer_encoding: ListEncoding,
      anchor_input_outref: output_reference(add_proposal_tx_id, 0),
      anchor_output_index: 0,
      passed_proposal_output_index: 1,
      anchor_spend_redeemer_index: 1,
      proposal_spend_redeemer_index: 2,
      anchor_spend_cpu: 14_288_762,
      anchor_spend_mem: 37_200,
      node_spend_cpu: 16_621_245,
      node_spend_mem: 40_362,
      mint_cpu: 562_049_640,
      mint_mem: 1_503_587,
      ttl: 129_555_311,
      collateral_inputs: #"d9010281825820000000000000000000000000000000000000000000000000000000000000000005",
      collateral_output: collateral_return,
      collateral_fee: total_collateral,
    }
  }

test success__mint_passed_proposal_script_data_hash() {
  expect  
      MintPassedProposal {
        anchor_spend_cpu,
        anchor_spend_mem,
        node_spend_cpu,
        node_spend_mem,
        mint_cpu,
        mint_mem,
        anchor_spend_redeemer_index,
        proposal_spend_redeemer_index,
        redeemer_encoding,
        ..
      }
    = mint_passed_proposal_redeemer

  validate_pass_script_data_hash(
    mint_passed_proposal_script_data_hash,
    acceptance_cost_model,
    anchor_spend_cpu,
    anchor_spend_mem,
    node_spend_cpu,
    node_spend_mem,
    mint_cpu,
    mint_mem,
    anchor_spend_redeemer_index,
    proposal_spend_redeemer_index,
    redeemer_encoding,
    mint_passed_proposal_redeemer,
  )
}

const mint_passed_proposal_tx_id =
  #"22641b8b14ba9dedf195e44cdf1a28cfda43ec0884384372a508fdc2978ef9e1"

const mint_passed_proposal_subject_script_hash =
  #"f7841fc32e5b232a80de73defd562300864d84dbe315581dd5885cb4"

const mint_passed_proposal_datum: PassedProposal =
  PassedProposal {
    proposer: fixture_wallet_address,
    passed_proposal_script_data_hash: mint_passed_proposal_script_data_hash,
    required_script_for_final_burn: #"c7844876a8a45ed7e3eae2becffa18cef557d9d36618ac8010a7ed13",
  }

const mint_passed_proposal_inputs: List<Input> =
  [
    Input {
      output_reference: output_reference(
        #"0000000000000000000000000000000000000000000000000000000000000000",
        5,
      ),
      output: output_with_only_ada(fixture_wallet_address, 500_000_000_000),
    },
    Input {
      output_reference: output_reference(add_proposal_tx_id, 0),
      output: output_with_inline_datum(
        fixture_governance_address,
        5_000_000,
        governance_root_datum(Some(#"0000002a")),
        governance_value(fixture_root_asset_name, 1),
      ),
    },
    Input {
      output_reference: output_reference(add_proposal_tx_id, 1),
      output: output_with_inline_datum(
        fixture_governance_address,
        6_236_570,
        fixture_proposal_datum,
        governance_value(fixture_cost_model_parameter_42_asset_name, 1),
      ),
    },
  ]

const mint_passed_proposal_outputs: List<Output> =
  [
    output_with_inline_datum(
      fixture_governance_address,
      5_000_000,
      governance_root_datum(None),
      governance_value(fixture_root_asset_name, 1),
    ),
    output_with_inline_datum(
      fixture_governance_address,
      6_236_570,
      mint_passed_proposal_datum,
      governance_value(
        passed_proposal_asset_name(mint_passed_proposal_subject_script_hash),
        1,
      ),
    ),
    output_with_only_ada(fixture_wallet_address, 499_999_467_684),
  ]

const mint_passed_proposal_mint: assets.Value =
  assets.zero
    |> assets.add(
        governance_script_hash,
        fixture_cost_model_parameter_42_asset_name,
        -1,
      )
    |> assets.add(
        governance_script_hash,
        passed_proposal_asset_name(mint_passed_proposal_subject_script_hash),
        1,
      )

test success__mint_passed_proposal_tx_id() {
  trace mint_passed_proposal_signed_tx_cbor

  expect  
      MintPassedProposal {
        ttl,
        collateral_inputs,
        collateral_output,
        collateral_fee,
        ..
      }
    = mint_passed_proposal_redeemer

  validate_tx_id_from_script_data_hash_with_mint(
    mint_passed_proposal_tx_id,
    mint_passed_proposal_script_data_hash,
    mint_passed_proposal_inputs,
    [fixture_governance_reference_input],
    mint_passed_proposal_outputs,
    0,
    532_316,
    ttl,
    mint_passed_proposal_mint,
    [fixture_wallet_payment_hash],
    collateral_inputs,
    collateral_output,
    collateral_fee,
  )
}

const private_testnet_governance_script_hash =
  #"dffef463f3a4c23c0dd18014cd56706cfed12b9440fa82d1e7be263a"

const private_testnet_guardrail_script_hash =
  #"fa24fb305126805cf2164c161d852a0e7330cf988f1fe558cf7d4a64"

const private_testnet_add_proposal_signed_tx_cbor =
  #"84ad00d901028282582013f0307c30733151445044c40b84b9a7878300b2cadfef29151ac3827ba727d600825820b04bb52200dfc2228c3e43ffa3a2e709dab31991cab9764c279630d93d7be95f000183a300581d71dffef463f3a4c23c0dd18014cd56706cfed12b9440fa82d1e7be263a01821a004c4b40a1581cdffef463f3a4c23c0dd18014cd56706cfed12b9440fa82d1e7be263aa14e50524f504f53414c535f524f4f5401028201d8184fd87982d8798140d87981440000002aa300581d71dffef463f3a4c23c0dd18014cd56706cfed12b9440fa82d1e7be263a01821a005f299aa1581cdffef463f3a4c23c0dd18014cd56706cfed12b9440fa82d1e7be263aa153434d5f504152414d5f494e4445585f0000002a01028201d8185904a2d87982d87a81d87988d87982d87981581c351f06c2dd19311df73b0e992e3d7f4c0008a973d3dd0cb46270f670d87981d87981d87981581cc0ebde3b386e3bacdd0d5863934b4602ecbddfe9dff4c633e3fc13b55820f9d792873789a23ca9b52369fc82461721124f1df7336a2421ba7d28f477938a5f584099015e1a000189b41901a401011903e818ad00011903e819ea350401192baf18201a000312591920a404193e801864193e801864193e801864193e801864193e582b801864193e80186418641864193e8018641a000170a718201a00020782182019f016041a0001194a18b200ff025f584019568718201a0001643519030104021a00014f581a0001e143191c893903831906b41903c018391a00014f580001011903e819a7a9040219779f197053184b0158401a000db464196a8f0119ca3f19022e011999101903e819ecb2011a00022a4718201a000144ce1820193bc318201a0001291101193371041956540a197147184a584001197147184a0119a9151902280119aecd19021d0119843c18201a00010a9618201a00011aaa1820191c4b1820191cdf1820192d1a18201a00014f581a0001e1584043191c893903831906b41903c018391a00014f5800011a0001614219020700011a000122c118201a00014f581a0001e143191c893903831906b41903c018391a584000014f580001011a00014f581a0001e143191c893903831906b41903c018391a00014f5800011a000e94721a0003414000021a0004213c19583c041a00163cad584019fc3604194ff30104001a00022aa818201a000189b41901a401011a00013eff182019e86a1820194eae182019600c1820195108182019654d182019602f182058401a0290f1e70a1a032e93af1937fd0a1a0298e40b1966c40a193e801864193e8018641a000eaf1f121a002a6e06061a0006be98011a0321aac7190eac121a000458401699121a048e466e1922a4121a0327ec9a121a001e743c18241a0031410f0c1a000dbf9e011a09f2f6d31910d318241a0004578218241a096e44021967b5182458401a0473cee818241a13e62472011a0f23d40118481a00212c5618481a0022814619fc3b041a00032b00192076041a0013be0419702c183f00011a000f59d919aa58406718fb00011a000187551902d61902cf00011a000187551902d61902cf00011a000187551902d61902cf00011a0001a5661902a800011a00017468011a00044a5840391949a000011a0002bfe2189f01011a00026b371922ee00011a00026e9219226d00011a0001a3e2190ce2011a00019e4919028f011a001df8bb195fc8031a0058400943b11a0003891119cf9800011a0001c7e71907a5041a000389cb0a1903e819610607011a00038a4a18201a132ed9841a017eceb5121a24d436c71a0402f5a8584018241a0005723c1947ed182d151a00035b2f1924e4011903e81a0002a0541a0002cb6e061818151a000341231a00096fa11907ce196e62011903e819950f0216551903e81a000176bd01010b1903e81a00043c490c15ff1b0000019fa89325d0581c3f493975f3230029befc56302f9bede25102e522ac3f466182eb22c3581ce2165c4f8ce0116ea0ae9176a668842178c8f79a19935991fad34b07d87a8082583901351f06c2dd19311df73b0e992e3d7f4c0008a973d3dd0cb46270f670c0ebde3b386e3bacdd0d5863934b4602ecbddfe9dff4c633e3fc13b51b000000011579c6d6021a000c62a40319045e0819044a09a1581cdffef463f3a4c23c0dd18014cd56706cfed12b9440fa82d1e7be263aa153434d5f504152414d5f494e4445585f0000002a010b5820f9d792873789a23ca9b52369fc82461721124f1df7336a2421ba7d28f477938a0dd901028182582013f0307c30733151445044c40b84b9a7878300b2cadfef29151ac3827ba727d6000ed9010281581c351f06c2dd19311df73b0e992e3d7f4c0008a973d3dd0cb46270f6701082583901351f06c2dd19311df73b0e992e3d7f4c0008a973d3dd0cb46270f670c0ebde3b386e3bacdd0d5863934b4602ecbddfe9dff4c633e3fc13b51b0000000115a84a14111a004c4b4012d901028382582068f2feac6034e6ffd5de76083bbbf184d71aba9ef729d896d0cc90a73b9f602f0082582090764a560a7a63bc3d3dfa2f34358d1f9c306c85812c0f9945360d03336e352103825820ef9279af974fc35c271e196c0a16d445e4814c32e02cae93a1cb767e2b55f0890014d9010281841a000f4240581de1c0ebde3b386e3bacdd0d5863934b4602ecbddfe9dff4c633e3fc13b584008258204c99696adb28a00012d96f216f0f03e34e95df049b1df3d01b7fcef7ca315eaa00a112a10299015e1a000189b41901a401011903e818ad00011903e819ea350401192baf18201a000312591920a404193e801864193e801864193e801864193e801864193e801864193e80186418641864193e8018641a000170a718201a00020782182019f016041a0001194a18b2000219568718201a0001643519030104021a00014f581a0001e143191c893903831906b41903c018391a00014f580001011903e819a7a9040219779f197053184b011a000db464196a8f0119ca3f19022e011999101903e819ecb2011a00022a4718201a000144ce1820193bc318201a0001291101193371041956540a197147184a01197147184a0119a9151902280119aecd19021d0119843c18201a00010a9618201a00011aaa1820191c4b1820191cdf1820192d1a18201a00014f581a0001e143191c893903831906b41903c018391a00014f5800011a0001614219020700011a000122c118201a00014f581a0001e143191c893903831906b41903c018391a00014f580001011a00014f581a0001e143191c893903831906b41903c018391a00014f5800011a000e94721a0003414000021a0004213c19583c041a00163cad19fc3604194ff30104001a00022aa818201a000189b41901a401011a00013eff182019e86a1820194eae182019600c1820195108182019654d182019602f18201a0290f1e70a1a032e93af1937fd0a1a0298e40b1966c40a193e801864193e8018641a000eaf1f121a002a6e06061a0006be98011a0321aac7190eac121a00041699121a048e466e1922a4121a0327ec9a121a001e743c18241a0031410f0c1a000dbf9e011a09f2f6d31910d318241a0004578218241a096e44021967b518241a0473cee818241a13e62472011a0f23d40118481a00212c5618481a0022814619fc3b041a00032b00192076041a0013be0419702c183f00011a000f59d919aa6718fb00011a000187551902d61902cf00011a000187551902d61902cf00011a000187551902d61902cf00011a0001a5661902a800011a00017468011a00044a391949a000011a0002bfe2189f01011a00026b371922ee00011a00026e9219226d00011a0001a3e2190ce2011a00019e4919028f011a001df8bb195fc8031a000943b11a0003891119cf9800011a0001c7e71907a5041a000389cb0a1903e819610607011a00038a4a18201a132ed9841a017eceb5121a24d436c71a0402f5a818241a0005723c1947ed182d151a00035b2f1924e4011903e81a0002a0541a0002cb6e061818151a000341231a00096fa11907ce196e62011903e819950f02161903e81a000176bd01010b1903e81a00043c490c15581cfa24fb305126805cf2164c161d852a0e7330cf988f1fe558cf7d4a6482783568747470733a2f2f707269766174652d746573746e65742e696e76616c69642f676f7665726e616e63652f636f73742d6d6f64656c58200000000000000000000000000000000000000000000000000000000000000000a200d901028182582042dc5e55de92945d0a7058e51383c3e4e7b60eb594ef12ca08672ab2e275d1d95840a92b9198deec2d5c039462900d71176a958e2fb3690512e0082a782d9d0f31bfd45c864e02ce81171a6516c54bfa2014d0814c6c64ea8acdc4ded235f229f5010583840001d87980821991501a00da077a840100d87a8800d8798000010183d8798400011991501a00da077ad8798401001a0027bf841a4c493458d8798402001a00074dc91a063c25d980d8798a19045e40d87a8019044a5828d901028182582013f0307c30733151445044c40b84b9a7878300b2cadfef29151ac3827ba727d6005f584082583901351f06c2dd19311df73b0e992e3d7f4c0008a973d3dd0cb46270f670c0ebde3b386e3bacdd0d5863934b4602ecbddfe9dff4c633e3fc13b51b000000450115a84a14ff451a004c4b4040583568747470733a2f2f707269766174652d746573746e65742e696e76616c69642f676f7665726e616e63652f636f73742d6d6f64656c58200000000000000000000000000000000000000000000000000000000000000000821a0027bf841a4c493458840500a0821a00074dc91a063c25d9f5f6"

const private_testnet_add_proposal_tx_id =
  #"1a6b38583e5f82c7b92106d4ebb541f32026d0177646819fd5d13c8a00c450e1"

const private_testnet_add_proposal_script_data_hash =
  #"f9d792873789a23ca9b52369fc82461721124f1df7336a2421ba7d28f477938a"

const private_testnet_add_proposal_redeemer_metadata: List<RedeemerMetadata> =
  [
    RedeemerMetadata {
      context_index: 0,
      ledger_index: 1,
      mem: 37_200,
      cpu: 14_288_762,
    },
    RedeemerMetadata {
      context_index: 1,
      ledger_index: 0,
      mem: 2_604_932,
      cpu: 1_279_865_944,
    },
    RedeemerMetadata {
      context_index: 2,
      ledger_index: 0,
      mem: 478_665,
      cpu: 104_605_145,
    },
  ]

const private_testnet_add_proposal_redeemer_encoding: RedeemerEncoding =
  ListEncoding

const private_testnet_add_proposal_other_language_cost_models: List<
    LanguageCostModel,
  > =
  []

const private_testnet_wallet_payment_hash =
  #"351f06c2dd19311df73b0e992e3d7f4c0008a973d3dd0cb46270f670"

const private_testnet_wallet_stake_hash =
  #"c0ebde3b386e3bacdd0d5863934b4602ecbddfe9dff4c633e3fc13b5"

const private_testnet_proposal_ancestor: GovernanceActionId =
  GovernanceActionId {
    transaction: #"4c99696adb28a00012d96f216f0f03e34e95df049b1df3d01b7fcef7ca315eaa",
    proposal_procedure: 0,
  }

/// Script-data-hash reconstruction reads only the purpose constructor tag. The
/// exact protocol update, ancestor, and guardrail are reconstructed by the
/// transaction-id fixture below.
const private_testnet_guardrail_proposing_purpose: ScriptPurpose =
  transaction.Propose {
    at: 0,
    proposal_procedure: ProposalProcedure {
      deposit: 1_000_000,
      return_address: VerificationKey(private_testnet_wallet_stake_hash),
      governance_action: governance.NicePoll,
    },
  }

const private_testnet_add_proposal_spend_purpose: ScriptPurpose =
  Spend(
    output_reference(
      #"b04bb52200dfc2228c3e43ffa3a2e709dab31991cab9764c279630d93d7be95f",
      0,
    ),
  )

const private_testnet_add_proposal_spend_redeemer_data: Data = DelegateToMint

const private_testnet_add_proposal_mint_purpose: ScriptPurpose =
  Mint(private_testnet_governance_script_hash)

const private_testnet_guardrail_redeemer_data: Data = builtin.map_data([])

const private_testnet_add_proposal_mint_redeemer_data: Data =
  AddProposal {
    gov_action_lifespan_reference_input_index: 0,
    redeemer_encoding: private_testnet_add_proposal_redeemer_encoding,
    anchor_output_index: 0,
    proposal_node_output_index: 1,
    initial_cost_model_parameter_value: 1,
    redeemer_metadata: private_testnet_add_proposal_redeemer_metadata,
    other_language_cost_models: private_testnet_add_proposal_other_language_cost_models,
    body_witness: AddProposalBodyWitness {
      ttl: 1_118,
      certificates: "",
      auxiliary_data_hash: None,
      validity_start: 1_098,
      collateral_inputs: #"d901028182582013f0307c30733151445044c40b84b9a7878300b2cadfef29151ac3827ba727d600",
      collateral_return: #"82583901351f06c2dd19311df73b0e992e3d7f4c0008a973d3dd0cb46270f670c0ebde3b386e3bacdd0d5863934b4602ecbddfe9dff4c633e3fc13b51b0000000115a84a14",
      total_collateral: #"1a004c4b40",
      voting_procedures: #"",
      proposal_anchor_url: #"68747470733a2f2f707269766174652d746573746e65742e696e76616c69642f676f7665726e616e63652f636f73742d6d6f64656c",
      proposal_anchor_data_hash: #"0000000000000000000000000000000000000000000000000000000000000000",
    },
  }

fn private_testnet_add_proposal_redeemers() -> Pairs<ScriptPurpose, Redeemer> {
  let spend_redeemer: Redeemer = private_testnet_add_proposal_spend_redeemer_data
  let mint_redeemer: Redeemer = private_testnet_add_proposal_mint_redeemer_data
  let guardrail_redeemer: Redeemer = private_testnet_guardrail_redeemer_data

  [
    Pair(private_testnet_add_proposal_spend_purpose, spend_redeemer),
    Pair(private_testnet_add_proposal_mint_purpose, mint_redeemer),
    Pair(private_testnet_guardrail_proposing_purpose, guardrail_redeemer),
  ]
}

test success__private_testnet_add_proposal_script_data_hash() {
  validate_script_data_hash_from_metadata(
    private_testnet_add_proposal_script_data_hash,
    baseline_cost_model,
    private_testnet_add_proposal_redeemers(),
    private_testnet_add_proposal_redeemer_metadata,
    private_testnet_add_proposal_redeemer_encoding,
    private_testnet_add_proposal_other_language_cost_models,
  )
}

const private_testnet_cost_model_parameter_42_asset_name =
  #"434d5f504152414d5f494e4445585f0000002a"

const private_testnet_lifespan_configuration_policy_id =
  #"c8759406c18f2814f67b65ebe48ba33157de36323f5d3908ec223bf3"

const private_testnet_governance_reference_script_owner =
  #"b348e2642b1dcec9371d442374404e95d619f890b9aea22d634e3926"

const private_testnet_guardrail_reference_script_owner_payment_hash =
  #"142d22c19a6e4c1203f97e8b6f55ae16b3d8f4a2013882c3acd5ca34"

const private_testnet_guardrail_reference_script_owner_stake_hash =
  #"a705c43e4a037ca87bb832dc918b281b506210ba2bb3ee5ebd522da5"

const private_testnet_governance_address: Address =
  Address {
    payment_credential: Script(private_testnet_governance_script_hash),
    stake_credential: None,
  }

const private_testnet_governance_reference_script_owner_address: Address =
  Address {
    payment_credential: VerificationKey(
      private_testnet_governance_reference_script_owner,
    ),
    stake_credential: None,
  }

const private_testnet_guardrail_reference_script_owner_address: Address =
  Address {
    payment_credential: VerificationKey(
      private_testnet_guardrail_reference_script_owner_payment_hash,
    ),
    stake_credential: Some(
      Inline(
        VerificationKey(
          private_testnet_guardrail_reference_script_owner_stake_hash,
        ),
      ),
    ),
  }

const private_testnet_lifespan_configuration_address: Address =
  Address {
    payment_credential: Script(private_testnet_lifespan_configuration_policy_id),
    stake_credential: None,
  }

const private_testnet_wallet_address: Address =
  Address {
    payment_credential: VerificationKey(private_testnet_wallet_payment_hash),
    stake_credential: Some(
      Inline(VerificationKey(private_testnet_wallet_stake_hash)),
    ),
  }

fn private_testnet_governance_value(
  asset_name: ByteArray,
  quantity: Int,
) -> assets.Value {
  assets.zero
    |> assets.add(private_testnet_governance_script_hash, asset_name, quantity)
}

const private_testnet_lifespan_configuration_value: assets.Value =
  assets.zero
    |> assets.add(
        private_testnet_lifespan_configuration_policy_id,
        gov_action_lifespan_asset_name,
        1,
      )

const private_testnet_proposal_datum: Datum =
  linked_list.Element {
    data: linked_list.Node(
      Proposal {
        proposer: private_testnet_wallet_address,
        gov_action_script_data_hash: private_testnet_add_proposal_script_data_hash,
        cost_model_prefix,
        acceptance_cost_model_parameter_value: 2,
        cost_model_postfix,
        valid_until: 1_785_239_643_600,
        subject_script_hash: #"3f493975f3230029befc56302f9bede25102e522ac3f466182eb22c3",
        required_script_for_final_burn: #"e2165c4f8ce0116ea0ae9176a668842178c8f79a19935991fad34b07",
      },
    ),
    link: None,
  }

const private_testnet_governance_reference_input: Input =
  Input {
    output_reference: output_reference(
      #"ef9279af974fc35c271e196c0a16d445e4814c32e02cae93a1cb767e2b55f089",
      0,
    ),
    output: Output {
      address: private_testnet_governance_reference_script_owner_address,
      value: assets.from_lovelace(55_099_040),
      datum: NoDatum,
      reference_script: Some(private_testnet_governance_script_hash),
    },
  }

const private_testnet_guardrail_reference_input: Input =
  Input {
    output_reference: output_reference(
      #"90764a560a7a63bc3d3dfa2f34358d1f9c306c85812c0f9945360d03336e3521",
      3,
    ),
    output: Output {
      address: private_testnet_guardrail_reference_script_owner_address,
      value: assets.from_lovelace(20_000_000),
      datum: NoDatum,
      reference_script: Some(private_testnet_guardrail_script_hash),
    },
  }

const private_testnet_lifespan_configuration_reference_input: Input =
  Input {
    output_reference: output_reference(
      #"68f2feac6034e6ffd5de76083bbbf184d71aba9ef729d896d0cc90a73b9f602f",
      0,
    ),
    output: output_with_inline_datum(
      private_testnet_lifespan_configuration_address,
      5_000_000,
      120_000,
      private_testnet_lifespan_configuration_value,
    ),
  }

const private_testnet_add_proposal_inputs: List<Input> =
  [
    Input {
      output_reference: output_reference(
        #"13f0307c30733151445044c40b84b9a7878300b2cadfef29151ac3827ba727d6",
        0,
      ),
      output: output_with_only_ada(
        private_testnet_wallet_address,
        4_663_317_844,
      ),
    },
    Input {
      output_reference: output_reference(
        #"b04bb52200dfc2228c3e43ffa3a2e709dab31991cab9764c279630d93d7be95f",
        0,
      ),
      output: output_with_inline_datum(
        private_testnet_governance_address,
        5_000_000,
        governance_root_datum(None),
        private_testnet_governance_value(fixture_root_asset_name, 1),
      ),
    },
  ]

const private_testnet_add_proposal_reference_inputs: List<Input> =
  [
    private_testnet_lifespan_configuration_reference_input,
    private_testnet_guardrail_reference_input,
    private_testnet_governance_reference_input,
  ]

const private_testnet_add_proposal_outputs: List<Output> =
  [
    output_with_inline_datum(
      private_testnet_governance_address,
      5_000_000,
      governance_root_datum(Some(#"0000002a")),
      private_testnet_governance_value(fixture_root_asset_name, 1),
    ),
    output_with_inline_datum(
      private_testnet_governance_address,
      6_236_570,
      private_testnet_proposal_datum,
      private_testnet_governance_value(
        private_testnet_cost_model_parameter_42_asset_name,
        1,
      ),
    ),
    output_with_only_ada(private_testnet_wallet_address, 4_655_269_590),
  ]

const private_testnet_add_proposal_tx_fee: Int = 811_684

test success__private_testnet_add_proposal_tx_id_from_script_data_hash_with_proposal_procedures() {
  trace private_testnet_add_proposal_signed_tx_cbor

  expect AddProposal { body_witness, .. } = private_testnet_add_proposal_mint_redeemer_data
  let  
      AddProposalBodyWitness {
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
      }
    = body_witness

  let serialised_proposal_procedures = serialise_add_proposal_proposal_procedures(
    1,
    1_000_000,
    VerificationKey(private_testnet_wallet_stake_hash),
    Some(private_testnet_proposal_ancestor),
    acceptance_cost_model,
    Some(private_testnet_guardrail_script_hash),
    proposal_anchor_url,
    proposal_anchor_data_hash,
  )

  validate_tx_id_from_script_data_hash_with_proposal_procedures(
    private_testnet_add_proposal_tx_id,
    private_testnet_add_proposal_script_data_hash,
    private_testnet_add_proposal_inputs,
    private_testnet_add_proposal_reference_inputs,
    private_testnet_add_proposal_outputs,
    1,
    private_testnet_add_proposal_tx_fee,
    private_testnet_governance_value(
      private_testnet_cost_model_parameter_42_asset_name,
      1,
    ),
    [],
    [],
    [private_testnet_wallet_payment_hash],
    [],
    None,
    None,
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
}

const private_testnet_mint_passed_proposal_script_data_hash =
  #"7e4956103fed0add6fdc760498e4b613ee33c011f0e35658628deb72f7375f3f"

const private_testnet_mint_passed_proposal_signed_tx_cbor =
  #"84ab00d90102838258201a6b38583e5f82c7b92106d4ebb541f32026d0177646819fd5d13c8a00c450e1008258201a6b38583e5f82c7b92106d4ebb541f32026d0177646819fd5d13c8a00c450e101825820d269e9a4597976c602891da2e13a50a181ba69a3f6c058772d540926772fbda2000183a300581d71dffef463f3a4c23c0dd18014cd56706cfed12b9440fa82d1e7be263a01821a004c4b40a1581cdffef463f3a4c23c0dd18014cd56706cfed12b9440fa82d1e7be263aa14e50524f504f53414c535f524f4f5401028201d8184ad87982d8798140d87a80a300581d71dffef463f3a4c23c0dd18014cd56706cfed12b9440fa82d1e7be263a01821a005f299aa1581cdffef463f3a4c23c0dd18014cd56706cfed12b9440fa82d1e7be263aa15820504153533f493975f3230029befc56302f9bede25102e522ac3f466182eb22c301028201d818588ed87a83d87982d87981581c351f06c2dd19311df73b0e992e3d7f4c0008a973d3dd0cb46270f670d87981d87981d87981581cc0ebde3b386e3bacdd0d5863934b4602ecbddfe9dff4c633e3fc13b558207e4956103fed0add6fdc760498e4b613ee33c011f0e35658628deb72f7375f3f581ce2165c4f8ce0116ea0ae9176a668842178c8f79a19935991fad34b0782583901351f06c2dd19311df73b0e992e3d7f4c0008a973d3dd0cb46270f670c0ebde3b386e3bacdd0d5863934b4602ecbddfe9dff4c633e3fc13b51b00000001156e7981021a0008a23c0319052e09a1581cdffef463f3a4c23c0dd18014cd56706cfed12b9440fa82d1e7be263aa253434d5f504152414d5f494e4445585f0000002a205820504153533f493975f3230029befc56302f9bede25102e522ac3f466182eb22c3010b58207e4956103fed0add6fdc760498e4b613ee33c011f0e35658628deb72f7375f3f0dd9010281825820d269e9a4597976c602891da2e13a50a181ba69a3f6c058772d540926772fbda2000ed9010281581c351f06c2dd19311df73b0e992e3d7f4c0008a973d3dd0cb46270f6701082583901351f06c2dd19311df73b0e992e3d7f4c0008a973d3dd0cb46270f670c0ebde3b386e3bacdd0d5863934b4602ecbddfe9dff4c633e3fc13b51b00000001152ad07d111a004c4b4012d901028282582090764a560a7a63bc3d3dfa2f34358d1f9c306c85812c0f9945360d03336e352103825820ef9279af974fc35c271e196c0a16d445e4814c32e02cae93a1cb767e2b55f08900a200d901028182582042dc5e55de92945d0a7058e51383c3e4e7b60eb594ef12ca08672ab2e275d1d958406b9d6207720a09d44556ebec5bf8dc9357d20e3d1e71477986f08dfce58dada168c1b2c4e2006531ab68417e0ab35e5fef78b9bcd04a4e5b2e8b1234b14407040583840000d87980821984f61a00b67037840001d87980821991501a00da077a840100d87b90d87980d8798258201a6b38583e5f82c7b92106d4ebb541f32026d0177646819fd5d13c8a00c450e100000100011a00b670371984f61a00da077a1991501a21d6c73c1a00170d0519052e5828d9010281825820d269e9a4597976c602891da2e13a50a181ba69a3f6c058772d540926772fbda2005f584082583901351f06c2dd19311df73b0e992e3d7f4c0008a973d3dd0cb46270f670c0ebde3b386e3bacdd0d5863934b4602ecbddfe9dff4c633e3fc13b51b0000004501152ad07dff451a004c4b40821a00170d051a21d6c73cf5f6"

const private_testnet_mint_passed_proposal_redeemer: MintRedeemer =
  MintPassedProposal {
    redeemer_encoding: ListEncoding,
    anchor_input_outref: output_reference(private_testnet_add_proposal_tx_id, 0),
    anchor_output_index: 0,
    passed_proposal_output_index: 1,
    anchor_spend_redeemer_index: 0,
    proposal_spend_redeemer_index: 1,
    anchor_spend_cpu: 11_956_279,
    anchor_spend_mem: 34_038,
    node_spend_cpu: 14_288_762,
    node_spend_mem: 37_200,
    mint_cpu: 567_723_836,
    mint_mem: 1_510_661,
    ttl: 1_326,
    collateral_inputs: #"d9010281825820d269e9a4597976c602891da2e13a50a181ba69a3f6c058772d540926772fbda200",
    collateral_output: #"82583901351f06c2dd19311df73b0e992e3d7f4c0008a973d3dd0cb46270f670c0ebde3b386e3bacdd0d5863934b4602ecbddfe9dff4c633e3fc13b51b00000001152ad07d",
    collateral_fee: #"1a004c4b40",
  }

test success__private_testnet_mint_passed_proposal_script_data_hash() {
  expect  
      MintPassedProposal {
        anchor_spend_cpu,
        anchor_spend_mem,
        node_spend_cpu,
        node_spend_mem,
        mint_cpu,
        mint_mem,
        anchor_spend_redeemer_index,
        proposal_spend_redeemer_index,
        redeemer_encoding,
        ..
      }
    = private_testnet_mint_passed_proposal_redeemer

  validate_pass_script_data_hash(
    private_testnet_mint_passed_proposal_script_data_hash,
    acceptance_cost_model,
    anchor_spend_cpu,
    anchor_spend_mem,
    node_spend_cpu,
    node_spend_mem,
    mint_cpu,
    mint_mem,
    anchor_spend_redeemer_index,
    proposal_spend_redeemer_index,
    redeemer_encoding,
    private_testnet_mint_passed_proposal_redeemer,
  )
}

const private_testnet_mint_passed_proposal_tx_id =
  #"1da6a267e33ebe9201c4bb28461ac5f36ab4728c56562526ef12933260bba00f"

const private_testnet_mint_passed_proposal_subject_script_hash =
  #"3f493975f3230029befc56302f9bede25102e522ac3f466182eb22c3"

const private_testnet_mint_passed_proposal_datum: PassedProposal =
  PassedProposal {
    proposer: private_testnet_wallet_address,
    passed_proposal_script_data_hash: private_testnet_mint_passed_proposal_script_data_hash,
    required_script_for_final_burn: #"e2165c4f8ce0116ea0ae9176a668842178c8f79a19935991fad34b07",
  }

const private_testnet_mint_passed_proposal_inputs: List<Input> =
  [
    Input {
      output_reference: output_reference(private_testnet_add_proposal_tx_id, 0),
      output: output_with_inline_datum(
        private_testnet_governance_address,
        5_000_000,
        governance_root_datum(Some(#"0000002a")),
        private_testnet_governance_value(fixture_root_asset_name, 1),
      ),
    },
    Input {
      output_reference: output_reference(private_testnet_add_proposal_tx_id, 1),
      output: output_with_inline_datum(
        private_testnet_governance_address,
        6_236_570,
        private_testnet_proposal_datum,
        private_testnet_governance_value(
          private_testnet_cost_model_parameter_42_asset_name,
          1,
        ),
      ),
    },
    Input {
      output_reference: output_reference(
        #"d269e9a4597976c602891da2e13a50a181ba69a3f6c058772d540926772fbda2",
        0,
      ),
      output: output_with_only_ada(
        private_testnet_wallet_address,
        4_655_094_717,
      ),
    },
  ]

const private_testnet_mint_passed_proposal_outputs: List<Output> =
  [
    output_with_inline_datum(
      private_testnet_governance_address,
      5_000_000,
      governance_root_datum(None),
      private_testnet_governance_value(fixture_root_asset_name, 1),
    ),
    output_with_inline_datum(
      private_testnet_governance_address,
      6_236_570,
      private_testnet_mint_passed_proposal_datum,
      private_testnet_governance_value(
        passed_proposal_asset_name(
          private_testnet_mint_passed_proposal_subject_script_hash,
        ),
        1,
      ),
    ),
    output_with_only_ada(private_testnet_wallet_address, 4_654_528_897),
  ]

const private_testnet_mint_passed_proposal_mint: assets.Value =
  assets.zero
    |> assets.add(
        private_testnet_governance_script_hash,
        private_testnet_cost_model_parameter_42_asset_name,
        -1,
      )
    |> assets.add(
        private_testnet_governance_script_hash,
        passed_proposal_asset_name(
          private_testnet_mint_passed_proposal_subject_script_hash,
        ),
        1,
      )

test success__private_testnet_mint_passed_proposal_tx_id() {
  trace private_testnet_mint_passed_proposal_signed_tx_cbor

  expect  
      MintPassedProposal {
        ttl,
        collateral_inputs,
        collateral_output,
        collateral_fee,
        ..
      }
    = private_testnet_mint_passed_proposal_redeemer

  validate_tx_id_from_script_data_hash_with_mint(
    private_testnet_mint_passed_proposal_tx_id,
    private_testnet_mint_passed_proposal_script_data_hash,
    private_testnet_mint_passed_proposal_inputs,
    [
      private_testnet_guardrail_reference_input,
      private_testnet_governance_reference_input,
    ],
    private_testnet_mint_passed_proposal_outputs,
    1,
    565_820,
    ttl,
    private_testnet_mint_passed_proposal_mint,
    [private_testnet_wallet_payment_hash],
    collateral_inputs,
    collateral_output,
    collateral_fee,
  )
}
