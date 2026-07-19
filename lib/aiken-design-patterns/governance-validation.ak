//// # Governance-coupled protocol update pattern
////
//// This module demonstrates a deliberately narrow pattern for coupling a local
//// protocol action to a Cardano protocol-parameter governance action. A
//// proposer inserts an `Initialized` proposal into a linked list. The proposal
//// stores the cost model as a splice around the selected builtin: the prefix
//// includes the definite-array header and every complete integer before the
//// selected index, while the postfix contains every byte after the selected
//// integer. The initial model is reconstructed by inserting
//// `cbor.serialise(initial_builtin_cost)` between those byte strings. The datum
//// also stores `acceptance_builtin_cost`, the execution budgets and redeemer
//// indices needed to reconstruct the script data hash, the stable subject
//// withdrawal script, and the dynamic final-action withdrawal script.
//// `CoupleWithGovernanceAction` then reproduces the proposal as
//// `GovernanceActionSubmitted` when the matching action is submitted. Its
//// accepted model is reconstructed from the same prefix and postfix with
//// `cbor.serialise(acceptance_builtin_cost)` inserted between them. The
//// submitted cost model for the selected Plutus language must match that
//// reconstruction at every entry.
////
//// The contract cannot directly inspect the history of Cardano governance
//// votes. Instead, passage is witnessed by the live transaction language view:
//// once the protocol-parameter change has been enacted, anyone can construct a
//// transaction whose selected Plutus cost model contains the accepted builtin
//// cost.
//// `MintPassedProposal` removes the proposal from the linked list and produces
//// an out-of-list `PassedProposal` carrying an authorization token named
//// `"PASS" || subject_script_hash`. `FinalizePassedProposal` burns that token
//// and requires both the stable subject withdrawal encoded after `"PASS"` and
//// the proposal's dynamic `required_script_for_final_burn` withdrawal.
////
//// This passage proof authenticates the complete live cost model, not the
//// identity or voting history of the action which enacted it. The
//// `GovernanceActionSubmitted` state does not provide an on-chain proof that
//// its own `GovernanceActionId` caused the observed model. An action outside the
//// list that enacted the same complete model would therefore satisfy the proof.
//// The intended security assumption is that an independently submitted action
//// is negligibly unlikely to receive enough governance support to enact the
//// exact same single-builtin change, with every other cost in the selected model
//// preserved, by chance.
//// The shared list coordinates deliberate uses of that approval signal; it does
//// not cryptographically exclude a matching action submitted outside the list.
////
//// `gov_action_lifespan` is a trusted deployment parameter representing a
//// conservative upper bound on the time needed after the latest coupling
//// deadline for voting, enactment, any assumed delaying-action extension, and
//// observation through `MintPassedProposal`. `valid_until` is fixed to
//// `must_couple_by + gov_action_lifespan`. Once a `PassedProposal` is minted,
//// finalization may happen later without a deadline. If the configured bound is
//// shorter than the deployment's actual governance settlement horizon, the
//// submitted node can become removable while its ledger action can still enact.
////
//// A proposal node key is the exact four-byte big-endian encoding of
//// `builtin_index`. This ensures only one proposal can point to a given
//// builtin at a time.
////
//// Transaction-output serialization supports enterprise, base, and pointer
//// addresses. Callers supply the four-bit `network_tag` encoded in every
//// reconstructed output address.
////
//// This is not a general-purpose transaction serializer. The hash checks below
//// intentionally reconstruct only the transaction shape used by this pattern.
//// The following are opinionated design decisions, not accidental omissions:
////
//// TODO: Most of the following must be removed. Because of guardrail scripts
////       in parameter update governance actions, which require executing
////       arbitrary logic, all transaction shapes must be supported.
//// - Transaction-body reconstruction supports only the exact field sets used
////   by these proposal transitions. Adding other body fields requires extending
////   the relevant wrapper and shared reconstruction at the same time.
//// - `inputs`, `reference_inputs`, `outputs`, and `extra_signatories` each
////   have an implicit maximum of 23 entries. Their serializers intentionally use
////   the single-byte definite-list form and do not perform a separate on-chain
////   length check. Transactions outside this supported shape fail transaction-id
////   reconstruction. Generalized list-length encoding is deliberately omitted
////   from these already serialization-heavy validator paths.
//// - `ttl` is mandatory for `AddProposal`, `CoupleWithGovernanceAction`, and
////   `MintPassedProposal`. Their redeemers carry it explicitly so the
////   reconstructed transaction body can include the same upper validity bound
////   as the real transaction.
//// - Datum hashes and reference scripts are not allowed in any of the outputs.
////   Inline datums are allowed and are serialized with the canonical
////   Plutus-data encoding used here.
//// - The script data hash shape is fixed for each transition. No extra Plutus
////   redeemers or languages may appear beyond the shape reconstructed for that
////   transition.
//// - The governance mint redeemer index is expected to be `0`, and stored
////   redeemer indices and execution budgets must match the transaction's
////   actual redeemer entries. This is what binds each proposal state to its
////   transition transaction id.
//// - Language views are reconstructed as a singleton map keyed by
////   `plutus_language_id`. Supporting multiple language views requires
////   extending the hash reconstruction code.

use aiken/builtin
use aiken/cbor
use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{ScriptHash, VerificationKeyHash}
use aiken/interval.{Finite, Interval, IntervalBound}
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list
use aiken_design_patterns/linked_list/advanced as advanced_linked_list
use aiken_design_patterns/linked_list/internal.{
  validate_singular_authentic_input_helper,
}
use aiken_design_patterns/stake_validator
use cardano/address.{Address, Inline, Pointer, Script, VerificationKey}
use cardano/assets.{AssetName, Lovelace, PolicyId, Value}
use cardano/governance.{
  GovernanceActionId, ProposalProcedure, ProtocolParameters,
}
use cardano/governance/protocol_parameters
use cardano/transaction.{
  DatumHash, InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}

const root_key: linked_list.RootKey = "PROPOSALS_ROOT"

const node_key_prefix: linked_list.NodeKeyPrefix = "BUILTIN_INDEX_"

const node_key_prefix_length: linked_list.NodeKeyPrefixLength =
  bytearray.length(node_key_prefix)

/// Namespace for proposals that show their target builtin cost has gone live.
/// This out-of-list UTxO is needed to free up the spot for other proposals,
/// since there is no guarantee their required scripts succeed or not.
const passed_proposal_prefix: ByteArray = "PASS"

const passed_proposal_prefix_length: Int =
  bytearray.length(passed_proposal_prefix)

/// Byte length of a Cardano script hash.
const script_hash_byte_count: Int = 28

/// This determines the supported number of builtins carried in a cost model.
/// For example, the current Plutus V3 cost model has 350 elements, so four bytes
/// are more than enough.
const node_key_byte_count: Int = 4

/// One hour max time between creating the proposal node and submitting the
/// coupled governance action.
const time_between_proposal_and_gov_action: Int = 60 * 60 * 1_000

/// Ten minutes maximum validity range span to prevent upper bounds too far in
/// the future.
const max_validity_range_span: Int = 10 * 60 * 1_000

/// Cost models in protocol parameters are a map from Plutus language
/// identifiers to ordered lists of integer costs. This is the map key for the
/// language selected by this contract and must track its compilation target.
const plutus_language_id = 2

const serialised_plutus_language_id = cbor.serialise(plutus_language_id)

pub type Empty =
  ByteArray

/// `cost_model_prefix` includes the cost model's definite-array CBOR header and
/// exactly the complete integer entries before the builtin selected by the node
/// key. `cost_model_postfix` starts immediately after that builtin's integer
/// and preserves the rest of the model byte-for-byte. An `Initialized` model
/// inserts `cbor.serialise(initial_builtin_cost)` between those fields. A
/// `GovernanceActionSubmitted` model inserts
/// `cbor.serialise(acceptance_builtin_cost)` between them.
///
/// `subject_script_hash` identifies a stable withdrawal script to which the
/// subject contract delegates authorization. Its 28-byte hash is encoded after
/// `PASS` in the resulting token name. `required_script_for_final_burn` is a
/// separate, proposal-specific withdrawal script that enforces the final action.
pub type Proposal {
  Initialized {
    proposer: Address,
    subject_script_hash: ScriptHash,
    initialization_script_data_hash: ByteArray,
    spend_redeemer_index: Int,
    cost_model_prefix: ByteArray,
    initial_builtin_cost: Int,
    cost_model_postfix: ByteArray,
    acceptance_builtin_cost: Int,
    spend_cpu: Int,
    spend_mem: Int,
    mint_cpu: Int,
    mint_mem: Int,
    must_couple_by: Int,
    required_script_for_final_burn: ScriptHash,
  }
  GovernanceActionSubmitted {
    proposer: Address,
    subject_script_hash: ScriptHash,
    gov_action_script_data_hash: ByteArray,
    spend_redeemer_index: Int,
    cost_model_prefix: ByteArray,
    acceptance_builtin_cost: Int,
    cost_model_postfix: ByteArray,
    spend_cpu: Int,
    spend_mem: Int,
    valid_until: Int,
    required_script_for_final_burn: ScriptHash,
  }
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
  anchor_spend_redeemer_index: Int,
  proposal_spend_redeemer_index: Int,
  anchor_spend_cpu: Int,
  anchor_spend_mem: Int,
  node_spend_cpu: Int,
  node_spend_mem: Int,
  mint_cpu: Int,
  mint_mem: Int,
  required_script_for_final_burn: ScriptHash,
}

pub type SpendRedeemer {
  // Spend script delegates its logic to the minting script and performs no
  // other validations.
  DelegateToMint
  // Spending and reproducing an `Initialized` proposal in the transaction that
  // submits its corresponding governance action. The reproduced proposal node
  // has `GovernanceActionSubmitted` underlying data. `ttl` authenticates the
  // transaction's upper validity bound. The anchor is the only proposal field
  // omitted from the Plutus context, so its URL bytes and data hash are supplied
  // here and authenticated through the transaction ID.
  CoupleWithGovernanceAction {
    proposal_input_index: Int,
    proposal_output_index: Int,
    ttl: Int,
    anchor_url: ByteArray,
    anchor_data_hash: ByteArray,
    collateral_inputs: ByteArray,
    collateral_output: ByteArray,
    collateral_fee: ByteArray,
  }
}

pub type MintRedeemer {
  // Initializing the list for proposals.
  Init { nonce_input_index: Int, root_output_index: Int }
  // Inserting a new `Initialized` proposal node in the list. At mint we must
  // validate that the splice targets the specified index and that
  // `acceptance_builtin_cost` increments or decrements its initial value.
  // `invalid_before` and `ttl` must be equal to the transaction's slot numbers.
  // These are needed since the contract's endpoint requires the deadline to be
  // in a specific time in the future with a small validity range.
  AddProposal {
    anchor_output_index: Int,
    proposal_node_output_index: Int,
    invalid_before: Int,
    ttl: Int,
    collateral_inputs: ByteArray,
    collateral_output: ByteArray,
    collateral_fee: ByteArray,
  }
  // Removing a proposal which its target builtin has gone live. This endpoint
  // also mints a subject-withdrawal-bound `PASS` token outside the list
  // namespace.
  MintPassedProposal {
    anchor_input_outref: OutputReference,
    anchor_output_index: Int,
    passed_proposal_output_index: Int,
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
  //
  anchor_output_index: Int,
  proposal_node_output_index: Int,
  invalid_before: Int,
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
    validity_range,
    id,
    ..
  } = tx

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

    // 1. Lovelace of the anchor element must be preserved.
    expect anchor_lovelace_change >= 0

    // 2. Proposal node's underlying data must be `Initialized`.
    expect Initialized {
      proposer,
      subject_script_hash,
      initialization_script_data_hash,
      spend_redeemer_index,
      cost_model_prefix,
      initial_builtin_cost,
      cost_model_postfix,
      acceptance_builtin_cost,
      spend_cpu,
      spend_mem,
      mint_cpu,
      mint_mem,
      must_couple_by,
      ..
    } = proposal_data

    // 3. The proposer's address must have a staking part. The next step
    //    requires equality of this stake credential with the return address
    //    specified in the governance action.
    expect Address { stake_credential: Some(Inline(_)), .. } = proposer

    // 4. The stable subject withdrawal must have a canonical 28-byte hash so
    //    its PASS asset name is exactly 32 bytes.
    expect bytearray.length(subject_script_hash) == script_hash_byte_count

    // 5. The builtin's index is derived from the node's key. The array header
    //    must declare an element at that index, and the prefix must end exactly
    //    after all complete integer entries preceding it.
    let builtin_index = builtin_index_from_node_key(proposal_key)
    expect validate_cost_model_prefix(cost_model_prefix, builtin_index)

    // 6. The new cost must be the initial cost incremented or decremented by 1.
    expect or {
        acceptance_builtin_cost == initial_builtin_cost + 1,
        acceptance_builtin_cost == initial_builtin_cost - 1,
      }

    // 7. The proposal must couple with a corresponding governance action at
    //    most `time_between_proposal_and_gov_action` later.
    expect
      must_couple_by == validity_range_upper_bound + time_between_proposal_and_gov_action

    // 8. Reconstruct the baseline cost model and validate that the specified
    //    script data matches the hash.
    let baseline_cost_model =
      splice_cost_model(
        cost_model_prefix,
        initial_builtin_cost,
        cost_model_postfix,
      )
    expect
      validate_add_proposal_script_data_hash(
        initialization_script_data_hash,
        baseline_cost_model,
        spend_cpu,
        spend_mem,
        mint_cpu,
        mint_mem,
        spend_redeemer_index,
        redeemer,
      )

    // 9. Validate `initialization_script_data_hash` leads to the current transaction ID.
    expect
      id
        |> validate_add_proposal_tx_id_from_script_data_hash(
            initialization_script_data_hash,
            inputs,
            reference_inputs,
            outputs,
            network_tag,
            fee,
            invalid_before,
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

pub fn couple_with_governance_action(
  network_tag: Int,
  governance_nft_policy: PolicyId,
  gov_action_lifespan: Int,
  //
  proposal_input_index: Int,
  proposal_output_index: Int,
  ttl: Int,
  anchor_url: ByteArray,
  anchor_data_hash: ByteArray,
  collateral_inputs: ByteArray,
  collateral_output: ByteArray,
  collateral_fee: ByteArray,
  //
  own_outref: OutputReference,
  redeemer: SpendRedeemer,
  tx: Transaction,
) -> Bool {
  let Transaction {
    inputs,
    outputs,
    mint,
    reference_inputs,
    extra_signatories,
    fee,
    validity_range,
    proposal_procedures: tx_proposal_procedures,
    id,
    ..
  } = tx

  {
    let
      _proposal_address,
      proposal_lovelace_change,
      m_proposal_key,
      proposal_old_data,
      proposal_new_data,
      _proposal_link,
    <-
      linked_list.spend_for_updating_elements_data(
        proposal_input_index,
        proposal_output_index,
        own_outref,
        inputs,
        outputs,
        mint,
      )

    // 1. Lovelace of the proposal node must be preserved.
    expect proposal_lovelace_change >= 0

    // 2. The spent element must be a node (TODO: this might not be needed).
    expect Some(_) = m_proposal_key

    // 3. The spent node's data must be `Initialized`.
    expect Initialized {
      proposer: prev_proposer,
      subject_script_hash: prev_subject_script_hash,
      cost_model_prefix: prev_cost_model_prefix,
      initial_builtin_cost,
      cost_model_postfix: prev_cost_model_postfix,
      acceptance_builtin_cost: prev_acceptance_builtin_cost,
      must_couple_by,
      required_script_for_final_burn: prev_required_script_for_final_burn,
      ..
    } = proposal_old_data

    // 4. The reproduced node's data must be `GovernanceActionSubmitted`.
    expect GovernanceActionSubmitted {
      proposer,
      subject_script_hash,
      gov_action_script_data_hash,
      spend_redeemer_index,
      cost_model_prefix,
      acceptance_builtin_cost,
      cost_model_postfix,
      spend_cpu,
      spend_mem,
      valid_until,
      required_script_for_final_burn,
    } = proposal_new_data

    // 5. The splice's non-target bytes, proposer, accepted builtin cost,
    //    subject withdrawal, proposal expiry, and final-action withdrawal must
    //    be preserved.
    expect cost_model_prefix == prev_cost_model_prefix
    expect cost_model_postfix == prev_cost_model_postfix
    expect proposer == prev_proposer
    expect subject_script_hash == prev_subject_script_hash
    expect acceptance_builtin_cost == prev_acceptance_builtin_cost
    expect required_script_for_final_burn == prev_required_script_for_final_burn

    // 6. The governance action must be submitted within the coupling window.
    expect validity_range |> interval.is_entirely_before(must_couple_by)

    // 7. Expiry of the proposal node is determined by the list's parameter.
    //    This means whenever the lifespan of governance actions changes due to
    //    protocol parameter changes (epoch count and/or slot length), a new
    //    list instance must be used.
    expect valid_until == must_couple_by + gov_action_lifespan

    // 8. Reconstruct the live baseline model and validate that the specified
    //    script data matches the hash.
    let baseline_cost_model =
      splice_cost_model(
        prev_cost_model_prefix,
        initial_builtin_cost,
        prev_cost_model_postfix,
      )
    expect
      validate_spend_only_script_data_hash(
        gov_action_script_data_hash,
        baseline_cost_model,
        spend_cpu,
        spend_mem,
        spend_redeemer_index,
        redeemer,
      )

    // 9. Only one proposal procedure must exist in the transaction.
    expect [ProposalProcedure { deposit, return_address, governance_action }] =
      tx_proposal_procedures

    // 10. The deposit reward address must match the stake credential of the
    //    proposer's address.
    expect Some(Inline(return_address)) == proposer.stake_credential

    expect ProtocolParameters { ancestor, new_parameters, guardrails } =
      governance_action

    // 11. The proposed cost model for the selected Plutus language must preserve
    //     every non-target entry and replace only the selected builtin cost.
    expect Some(raw_cost_models) =
      protocol_parameters.cost_models(new_parameters)
    let expected_cost_model =
      splice_cost_model(
        prev_cost_model_prefix,
        acceptance_builtin_cost,
        prev_cost_model_postfix,
      )
    expect
      raw_cost_models_to_ledger_encoding(
        raw_cost_models,
        prev_cost_model_prefix,
      ) == expected_cost_model

    // 12. Reconstruct the ledger proposal procedure. Its anchor is the only
    //     part unavailable from the script context.
    let reward_account =
      when return_address is {
        VerificationKey(hash) ->
          builtin.cons_bytearray(0xe0 + network_tag, hash)
        Script(hash) -> builtin.cons_bytearray(0xf0 + network_tag, hash)
      }
    let serialised_ancestor =
      when ancestor is {
        None -> #"f6"
        Some(GovernanceActionId { transaction, proposal_procedure }) ->
          serialise_list_of_two(
            cbor.serialise(transaction),
            cbor.serialise(proposal_procedure),
          )
      }
    // The reconstructed action contains exactly one parameter update: the
    // singleton cost-model map at protocol-parameter index 18.
    // Any other shape produces a different transaction ID.
    let serialised_new_parameters =
      #"a112a1"
        |> bytearray.concat(serialised_plutus_language_id)
        |> bytearray.concat(expected_cost_model)
    let serialised_guardrails =
      when guardrails is {
        None -> #"f6"
        Some(script_hash) -> cbor.serialise(script_hash)
      }
    let serialised_anchor =
      serialise_list_of_two(
        serialise_cbor_head(3, bytearray.length(anchor_url))
          |> bytearray.concat(anchor_url),
        cbor.serialise(anchor_data_hash),
      )
    let serialised_proposal_procedures =
      #"d901028184"
        |> bytearray.concat(cbor.serialise(deposit))
        |> bytearray.concat(cbor.serialise(reward_account))
        |> bytearray.concat(#"8400")
        |> bytearray.concat(serialised_ancestor)
        |> bytearray.concat(serialised_new_parameters)
        |> bytearray.concat(serialised_guardrails)
        |> bytearray.concat(serialised_anchor)

    // 13. Validate `gov_action_script_data_hash` leads to the current
    //     transaction ID.
    expect
      id
        |> validate_tx_id_from_script_data_hash_with_proposal_procedures(
            gov_action_script_data_hash,
            inputs,
            reference_inputs,
            outputs,
            network_tag,
            fee,
            ttl,
            serialised_proposal_procedures,
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

pub fn mint_passed_proposal(
  network_tag: Int,
  governance_nft_policy: PolicyId,
  //
  anchor_input_outref: OutputReference,
  anchor_output_index: Int,
  passed_proposal_output_index: Int,
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
    anchor_spend_redeemer_index,
    proposal_spend_redeemer_index,
    anchor_spend_cpu,
    anchor_spend_mem,
    node_spend_cpu,
    node_spend_mem,
    mint_cpu,
    mint_mem,
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
    expect GovernanceActionSubmitted {
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

  // 5. The proposer must receive a pure ADA output carrying at least the
  //    finalized `PASS` UTxO's lovelace. No datum, no reference script.
  expect
    outputs
      |> list.expect_at(proposer_output_index)
      |> validate_proposer_reimbursement(proposer, passed_utxo_lovelace)

  // 6. The stable subject withdrawal encoded after `PASS` must execute.
  expect
    stake_validator.validate_withdraw_minimal(
      withdraw_script_hash: subject_script_hash,
      withdrawals: withdrawals,
      withdrawal_index: subject_withdrawal_index,
    )

  // 7. The proposal-specific final-action withdrawal must also execute.
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
    expect removing_node_data: Proposal = removing_node_data
    let proposer =
      when removing_node_data is {
        Initialized { proposer, must_couple_by, .. } -> {
          expect validity_range |> interval.is_entirely_after(must_couple_by)
          proposer
        }
        GovernanceActionSubmitted { proposer, valid_until, .. } -> {
          expect validity_range |> interval.is_entirely_after(valid_until)
          proposer
        }
      }

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
  mint: Value,
) -> Bool {
  expect [Pair(burnt_token_name, burn_quantity)] =
    mint |> assets.tokens(governance_nft_policy) |> dict.to_pairs
  and {
    burn_quantity == -1,
    burnt_token_name == passed_proposal_asset_name(recognized_script_hash),
  }
}

/// Decodes a given CBOR byte array into an `Int`.
pub fn cbor_int_to_int(cbor_int: ByteArray) -> Int {
  let header = bytearray.at(cbor_int, 0)
  let major_type = header / 32
  let additional_info = header % 32

  expect major_type == 0 || major_type == 1

  let n, next_cursor <- cbor_int_payload(cbor_int, 0, additional_info)

  expect next_cursor == bytearray.length(cbor_int)

  let is_canonical =
    if additional_info == 24 {
      n >= 24
    } else if additional_info == 25 {
      n >= 256
    } else if additional_info == 26 {
      n >= 65536
    } else if additional_info == 27 {
      n >= 4294967296
    } else {
      True
    }

  expect is_canonical

  if major_type == 0 {
    n
  } else {
    -1 - n
  }
}

/// Read an entry from a cost-model byte array whose exact bytes are
/// authenticated as a ledger language view by the enclosing validation. This
/// function assumes every array entry is a signed CBOR integer and must not be
/// used on an unauthenticated byte array.
pub fn builtin_cost_at(cost_model: ByteArray, index: Int) -> Int {
  let length, cursor <- process_cost_model_header(cost_model)

  expect index >= 0
  expect index < length

  do_builtin_cost_at(cost_model, cursor, 0, index)
}

pub fn validate_add_proposal_script_data_hash(
  script_data_hash: ByteArray,
  cost_model: ByteArray,
  spend_cpu: Int,
  spend_mem: Int,
  mint_cpu: Int,
  mint_mem: Int,
  spend_redeemer_index: Int,
  mint_redeemer: MintRedeemer,
) -> Bool {
  let spend_redeemer: SpendRedeemer = DelegateToMint

  let redeemer_entries =
    serialise_redeemer_entry(
      0,
      spend_redeemer_index,
      serialise_plutus_data(spend_redeemer),
      serialise_budget(spend_mem, spend_cpu),
    )
      |> bytearray.concat(
          serialise_redeemer_entry(
            1,
            0,
            serialise_plutus_data(mint_redeemer),
            serialise_budget(mint_mem, mint_cpu),
          ),
        )

  validate_script_data_hash(script_data_hash, cost_model, 2, redeemer_entries)
}

pub fn validate_spend_only_script_data_hash(
  script_data_hash: ByteArray,
  cost_model: ByteArray,
  spend_cpu: Int,
  spend_mem: Int,
  spend_redeemer_index: Int,
  spend_redeemer: SpendRedeemer,
) -> Bool {
  let redeemer_entry =
    serialise_redeemer_entry(
      0,
      spend_redeemer_index,
      serialise_plutus_data(spend_redeemer),
      serialise_budget(spend_mem, spend_cpu),
    )

  validate_script_data_hash(script_data_hash, cost_model, 1, redeemer_entry)
}

fn validate_script_data_hash(
  script_data_hash: ByteArray,
  cost_model: ByteArray,
  redeemer_count: Int,
  redeemer_entries: ByteArray,
) -> Bool {
  let redeemers = serialise_definite_list(redeemer_count, redeemer_entries)
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
  mint_redeemer: MintRedeemer,
) -> Bool {
  let spend_redeemer: SpendRedeemer = DelegateToMint
  let spend_redeemer_data = serialise_plutus_data(spend_redeemer)
  let anchor_spend_budget = serialise_budget(anchor_spend_mem, anchor_spend_cpu)
  let proposal_spend_budget =
    serialise_budget(proposal_spend_mem, proposal_spend_cpu)

  let redeemers =
    serialise_definite_list(
      3,
      serialise_redeemer_entry(
        0,
        anchor_spend_redeemer_index,
        spend_redeemer_data,
        anchor_spend_budget,
      )
        |> bytearray.concat(
            serialise_redeemer_entry(
              0,
              proposal_spend_redeemer_index,
              spend_redeemer_data,
              proposal_spend_budget,
            ),
          )
        |> bytearray.concat(
            serialise_redeemer_entry(
              1,
              0,
              serialise_plutus_data(mint_redeemer),
              serialise_budget(mint_mem, mint_cpu),
            ),
          ),
    )

  let language_views =
    #"a1"
      |> bytearray.concat(serialised_plutus_language_id)
      |> bytearray.concat(cost_model)

  builtin.blake2b_256(bytearray.concat(redeemers, language_views)) == script_data_hash
}

/// Transaction-body reconstruction is primarily referenced from Effectstream's
/// inverse-whirlpool implementation at:
/// https://github.com/effectstream/effectstream/blob/0b70d63a217676ce52748a2cd267f5cbed1109e4/packages/cardano-contracts/inverse-whirlpool/validators/whirl.ak#L261-L291
/// https://github.com/effectstream/effectstream/blob/0b70d63a217676ce52748a2cd267f5cbed1109e4/packages/cardano-contracts/inverse-whirlpool/lib/inverse_whirlpool/conversion.ak#L12-L126
/// `network_tag` is the four-bit tag encoded in every reconstructed output
/// address.
pub fn validate_add_proposal_tx_id_from_script_data_hash(
  tx_id: ByteArray,
  script_data_hash: ByteArray,
  inputs: List<Input>,
  reference_inputs: List<Input>,
  outputs: List<Output>,
  network_tag: Int,
  fee: Lovelace,
  invalid_before: Int,
  ttl: Int,
  mint: Value,
  extra_signatories: List<VerificationKeyHash>,
  collateral_inputs: ByteArray,
  collateral_output: ByteArray,
  collateral_fee: ByteArray,
) -> Bool {
  do_validate_tx_id_from_script_data_hash(
    tx_id,
    script_data_hash,
    inputs,
    reference_inputs,
    outputs,
    network_tag,
    fee,
    ttl,
    extra_signatories,
    collateral_inputs,
    collateral_output,
    collateral_fee,
    #"ac",
    #"08" |> bytearray.concat(cbor.serialise(invalid_before)),
    #"09" |> bytearray.concat(cbor.serialise(assets.to_dict(mint))),
    "",
  )
}

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
  do_validate_tx_id_from_script_data_hash(
    tx_id,
    script_data_hash,
    inputs,
    reference_inputs,
    outputs,
    network_tag,
    fee,
    ttl,
    extra_signatories,
    collateral_inputs,
    collateral_output,
    collateral_fee,
    #"ab",
    "",
    #"09" |> bytearray.concat(cbor.serialise(assets.to_dict(mint))),
    "",
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
  ttl: Int,
  serialised_proposal_procedures: ByteArray,
  extra_signatories: List<VerificationKeyHash>,
  collateral_inputs: ByteArray,
  collateral_output: ByteArray,
  collateral_fee: ByteArray,
) -> Bool {
  do_validate_tx_id_from_script_data_hash(
    tx_id,
    script_data_hash,
    inputs,
    reference_inputs,
    outputs,
    network_tag,
    fee,
    ttl,
    extra_signatories,
    collateral_inputs,
    collateral_output,
    collateral_fee,
    #"ab",
    "",
    "",
    #"14" |> bytearray.concat(serialised_proposal_procedures),
  )
}

pub fn validate_tx_id_from_script_data_hash_without_mint_and_proposals(
  tx_id: ByteArray,
  script_data_hash: ByteArray,
  inputs: List<Input>,
  reference_inputs: List<Input>,
  outputs: List<Output>,
  network_tag: Int,
  fee: Lovelace,
  ttl: Int,
  extra_signatories: List<VerificationKeyHash>,
  collateral_inputs: ByteArray,
  collateral_output: ByteArray,
  collateral_fee: ByteArray,
) -> Bool {
  do_validate_tx_id_from_script_data_hash(
    tx_id,
    script_data_hash,
    inputs,
    reference_inputs,
    outputs,
    network_tag,
    fee,
    ttl,
    extra_signatories,
    collateral_inputs,
    collateral_output,
    collateral_fee,
    #"aa",
    "",
    "",
    "",
  )
}

fn do_validate_tx_id_from_script_data_hash(
  tx_id: ByteArray,
  script_data_hash: ByteArray,
  inputs: List<Input>,
  reference_inputs: List<Input>,
  outputs: List<Output>,
  network_tag: Int,
  fee: Lovelace,
  ttl: Int,
  extra_signatories: List<VerificationKeyHash>,
  collateral_inputs: ByteArray,
  collateral_output: ByteArray,
  collateral_fee: ByteArray,
  tx_body_map_header: ByteArray,
  field_8: ByteArray,
  field_9: ByteArray,
  field_20: ByteArray,
) -> Bool {
  // Transaction collections are subject to the module-level implicit maximum
  // of 23 entries. Keeping that precondition off-chain avoids charging every
  // supported transition for generalized CBOR list-length handling.
  expect network_tag >= 0 && network_tag <= 15

  let serialised_inputs = serialise_tx_inputs(inputs)
  let serialised_reference_inputs = serialise_tx_inputs(reference_inputs)
  let serialised_outputs = serialise_tx_outputs(outputs, network_tag)
  let serialised_fee = cbor.serialise(fee)
  let serialised_script_data_hash = cbor.serialise(script_data_hash)
  let serialised_extra_signatories =
    serialise_extra_signatories(extra_signatories)

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
      |> bytearray.concat(field_8)
      |> bytearray.concat(field_9)
      |> bytearray.concat(#"0b")
      |> bytearray.concat(serialised_script_data_hash)
      |> bytearray.concat(#"0d")
      |> bytearray.concat(collateral_inputs)
      |> bytearray.concat(#"0e")
      |> bytearray.concat(serialised_extra_signatories)
      |> bytearray.concat(#"10")
      |> bytearray.concat(collateral_output)
      |> bytearray.concat(#"11")
      |> bytearray.concat(collateral_fee)
      |> bytearray.concat(#"12")
      |> bytearray.concat(serialised_reference_inputs)
      |> bytearray.concat(field_20)

  let reconstructed_tx_id = builtin.blake2b_256(tx_body)

  reconstructed_tx_id == tx_id
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

fn serialise_redeemer_entry(
  tag: Int,
  index: Int,
  redeemer_data: ByteArray,
  budget: ByteArray,
) -> ByteArray {
  #"84"
    |> bytearray.concat(cbor.serialise(tag))
    |> bytearray.concat(cbor.serialise(index))
    |> bytearray.concat(redeemer_data)
    |> bytearray.concat(budget)
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

  #"d90102" |> bytearray.concat(serialise_definite_list(length, body))
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
  let Output { address, value, datum, reference_script } = output

  when datum is {
    NoDatum -> {
      expect None = reference_script

      #"82"
        |> bytearray.concat(serialise_address(address, network_tag))
        |> bytearray.concat(serialise_output_value(value))
    }
    DatumHash(_) -> fail @"datum hashes cannot be recovered"
    InlineDatum(data) -> {
      expect None = reference_script

      #"a3"
        |> bytearray.concat(#"00")
        |> bytearray.concat(serialise_address(address, network_tag))
        |> bytearray.concat(#"01")
        |> bytearray.concat(serialise_output_value(value))
        |> bytearray.concat(
            serialise_inline_output_datum(serialise_plutus_data(data)),
          )
    }
  }
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
    serialise_cbor_tag(102)
      |> bytearray.concat(
          serialise_definite_list(
            2,
            cbor.serialise(constructor)
              |> bytearray.concat(serialised_fields),
          ),
        )
  }
}

fn serialise_plutus_list_data(data: Data) -> ByteArray {
  serialise_plutus_data_list(builtin.un_list_data(data))
}

fn serialise_plutus_map_data(data: Data) -> ByteArray {
  let
    length,
    body,
  <-
    list.foldr2(
      builtin.un_map_data(data),
      0,
      "",
      fn(pair, length, body, return) {
        return(
          length + 1,
          serialise_plutus_data(pair.1st)
            |> bytearray.concat(serialise_plutus_data(pair.2nd))
            |> bytearray.concat(body),
        )
      },
    )

  serialise_cbor_head(5, length) |> bytearray.concat(body)
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
  let non_ada = value |> assets.without_lovelace |> assets.to_dict
  let multi_asset = cbor.serialise(non_ada)

  if multi_asset == #"a0" {
    lovelace
  } else {
    #"82" |> bytearray.concat(lovelace) |> bytearray.concat(multi_asset)
  }
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
  expect value >= 0

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
  let
    length,
    body,
  <-
    list.foldr2(
      extra_signatories,
      0,
      "",
      fn(signature, length, body, return) {
        return(length + 1, bytearray.concat(cbor.serialise(signature), body))
      },
    )

  #"d90102" |> bytearray.concat(serialise_definite_list(length, body))
}

fn serialise_definite_list(length: Int, body: ByteArray) -> ByteArray {
  // Callers use this only for fixed-size arrays or transaction collections that
  // satisfy the documented implicit maximum of 23 entries.
  builtin.cons_bytearray(0x80 + length, body)
}

/// Convert the raw `Data<Pairs<Int, List<Int>>>` cost models retrieved using
/// `protocol_parameters.cost_models()` to the exact definite array encoding
/// used by the ledger language view. It is expected that only one cost model
/// array is present within the map (same key as the hardcoded laguage ID). The
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

fn cbor_int_payload(
  cost_model: ByteArray,
  cursor: Int,
  additional_info: Int,
  return: fn(Int, Int) -> result,
) -> result {
  if additional_info < 24 {
    return(additional_info, cursor + 1)
  } else if additional_info == 24 {
    return(bytearray.at(cost_model, cursor + 1), cursor + 2)
  } else if additional_info == 25 {
    return(
      bytearray.slice(cost_model, cursor + 1, cursor + 2)
        |> bytearray.to_int_big_endian,
      cursor + 3,
    )
  } else if additional_info == 26 {
    return(
      bytearray.slice(cost_model, cursor + 1, cursor + 4)
        |> bytearray.to_int_big_endian,
      cursor + 5,
    )
  } else if additional_info == 27 {
    return(
      bytearray.slice(cost_model, cursor + 1, cursor + 8)
        |> bytearray.to_int_big_endian,
      cursor + 9,
    )
  } else {
    fail @"invalid cbor integer"
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

fn do_builtin_cost_at(
  cost_model: ByteArray,
  cursor: Int,
  current_index: Int,
  target_index: Int,
) -> Int {
  if current_index == target_index {
    let header = bytearray.at(cost_model, cursor)
    let major_type = header / 32
    let additional_info = header % 32

    // This intentionally accepts any CBOR integer encoding that decodes to the
    // selected cost, without re-checking canonical/minimal integer form. The
    // exact cost-model bytes are authenticated separately by script_data_hash.
    let n, _next_cursor <- cbor_int_payload(cost_model, cursor, additional_info)
    if major_type == 0 {
      n
    } else {
      -1 - n
    }
  } else {
    do_builtin_cost_at(
      cost_model,
      next_cost_model_int_cursor(cost_model, cursor),
      current_index + 1,
      target_index,
    )
  }
}
