//// This is the global linked list that protocols using this pattern share.
////
//// SECURITY ASSUMPTION: `MintPassedProposal` observes the live cost model for
//// the selected Plutus language; it cannot inspect governance history or prove
//// which `GovernanceActionId` enacted that model. A single global list resolves
//// conflicts among proposals that use this pattern, but cannot prevent a
//// matching governance action from being submitted outside it. If enacted, that
//// action also satisfies the passage proof for the listed proposal. Therefore
//// everyone able to submit or support a matching action must operationally
//// coordinate through this list. This is a trusted governance condition, not a
//// property enforced by the validator.
////
//// Once passage is observed, `MintPassedProposal` removes the active proposal
//// node and mints an out-of-list `PassedProposal`. `FinalizePassedProposal`
//// later burns it and executes the proposal's required script.
//// `MintPassedProposal` carries the ledger pointers and execution budgets used
//// to authenticate the passage transaction's script-data hash.
////
//// `AddProposal` receives a reference-input index for the configuration UTxO
//// that holds the governance-action lifespan. The UTxO carries the
//// `GOV_ACTION_LIFESPAN` NFT and an inline integer datum. The
//// `governance_parameters` validator below controls this configuration with a
//// bootstrap nonce and a threshold of authorized signers. Its integer lifespan
//// is trusted multisig-selected configuration: `AddProposal` authenticates and
//// adds it to the insertion deadline, but does not derive or semantically bound
//// it. The multisig must choose and review a value covering the conservative
//// governance settlement horizon after proposal insertion: voting, enactment,
//// any assumed delaying-action extension, observation, and minting an
//// out-of-list `PassedProposal`. Finalization may occur later without a
//// deadline.

use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use aiken_design_patterns/governance_validation as gov
use aiken_design_patterns/linked_list
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction,
}
use env

/// A single governance proposal list shared by protocol validators. Its address
/// is dedicated to this pattern's root, proposal-node, and passed-proposal
/// UTxOs; it is not a general-purpose payment destination.
validator governance(
  nonce: OutputReference,
  gov_action_lifespan_policy: PolicyId,
) {
  spend(
    _datum: Option<Data>,
    _redeemer: gov.SpendRedeemer,
    own_outref: OutputReference,
    tx: Transaction,
  ) {
    let Transaction { inputs, mint, .. } = tx

    expect Input {
      output: Output {
        address: Address { payment_credential: Script(own_policy), .. },
        ..
      },
      ..
    } =
      inputs
        |> list.expect_find(fn(input) { input.output_reference == own_outref })

    linked_list.spend_for_adding_or_removing_an_element(own_policy, mint)
  }

  mint(redeemer: gov.MintRedeemer, own_policy: PolicyId, tx: Transaction) {
    when redeemer is {
      gov.Init { nonce_input_index, root_output_index } ->
        gov.init(nonce, nonce_input_index, root_output_index, own_policy, tx)
      gov.AddProposal {
        gov_action_lifespan_reference_input_index,
        redeemer_encoding,
        anchor_output_index,
        proposal_node_output_index,
        initial_builtin_cost,
        redeemer_metadata,
        other_language_cost_models,
        body_witness,
      } ->
        gov.add_proposal(
          env.network_tag,
          own_policy,
          gov_action_lifespan_policy,
          gov_action_lifespan_reference_input_index,
          redeemer_encoding,
          anchor_output_index,
          proposal_node_output_index,
          initial_builtin_cost,
          redeemer_metadata,
          other_language_cost_models,
          body_witness,
          tx,
        )
      gov.MintPassedProposal {
        redeemer_encoding,
        anchor_input_outref,
        anchor_output_index,
        passed_proposal_output_index,
        anchor_spend_redeemer_index,
        proposal_spend_redeemer_index,
        anchor_spend_cpu,
        anchor_spend_mem,
        node_spend_cpu,
        node_spend_mem,
        mint_cpu,
        mint_mem,
        ttl,
        collateral_inputs,
        collateral_output,
        collateral_fee,
      } ->
        gov.mint_passed_proposal(
          env.network_tag,
          own_policy,
          redeemer_encoding,
          anchor_input_outref,
          anchor_output_index,
          passed_proposal_output_index,
          anchor_spend_redeemer_index,
          proposal_spend_redeemer_index,
          anchor_spend_cpu,
          anchor_spend_mem,
          node_spend_cpu,
          node_spend_mem,
          mint_cpu,
          mint_mem,
          ttl,
          collateral_inputs,
          collateral_output,
          collateral_fee,
          redeemer,
          tx,
        )
      gov.FinalizePassedProposal {
        proposer_output_index,
        subject_withdrawal_index,
        required_script_withdrawal_index,
      } ->
        gov.finalize_passed_proposal(
          own_policy,
          proposer_output_index,
          subject_withdrawal_index,
          required_script_withdrawal_index,
          tx,
        )
      gov.RemoveExpiredProposal {
        anchor_input_outref,
        anchor_output_index,
        proposer_output_index,
      } ->
        gov.remove_expired_proposal(
          anchor_input_outref,
          anchor_output_index,
          proposer_output_index,
          own_policy,
          tx,
        )
    }
  }

  else(_) {
    fail
  }
}

/// Multisig-controlled configuration UTxO for the governance-action lifespan.
/// The inline integer is trusted configuration: threshold-authorized updates
/// preserve its type and NFT, but this validator does not derive or restrict its
/// semantic range. Its minting-policy ID and spending-script hash are both this
/// validator's applied hash.
validator governance_parameters(
  bootstrap_nonce: OutputReference,
  authorized_signers: List<VerificationKeyHash>,
  threshold: Int,
) {
  spend(
    _datum: Option<Int>,
    continuation_output_index: Int,
    own_outref: OutputReference,
    tx: Transaction,
  ) {
    let Transaction { inputs, outputs, extra_signatories, .. } = tx

    expect Input {
      output: Output {
        address: Address { payment_credential: Script(own_policy), .. },
        value: input_value,
        ..
      },
      ..
    } =
      inputs
        |> list.expect_find(fn(input) { input.output_reference == own_outref })

    expect
      input_value
        |> assets.has_nft_strict(own_policy, gov.gov_action_lifespan_asset_name)

    expect authorized_signers == list.unique(authorized_signers)
    expect
      list.foldl(
        authorized_signers,
        0,
        fn(authorized_signer, signer_count) {
          if extra_signatories |> list.has(authorized_signer) {
            signer_count + 1
          } else {
            signer_count
          }
        },
      ) >= threshold

    expect Output {
      address: Address { payment_credential: Script(continuing_policy), .. },
      value: continuing_value,
      datum: InlineDatum(continuing_lifespan_data),
      reference_script: None,
    } = outputs |> list.expect_at(continuation_output_index)

    expect continuing_policy == own_policy
    expect
      continuing_value
        |> assets.has_nft_strict(own_policy, gov.gov_action_lifespan_asset_name)
    expect _: Int = continuing_lifespan_data

    True
  }

  mint(output_index: Int, own_policy: PolicyId, tx: Transaction) {
    let Transaction { inputs, outputs, mint, .. } = tx

    expect
      inputs
        |> list.any(fn(input) { input.output_reference == bootstrap_nonce })
    expect
      mint == assets.from_asset(
        own_policy,
        gov.gov_action_lifespan_asset_name,
        1,
      )

    expect Output {
      address: Address { payment_credential: Script(output_policy), .. },
      value: output_value,
      datum: InlineDatum(lifespan_data),
      reference_script: None,
    } = outputs |> list.expect_at(output_index)

    expect output_policy == own_policy
    expect
      output_value
        |> assets.has_nft_strict(own_policy, gov.gov_action_lifespan_asset_name)
    expect _: Int = lifespan_data
    expect authorized_signers == list.unique(authorized_signers)
    expect threshold > 0
    expect threshold <= list.length(authorized_signers)

    True
  }

  else(_) {
    fail
  }
}
