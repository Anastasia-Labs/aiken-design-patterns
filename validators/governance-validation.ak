//// This is the global linked list all protocols aiming to utilize this pattern
//// should use.
////
//// SECURITY ASSUMPTION: `MintPassedProposal` observes the live Plutus V3 cost
//// model; it cannot inspect governance history or prove which
//// `GovernanceActionId` enacted that model. An action outside this list which
//// enacts the same complete cost model would therefore also satisfy the passage
//// proof for the listed proposal. All actions which increment or decrement one
//// builtin cost in this way must be coordinated through this single list.
////
//// Once passage is observed, `MintPassedProposal` removes the active proposal
//// node and mints an out-of-list `PassedProposal`. `FinalizePassedProposal`
//// later burns it and executes the proposal's required script.
////
//// A proposal's local deadline must also cover the deployment's conservative
//// governance settlement horizon: submission, voting, enactment, any assumed
//// bound on delaying-action lifetime extensions, observation, minting an
//// out-of-list `PassedProposal`, and later finalization. The validator does not
//// derive or enforce that deployment-specific duration.

use aiken/collection/list
use aiken_design_patterns/governance_validation as gov
use aiken_design_patterns/linked_list
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId}
use cardano/transaction.{Input, Output, OutputReference, Transaction}

/// A single governance proposal list shared by protocol validators.
validator governance(
  nonce: OutputReference,
  network_tag: Int,
  gov_action_lifespan: Int,
) {
  spend(
    _datum: Option<Data>,
    redeemer: gov.SpendRedeemer,
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

    when redeemer is {
      gov.DelegateToMint ->
        linked_list.spend_for_adding_or_removing_an_element(own_policy, mint)
      gov.CoupleWithGovernanceAction {
        proposal_input_index,
        proposal_output_index,
        ttl,
        anchor_url,
        anchor_data_hash,
        collateral_inputs,
        collateral_output,
        collateral_fee,
      } ->
        gov.couple_with_governance_action(
          network_tag,
          own_policy,
          gov_action_lifespan,
          proposal_input_index,
          proposal_output_index,
          ttl,
          anchor_url,
          anchor_data_hash,
          collateral_inputs,
          collateral_output,
          collateral_fee,
          own_outref,
          redeemer,
          tx,
        )
    }
  }

  mint(redeemer: gov.MintRedeemer, own_policy: PolicyId, tx: Transaction) {
    when redeemer is {
      gov.Init { nonce_input_index, root_output_index } ->
        gov.init(nonce, nonce_input_index, root_output_index, own_policy, tx)
      gov.AddProposal {
        anchor_output_index,
        proposal_node_output_index,
        invalid_before,
        ttl,
        collateral_inputs,
        collateral_output,
        collateral_fee,
      } ->
        gov.add_proposal(
          network_tag,
          own_policy,
          anchor_output_index,
          proposal_node_output_index,
          invalid_before,
          ttl,
          collateral_inputs,
          collateral_output,
          collateral_fee,
          redeemer,
          tx,
        )
      gov.MintPassedProposal {
        anchor_input_outref,
        anchor_output_index,
        passed_proposal_output_index,
        ttl,
        collateral_inputs,
        collateral_output,
        collateral_fee,
      } ->
        gov.mint_passed_proposal(
          network_tag,
          own_policy,
          anchor_input_outref,
          anchor_output_index,
          passed_proposal_output_index,
          ttl,
          collateral_inputs,
          collateral_output,
          collateral_fee,
          redeemer,
          tx,
        )
      gov.FinalizePassedProposal {
        proposer_output_index,
        proposals_withdrawal_script_index,
      } ->
        gov.finalize_passed_proposal(
          own_policy,
          proposer_output_index,
          proposals_withdrawal_script_index,
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
