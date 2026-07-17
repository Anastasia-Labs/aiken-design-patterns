//// This is the global linked list all protocols aiming to utilize this pattern
//// should use. The important assumption is that no protocols outside this list
//// submit this sort of specific governance action proposals, i.e.
//// incrementing/decrementing a single builtin's cost.

use aiken/collection/list
use aiken_design_patterns/governance_validation as gov
use aiken_design_patterns/linked_list
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId}
use cardano/transaction.{Input, Output, OutputReference, Transaction}

/// A single governance proposal list shared by protocol validators.
validator governance(nonce: OutputReference, network_tag: Int) {
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
    } = inputs |> list.expect_find(fn(input) { input.output_reference == own_outref })

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
      gov.MarkProposalAsPassed {
        proposal_input_index,
        proposal_output_index,
        ttl,
        collateral_inputs,
        collateral_output,
        collateral_fee,
      } ->
        gov.mark_proposal_as_passed(
          network_tag,
          own_policy,
          proposal_input_index,
          proposal_output_index,
          ttl,
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
          ttl,
          collateral_inputs,
          collateral_output,
          collateral_fee,
          redeemer,
          tx,
        )
      gov.FinalizePassedProposal {
        anchor_input_outref,
        anchor_output_index,
        proposer_output_index,
        proposals_withdrawal_script_index,
      } ->
        gov.finalize_passed_proposal(
          own_policy,
          anchor_input_outref,
          anchor_output_index,
          proposer_output_index,
          proposals_withdrawal_script_index,
          tx,
        )
      gov.RemoveExpiredProposal { anchor_input_outref, anchor_output_index } ->
        gov.remove_expired_proposal(
          anchor_input_outref,
          anchor_output_index,
          own_policy,
          tx,
        )
    }
  }

  else(_) {
    fail
  }
}
