//// This is the global linked list all protocols aiming to utilize this pattern
//// should use.
////
//// SECURITY ASSUMPTION: `MintPassedProposal` observes the live cost model for
//// the selected Plutus language; it cannot inspect governance history or prove
//// which `GovernanceActionId` enacted that model. An action outside this list
//// which enacts the same complete cost model would therefore also satisfy the
//// passage proof for the listed proposal. All actions which increment or
//// decrement one builtin cost in this way must be coordinated through this
//// single list. The intended security assumption is that an independently
//// submitted action is negligibly unlikely to receive enough governance support
//// to enact the exact same single-builtin change, with every other cost in the
//// selected model preserved, by chance.
////
//// Once passage is observed, `MintPassedProposal` removes the active proposal
//// node and mints an out-of-list `PassedProposal`. `FinalizePassedProposal`
//// later burns it and executes the proposal's required script.
//// `MintPassedProposal` carries the ledger pointers and execution budgets used
//// to authenticate the passage transaction's script-data hash.
////
//// `gov_action_lifespan` is a trusted deployment parameter covering the
//// conservative governance settlement horizon after proposal insertion:
//// voting, enactment, any assumed delaying-action extension, observation, and
//// minting an out-of-list `PassedProposal`. Finalization may occur later
//// without a deadline. The validator does not derive that deployment-specific
//// duration.

use aiken/collection/list
use aiken_design_patterns/governance_validation as gov
use aiken_design_patterns/linked_list
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId}
use cardano/transaction.{Input, Output, OutputReference, Transaction}
use env

/// A single governance proposal list shared by protocol validators.
validator governance(nonce: OutputReference, gov_action_lifespan: Int) {
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
          gov_action_lifespan,
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
