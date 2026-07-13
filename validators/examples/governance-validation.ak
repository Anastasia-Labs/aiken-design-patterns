use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken_design_patterns/governance_validation as gov
use aiken_design_patterns/linked_list
use cardano/address.{Address, Credential, Script}
use cardano/assets.{AssetName, Lovelace, PolicyId}
use cardano/certificate.{Certificate, RegisterCredential}
use cardano/transaction.{
  InlineDatum, Input, Mint, Output, OutputReference, Transaction,
}

pub type ExampleParameters {
  protocol_fee: Lovelace,
}

const auth_nft_name: AssetName = "PROTOCOL_PARAMETERS"

/// Example validator that holds the UTxO that carries the protocol's
/// parameters.
validator parameters_contract(
  nonce: OutputReference,
  governance_policy: PolicyId,
) {
  spend(
    _datum: Option<ExampleParameters>,
    governance_finalize_redeemer_index: Int,
    _own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    // 1. The specified index must point to an invokation of the governance
    //    script's mint endpoint.
    expect Pair(Mint(invoked_mint_script_hash),
    governance_finalize_redeemer_data) =
      tx.redeemers |> list.expect_at(governance_finalize_redeemer_index)
    expect invoked_mint_script_hash == governance_policy

    // 2. The mint endpoint must be that of the finalize burn.
    expect gov.FinalizePassedProposal { .. } = governance_finalize_redeemer_data

    // Done.
    True
  }

  mint(output_index: Int, own_policy: PolicyId, tx: Transaction) {
    let Transaction { inputs, outputs, mint, .. } = tx

    // 1. Nonce must be spent.
    expect inputs |> list.any(fn(i) { i.output_reference == nonce })

    // 2. Output must go to a script with an inline datum and no script attached.
    expect Output {
      address: Address { payment_credential: Script(output_script_hash), .. },
      value: output_value,
      datum: InlineDatum(datum_data),
      reference_script: None,
    } = outputs |> list.expect_at(output_index)

    // 3. Destination address must be this same contract's spending script.
    expect output_script_hash == own_policy

    // 4. Output must have the auth NFT with no other assets.
    expect output_value |> assets.has_nft_strict(own_policy, auth_nft_name)

    // 5. Exactly one of the auth NFT must be minted.
    expect mint == assets.from_asset(own_policy, auth_nft_name, 1)

    // 6. The attached datum must have a proper shape. The values can be set
    //    arbitrarily at init.
    expect ExampleParameters { .. } = datum_data

    // Done.
    True
  }

  else(_) {
    fail
  }
}

/// Instance of the governance contract which the protocol parameters contracts
/// depend on.
validator governance(nonce: OutputReference, network_tag: Int) {
  spend(
    _datum: Option<Data>,
    _redeemer: gov.SpendRedeemer,
    own_outref: OutputReference,
    tx: Transaction,
  ) {
    let Transaction { inputs, mint, .. } = tx

    // 1. Find own script's hash.
    expect Input {
      output: Output {
        address: Address { payment_credential: Script(own_script_hash), .. },
        ..
      },
      ..
    } = inputs |> list.expect_find(fn(i) { i.output_reference == own_outref })

    // 2. Ensure the minting counterpart of this script is invoked.
    expect
      linked_list.spend_for_adding_or_removing_an_element(own_script_hash, mint)

    // Done.
    True
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
          anchor_output_index,
          proposal_node_output_index,
          ttl,
          network_tag,
          collateral_inputs,
          collateral_output,
          collateral_fee,
          redeemer,
          own_policy,
          tx,
        )
      gov.MintProposalPassNFT {
        anchor_input_outref,
        anchour_output_index,
        passage_utxo_output_index,
        ttl,
        collateral_inputs,
        collateral_output,
        collateral_fee,
      } ->
        gov.mint_proposal_pass_nft(
          anchor_input_outref,
          anchour_output_index,
          passage_utxo_output_index,
          ttl,
          network_tag,
          collateral_inputs,
          collateral_output,
          collateral_fee,
          redeemer,
          own_policy,
          tx,
        )
      gov.FinalizePassedProposal {
        proposer_output_index,
        proposals_withdrawal_script_index,
      } ->
        gov.finalize_passed_proposal(
          proposer_output_index,
          proposals_withdrawal_script_index,
          own_policy,
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

/// A sample proposal withdrawal script that doubles the protocol fee stored in
/// the parameters set.
validator double_the_protocol_fee(parameters_contract: ScriptHash) {
  withdraw(
    parameters_indexes: Pair<Int, Int>,
    _own_credential: Credential,
    tx: Transaction,
  ) {
    // This endpoint validate expenditure of the parameters UTxO, its
    // reproduction at the same address with an updated datum which only doubles
    // the fee field.
    let Transaction { inputs, outputs, .. } = tx

    expect Input {
      output: Output {
        address: input_address,
        value: input_value,
        datum: InlineDatum(input_datum),
        ..
      },
      ..
    } = inputs |> list.expect_at(parameters_indexes.1st)

    expect
      input_value |> assets.has_nft_strict(parameters_contract, auth_nft_name)

    expect ExampleParameters { protocol_fee } = input_datum

    let expected_output_datum: Data =
      ExampleParameters { protocol_fee: protocol_fee * 2 }

    expect Output {
      address: output_address,
      value: output_value,
      datum: InlineDatum(output_datum),
      reference_script: None,
    } = outputs |> list.expect_at(parameters_indexes.2nd)

    expect output_address == input_address
    expect
      output_value |> assets.has_nft_strict(parameters_contract, auth_nft_name)
    expect output_datum == expected_output_datum

    True
  }

  publish(_redeemer: Void, certificate: Certificate, _tx: Transaction) {
    // This endpoint allow registration unconditionally, while disallowing
    // deregistration entirely.
    expect RegisterCredential { .. } = certificate

    True
  }

  else(_) {
    fail
  }
}
