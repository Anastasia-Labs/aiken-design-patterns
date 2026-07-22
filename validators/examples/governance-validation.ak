use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken_design_patterns/governance_validation as gov
use aiken_design_patterns/stake_validator
use cardano/address.{Address, Credential, Script}
use cardano/assets.{AssetName, Lovelace, PolicyId}
use cardano/certificate.{Certificate, RegisterCredential}
use cardano/transaction.{
  InlineDatum, Input, Mint, Output, OutputReference, Redeemer, Transaction,
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
    redeemer: Pair<Int, Int>,
    own_outref: OutputReference,
    tx: Transaction,
  ) {
    let Transaction { inputs, withdrawals, .. } = tx

    let Pair(own_input_index, withdrawal_index) = redeemer

    // 1. Find own script hash using the input index provided via the redeemer.
    expect Input {
      output_reference,
      output: Output {
        address: Address { payment_credential: Script(own_script_hash), .. },
        ..
      },
    } = inputs |> list.expect_at(own_input_index)
    expect output_reference == own_outref

    // 2. Delegate this subject's spending authorization to its stable
    //    withdrawal script. That script may share this validator's hash or be a
    //    separate validator.
    expect
      stake_validator.validate_withdraw_minimal(
        withdraw_script_hash: own_script_hash,
        withdrawals: withdrawals,
        withdrawal_index: withdrawal_index,
      )

    // Done.
    True
  }

  // This is the stable subject withdrawal when the parameters contract uses
  // its own applied hash as its subject script.
  withdraw(
    governance_finalize_context_index: Int,
    own_credential: Credential,
    tx: Transaction,
  ) {
    let Transaction { mint, redeemers, .. } = tx
    expect Script(subject_script_hash) = own_credential

    // 1. The burned PASS token must name this subject withdrawal script.
    expect
      gov.validate_recognized_pass_burn(
        governance_policy,
        subject_script_hash,
        mint,
      )

    // 2. The specified context index must point to the governance
    //    finalization endpoint.
    expect Pair(Mint(invoked_mint_script_hash),
    governance_finalize_redeemer_data) =
      redeemers |> list.expect_at(governance_finalize_context_index)
    expect invoked_mint_script_hash == governance_policy
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

  publish(_redeemer: Redeemer, certificate: Certificate, _tx: Transaction) {
    // 1. Only registration of this script's withdrawal contract is allowed.
    expect RegisterCredential { .. } = certificate

    // Done.
    True
  }

  else(_) {
    fail
  }
}

/// A sample proposal-specific final-action withdrawal script that doubles the
/// protocol fee stored in the parameters set.
validator double_the_protocol_fee(parameters_contract: ScriptHash) {
  withdraw(
    parameters_indexes: Pair<Int, Int>,
    _own_credential: Credential,
    tx: Transaction,
  ) {
    // This endpoint validates expenditure of the parameters UTxO, its
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
    // This endpoint allows registration unconditionally, while disallowing
    // deregistration entirely.
    expect RegisterCredential { .. } = certificate

    True
  }

  else(_) {
    fail
  }
}
