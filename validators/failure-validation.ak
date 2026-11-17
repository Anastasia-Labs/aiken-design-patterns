//// @hidden

use aiken/collection/list
use aiken/crypto.{ScriptHash, VerificationKeyHash}
use aiken_design_patterns/failure_validation.{
  BuiltinRedeemer, FailedTransactionWitness, FailureParameters,
}
use aiken_design_patterns/multisig_parameters
use cardano/address.{Credential}
use cardano/assets.{PolicyId}
use cardano/certificate.{Certificate, RegisterCredential}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Redeemer, Transaction,
}
use config
use env

pub type ProofMintRedeemer {
  collateral_return_input_index: Int,
  failure_parameters_reference_input_index: Int,
  witness: FailedTransactionWitness,
}

/// Execute the configured builtin on direct redeemer data or ordered inline
/// datums selected by reference-input indexes. The environment validates the
/// collected argument list's arity and types as part of preparation.
validator builtin_probe {
  withdraw(
    builtin_redeemer: BuiltinRedeemer,
    _own_credential: Credential,
    tx: Transaction,
  ) {
    let Transaction { reference_inputs, .. } = tx
    let builtin_arguments = failure_validation.resolve_builtin_arguments(
      builtin_redeemer,
      reference_inputs,
    )
    env.apply_builtin(builtin_arguments)
  }

  publish(_redeemer: Redeemer, certificate: Certificate, _tx: Transaction) {
    // Permit registration without enabling delegation.
    expect RegisterCredential { .. } = certificate
    True
  }

  else(_) {
    fail
  }
}

/// Parameters identify the withdrawal probe and the multisig configuration NFT.
/// Both scripts' environments must select the same builtin and argument
/// preparation rules. The selected reference input carries the configuration
/// NFT and an inline `FailureParameters` datum whose exact budgets authenticate
/// the failed withdrawal. A configuration update can make earlier evidence
/// ineligible when its committed budgets differ from the live parameters.
validator failure_proof(
  withdrawal_script_hash: ScriptHash,
  failure_parameters_policy: PolicyId,
) {
  mint(redeemer: ProofMintRedeemer, policy_id: PolicyId, tx: Transaction) {
    let Transaction { inputs, reference_inputs, mint, .. } = tx
    let  
        ProofMintRedeemer {
          collateral_return_input_index,
          failure_parameters_reference_input_index,
          witness,
        }
      = redeemer

    expect  
        Input {
          output: Output { value, datum: InlineDatum(parameters_data), .. },
          ..
        }
      = reference_inputs
      |> list.expect_at(failure_parameters_reference_input_index)
    expect
      value
        |> assets.has_nft_strict(
            failure_parameters_policy,
            failure_validation.failure_parameters_asset_name,
          )
    expect FailureParameters { max_mem, max_cpu }: FailureParameters = parameters_data

    let builtin_arguments <- failure_validation.validate_mint(
      own_policy: policy_id,
      withdrawal_script_hash: withdrawal_script_hash,
      withdrawal_cpu: max_cpu,
      withdrawal_mem: max_mem,
      network_tag: config.network_tag,
      inputs: inputs,
      reference_inputs: reference_inputs,
      collateral_return_input_index: collateral_return_input_index,
      mint: mint,
      witness: witness,
    )
    env.validate_builtin_arguments(builtin_arguments)
  }

  else(_) {
    fail
  }
}

/// Multisig-controlled configuration for maximum memory and CPU budgets.
/// Its applied hash is both the configuration NFT policy ID and spending-script
/// hash. The shared helpers enforce authorization and the NFT lifecycle; these
/// continuations validate only the two integer fields of `FailureParameters`.
/// The values are trusted configuration with no numeric bounds.
/// `failure_proof` references this NFT's live UTxO to authenticate those budgets.
validator failure_parameters(
  bootstrap_nonce: OutputReference,
  authorized_signers: List<VerificationKeyHash>,
  threshold: Int,
) {
  spend(
    _datum: Option<FailureParameters>,
    continuation_output_index: Int,
    own_outref: OutputReference,
    tx: Transaction,
  ) {
    let continuing_parameters_data <- multisig_parameters.validate_spend(
      authorized_signers,
      threshold,
      failure_validation.failure_parameters_asset_name,
      continuation_output_index,
      own_outref,
      tx,
    )
    expect _: FailureParameters = continuing_parameters_data

    True
  }

  mint(output_index: Int, own_policy: PolicyId, tx: Transaction) {
    let parameters_data <- multisig_parameters.validate_mint(
      bootstrap_nonce,
      authorized_signers,
      threshold,
      failure_validation.failure_parameters_asset_name,
      output_index,
      own_policy,
      tx,
    )
    expect _: FailureParameters = parameters_data

    True
  }

  else(_) {
    fail
  }
}
