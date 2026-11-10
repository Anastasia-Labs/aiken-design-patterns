//// @hidden

use aiken/builtin
use aiken/crypto.{ScriptHash, VerificationKeyHash}
use aiken_design_patterns/failure_validation.{
  FailedTransactionWitness, FailureParameters,
}
use aiken_design_patterns/multisig_parameters
use cardano/address.{Credential, Script}
use cardano/assets.{PolicyId}
use cardano/certificate.{
  Certificate, DelegateBlockProduction, DelegateCredential,
  RegisterAndDelegateCredential, RegisterCredential, UnregisterCredential,
}
use cardano/transaction.{OutputReference, Redeemer, Transaction}
use config
use env
use tests/failure_validation/bodies
use tests/failure_validation/fixtures.{ProofFixture}

const max_mem = 17_500_000

const max_cpu = 10_000_000_000

pub type ProofMintRedeemer {
  collateral_return_input_index: Int,
  witness: FailedTransactionWitness,
}

/// Execute the configured builtin on redeemer arguments, validating their
/// arity and types as part of argument preparation.
validator builtin_probe {
  withdraw(
    builtin_arguments: Data,
    _own_credential: Credential,
    _tx: Transaction,
  ) {
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

/// The parameter identifies the withdrawal probe. Both scripts' environments
/// must select the same builtin and argument preparation rules.
validator failure_proof(withdrawal_script_hash: ScriptHash) {
  mint(redeemer: ProofMintRedeemer, policy_id: PolicyId, tx: Transaction) {
    let Transaction { inputs, mint, .. } = tx
    let ProofMintRedeemer { collateral_return_input_index, witness } = redeemer
    let builtin_arguments <- failure_validation.validate_mint(
      own_policy: policy_id,
      withdrawal_script_hash: withdrawal_script_hash,
      withdrawal_cpu: max_cpu,
      withdrawal_mem: max_mem,
      network_tag: config.network_tag,
      inputs: inputs,
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
/// This standalone configuration is not yet consumed by `failure_proof`.
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

// The empty context makes any dependence on an input or datum fail these tests.
// The ledger supplies the withdrawal credential and purpose during execution.
test withdraw__successful_builtin() {
  builtin_probe.withdraw(
    fixtures.successful_arguments,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_builtin_false() fail {
  builtin_probe.withdraw(
    fixtures.builtin_arguments,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_bad_signature() fail {
  builtin_probe.withdraw(
    fixtures.bad_signature_arguments,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_malformed_key() fail {
  builtin_probe.withdraw(
    fixtures.malformed_key_arguments,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_malformed_signature() fail {
  builtin_probe.withdraw(
    fixtures.malformed_signature_arguments,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_non_list_arguments() fail {
  builtin_probe.withdraw(
    fixtures.non_list_arguments,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_missing_argument() fail {
  builtin_probe.withdraw(
    fixtures.missing_argument,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_extra_argument() fail {
  builtin_probe.withdraw(
    fixtures.extra_argument,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_wrong_key_type() fail {
  builtin_probe.withdraw(
    fixtures.wrong_key_type,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_wrong_message_type() fail {
  builtin_probe.withdraw(
    fixtures.wrong_message_type,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_wrong_signature_type() fail {
  builtin_probe.withdraw(
    fixtures.wrong_signature_type,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

const ignored_redeemer = builtin.constr_data(0, [])

const registration =
  RegisterCredential {
    credential: Script(fixtures.script_hash),
    deposit: Never,
  }

const delegation =
  DelegateCredential {
    credential: Script(fixtures.script_hash),
    delegate: DelegateBlockProduction {
      stake_pool: builtin.replicate_byte(28, 5),
    },
  }

const registration_and_delegation =
  RegisterAndDelegateCredential {
    credential: Script(fixtures.script_hash),
    delegate: DelegateBlockProduction {
      stake_pool: builtin.replicate_byte(28, 5),
    },
    deposit: 2_000_000,
  }

const deregistration =
  UnregisterCredential {
    credential: Script(fixtures.script_hash),
    refund: Never,
  }

test publish__allows_registration() {
  builtin_probe.publish(ignored_redeemer, registration, transaction.placeholder)
}

test publish__rejects_delegation() fail {
  builtin_probe.publish(ignored_redeemer, delegation, transaction.placeholder)
}

test publish__rejects_registration_and_delegation() fail {
  builtin_probe.publish(
    ignored_redeemer,
    registration_and_delegation,
    transaction.placeholder,
  )
}

test publish__rejects_deregistration() fail {
  builtin_probe.publish(
    ignored_redeemer,
    deregistration,
    transaction.placeholder,
  )
}

// Construct entrypoint arguments in constants to measure only validation.
fn mint_fixture(
  arguments: Data,
  testnet_body: ByteArray,
  mainnet_body: ByteArray,
) -> (ProofMintRedeemer, Transaction) {
  let ProofFixture { transaction, collateral_return_input_index, witness } = fixtures.argument_proof(
    arguments,
    testnet_body,
    mainnet_body,
  )
  (ProofMintRedeemer { collateral_return_input_index, witness }, transaction)
}

const proof_builtin_false =
  mint_fixture(
    fixtures.builtin_arguments,
    bodies.builtin_false,
    bodies.builtin_false_mainnet,
  )

test mint__accepts_builtin_false() {
  let (redeemer, tx) = proof_builtin_false
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_bad_signature =
  mint_fixture(
    fixtures.bad_signature_arguments,
    bodies.bad_signature,
    bodies.bad_signature_mainnet,
  )

test mint__accepts_bad_signature() {
  let (redeemer, tx) = proof_bad_signature
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_builtin_key_length_error =
  mint_fixture(
    fixtures.malformed_key_arguments,
    bodies.malformed_key,
    bodies.malformed_key_mainnet,
  )

test mint__accepts_builtin_key_length_error() {
  let (redeemer, tx) = proof_builtin_key_length_error
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_builtin_signature_length_error =
  mint_fixture(
    fixtures.malformed_signature_arguments,
    bodies.malformed_signature,
    bodies.malformed_signature_mainnet,
  )

test mint__accepts_builtin_signature_length_error() {
  let (redeemer, tx) = proof_builtin_signature_length_error
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_long_message =
  mint_fixture(
    fixtures.long_message_arguments,
    bodies.long_message,
    bodies.long_message_mainnet,
  )

test mint__accepts_long_message() {
  let (redeemer, tx) = proof_long_message
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_non_list_arguments =
  mint_fixture(
    fixtures.non_list_arguments,
    bodies.non_list,
    bodies.non_list_mainnet,
  )

test mint__rejects_non_list_arguments() fail {
  let (redeemer, tx) = proof_non_list_arguments
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_missing_argument =
  mint_fixture(
    fixtures.missing_argument,
    bodies.missing_argument,
    bodies.missing_argument_mainnet,
  )

test mint__rejects_missing_argument() fail {
  let (redeemer, tx) = proof_missing_argument
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_extra_argument =
  mint_fixture(
    fixtures.extra_argument,
    bodies.extra_argument,
    bodies.extra_argument_mainnet,
  )

test mint__rejects_extra_argument() fail {
  let (redeemer, tx) = proof_extra_argument
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_wrong_key_type =
  mint_fixture(
    fixtures.wrong_key_type,
    bodies.wrong_key_type,
    bodies.wrong_key_type_mainnet,
  )

test mint__rejects_wrong_key_type() fail {
  let (redeemer, tx) = proof_wrong_key_type
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_wrong_message_type =
  mint_fixture(
    fixtures.wrong_message_type,
    bodies.wrong_message_type,
    bodies.wrong_message_type_mainnet,
  )

test mint__rejects_wrong_message_type() fail {
  let (redeemer, tx) = proof_wrong_message_type
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_wrong_signature_type =
  mint_fixture(
    fixtures.wrong_signature_type,
    bodies.wrong_signature_type,
    bodies.wrong_signature_type_mainnet,
  )

test mint__rejects_wrong_signature_type() fail {
  let (redeemer, tx) = proof_wrong_signature_type
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

test mint__rejects_mismatched_script_parameter() fail {
  let (redeemer, tx) = proof_builtin_false
  failure_proof.mint(
    builtin.replicate_byte(28, 3),
    redeemer,
    fixtures.policy_id,
    tx,
  )
}
