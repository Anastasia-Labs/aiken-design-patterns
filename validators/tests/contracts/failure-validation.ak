//// Entry point coverage for the builtin probe, failure proof, and its live
//// parameters reference input. Fixtures are constants so execution costs cover
//// validation only.

use aiken/builtin
use aiken_design_patterns/failure_validation.{
  FailureParameters, failure_parameters_asset_name,
}
use cardano/address.{Script}
use cardano/assets
use cardano/certificate.{
  DelegateBlockProduction, DelegateCredential, RegisterAndDelegateCredential,
  RegisterCredential, UnregisterCredential,
}
use cardano/transaction.{
  DatumHash, InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}
use failure_validation.{ProofMintRedeemer} as contract
use tests/failure_validation/bodies
use tests/failure_validation/fixtures.{ProofFixture}

// The empty context makes any dependence on an input or datum fail these tests.
// The ledger supplies the withdrawal credential and purpose during execution.
test withdraw__successful_builtin() {
  contract.builtin_probe.withdraw(
    fixtures.successful_arguments,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_builtin_false() fail {
  contract.builtin_probe.withdraw(
    fixtures.builtin_arguments,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_bad_signature() fail {
  contract.builtin_probe.withdraw(
    fixtures.bad_signature_arguments,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_malformed_key() fail {
  contract.builtin_probe.withdraw(
    fixtures.malformed_key_arguments,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_malformed_signature() fail {
  contract.builtin_probe.withdraw(
    fixtures.malformed_signature_arguments,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_non_list_arguments() fail {
  contract.builtin_probe.withdraw(
    fixtures.non_list_arguments,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_missing_argument() fail {
  contract.builtin_probe.withdraw(
    fixtures.missing_argument,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_extra_argument() fail {
  contract.builtin_probe.withdraw(
    fixtures.extra_argument,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_wrong_key_type() fail {
  contract.builtin_probe.withdraw(
    fixtures.wrong_key_type,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_wrong_message_type() fail {
  contract.builtin_probe.withdraw(
    fixtures.wrong_message_type,
    Script(fixtures.script_hash),
    transaction.placeholder,
  )
}

test withdraw__rejects_wrong_signature_type() fail {
  contract.builtin_probe.withdraw(
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
  contract.builtin_probe.publish(
    ignored_redeemer,
    registration,
    transaction.placeholder,
  )
}

test publish__rejects_delegation() fail {
  contract.builtin_probe.publish(
    ignored_redeemer,
    delegation,
    transaction.placeholder,
  )
}

test publish__rejects_registration_and_delegation() fail {
  contract.builtin_probe.publish(
    ignored_redeemer,
    registration_and_delegation,
    transaction.placeholder,
  )
}

test publish__rejects_deregistration() fail {
  contract.builtin_probe.publish(
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
  (
    ProofMintRedeemer {
      collateral_return_input_index,
      failure_parameters_reference_input_index: 0,
      witness,
    },
    Transaction {
      ..transaction,
      reference_inputs: [fixtures.failure_parameters_input],
    },
  )
}

const proof_builtin_false =
  mint_fixture(
    fixtures.builtin_arguments,
    bodies.builtin_false,
    bodies.builtin_false_mainnet,
  )

test mint__accepts_builtin_false() {
  let (redeemer, tx) = proof_builtin_false
  contract.failure_proof.mint(
    fixtures.script_hash,
    fixtures.failure_parameters_policy,
    redeemer,
    fixtures.policy_id,
    tx,
  )
}

const proof_bad_signature =
  mint_fixture(
    fixtures.bad_signature_arguments,
    bodies.bad_signature,
    bodies.bad_signature_mainnet,
  )

test mint__accepts_bad_signature() {
  let (redeemer, tx) = proof_bad_signature
  contract.failure_proof.mint(
    fixtures.script_hash,
    fixtures.failure_parameters_policy,
    redeemer,
    fixtures.policy_id,
    tx,
  )
}

const proof_builtin_key_length_error =
  mint_fixture(
    fixtures.malformed_key_arguments,
    bodies.malformed_key,
    bodies.malformed_key_mainnet,
  )

test mint__accepts_builtin_key_length_error() {
  let (redeemer, tx) = proof_builtin_key_length_error
  contract.failure_proof.mint(
    fixtures.script_hash,
    fixtures.failure_parameters_policy,
    redeemer,
    fixtures.policy_id,
    tx,
  )
}

const proof_builtin_signature_length_error =
  mint_fixture(
    fixtures.malformed_signature_arguments,
    bodies.malformed_signature,
    bodies.malformed_signature_mainnet,
  )

test mint__accepts_builtin_signature_length_error() {
  let (redeemer, tx) = proof_builtin_signature_length_error
  contract.failure_proof.mint(
    fixtures.script_hash,
    fixtures.failure_parameters_policy,
    redeemer,
    fixtures.policy_id,
    tx,
  )
}

const proof_long_message =
  mint_fixture(
    fixtures.long_message_arguments,
    bodies.long_message,
    bodies.long_message_mainnet,
  )

test mint__accepts_long_message() {
  let (redeemer, tx) = proof_long_message
  contract.failure_proof.mint(
    fixtures.script_hash,
    fixtures.failure_parameters_policy,
    redeemer,
    fixtures.policy_id,
    tx,
  )
}

const proof_non_list_arguments =
  mint_fixture(
    fixtures.non_list_arguments,
    bodies.non_list,
    bodies.non_list_mainnet,
  )

test mint__rejects_non_list_arguments() fail {
  let (redeemer, tx) = proof_non_list_arguments
  contract.failure_proof.mint(
    fixtures.script_hash,
    fixtures.failure_parameters_policy,
    redeemer,
    fixtures.policy_id,
    tx,
  )
}

const proof_missing_argument =
  mint_fixture(
    fixtures.missing_argument,
    bodies.missing_argument,
    bodies.missing_argument_mainnet,
  )

test mint__rejects_missing_argument() fail {
  let (redeemer, tx) = proof_missing_argument
  contract.failure_proof.mint(
    fixtures.script_hash,
    fixtures.failure_parameters_policy,
    redeemer,
    fixtures.policy_id,
    tx,
  )
}

const proof_extra_argument =
  mint_fixture(
    fixtures.extra_argument,
    bodies.extra_argument,
    bodies.extra_argument_mainnet,
  )

test mint__rejects_extra_argument() fail {
  let (redeemer, tx) = proof_extra_argument
  contract.failure_proof.mint(
    fixtures.script_hash,
    fixtures.failure_parameters_policy,
    redeemer,
    fixtures.policy_id,
    tx,
  )
}

const proof_wrong_key_type =
  mint_fixture(
    fixtures.wrong_key_type,
    bodies.wrong_key_type,
    bodies.wrong_key_type_mainnet,
  )

test mint__rejects_wrong_key_type() fail {
  let (redeemer, tx) = proof_wrong_key_type
  contract.failure_proof.mint(
    fixtures.script_hash,
    fixtures.failure_parameters_policy,
    redeemer,
    fixtures.policy_id,
    tx,
  )
}

const proof_wrong_message_type =
  mint_fixture(
    fixtures.wrong_message_type,
    bodies.wrong_message_type,
    bodies.wrong_message_type_mainnet,
  )

test mint__rejects_wrong_message_type() fail {
  let (redeemer, tx) = proof_wrong_message_type
  contract.failure_proof.mint(
    fixtures.script_hash,
    fixtures.failure_parameters_policy,
    redeemer,
    fixtures.policy_id,
    tx,
  )
}

const proof_wrong_signature_type =
  mint_fixture(
    fixtures.wrong_signature_type,
    bodies.wrong_signature_type,
    bodies.wrong_signature_type_mainnet,
  )

test mint__rejects_wrong_signature_type() fail {
  let (redeemer, tx) = proof_wrong_signature_type
  contract.failure_proof.mint(
    fixtures.script_hash,
    fixtures.failure_parameters_policy,
    redeemer,
    fixtures.policy_id,
    tx,
  )
}

test mint__rejects_mismatched_script_parameter() fail {
  let (redeemer, tx) = proof_builtin_false
  contract.failure_proof.mint(
    builtin.replicate_byte(28, 3),
    fixtures.failure_parameters_policy,
    redeemer,
    fixtures.policy_id,
    tx,
  )
}

const base_proof =
  fixtures.argument_proof(
    fixtures.builtin_arguments,
    bodies.builtin_false,
    bodies.builtin_false_mainnet,
  )

const parameters_output = fixtures.failure_parameters_input.output

const other_policy = builtin.replicate_byte(28, 17)

fn with_parameters_output(
  proof: ProofFixture,
  output: Output,
) -> (ProofMintRedeemer, Transaction) {
  let ProofFixture { transaction, collateral_return_input_index, witness } = proof
  (
    ProofMintRedeemer {
      collateral_return_input_index,
      failure_parameters_reference_input_index: 0,
      witness,
    },
    Transaction {
      ..transaction,
      reference_inputs: [Input { ..fixtures.failure_parameters_input, output }],
    },
  )
}

fn mint(proof: (ProofMintRedeemer, Transaction)) -> Bool {
  let (redeemer, tx) = proof
  contract.failure_proof.mint(
    fixtures.script_hash,
    fixtures.failure_parameters_policy,
    redeemer,
    fixtures.policy_id,
    tx,
  )
}

const valid = with_parameters_output(base_proof, parameters_output)

test mint__accepts_parameters_at_zero() {
  mint(valid)
}

const unrelated_input =
  Input {
    output_reference: OutputReference {
      transaction_id: builtin.replicate_byte(32, 32),
      output_index: 0,
    },
    output: Output {
      ..parameters_output,
      value: assets.from_lovelace(5_000_000),
    },
  }

const wrong_reference_index = {
    let (redeemer, tx) = valid
    (
      redeemer,
      Transaction {
        ..tx,
        reference_inputs: [unrelated_input, fixtures.failure_parameters_input],
      },
    )
  }

const nonzero_reference_index = {
    let (redeemer, tx) = wrong_reference_index
    (
      ProofMintRedeemer {
        ..redeemer,
        failure_parameters_reference_input_index: 1,
      },
      tx,
    )
  }

test mint__accepts_parameters_at_nonzero_index() {
  mint(nonzero_reference_index)
}

test mint__rejects_wrong_reference_index() fail {
  mint(wrong_reference_index)
}

const missing_reference = {
    let (redeemer, tx) = valid
    (redeemer, Transaction { ..tx, reference_inputs: [] })
  }

test mint__rejects_missing_reference() fail {
  mint(missing_reference)
}

const parameters_only_spent = {
    let (redeemer, tx) = missing_reference
    (
      redeemer,
      Transaction {
        ..tx,
        inputs: [fixtures.failure_parameters_input, ..tx.inputs],
      },
    )
  }

test mint__rejects_parameters_only_in_spending_inputs() fail {
  mint(parameters_only_spent)
}

const negative_index = {
    let (redeemer, tx) = valid
    (
      ProofMintRedeemer {
        ..redeemer,
        failure_parameters_reference_input_index: -1,
      },
      tx,
    )
  }

test mint__rejects_negative_reference_index() fail {
  mint(negative_index)
}

const out_of_bounds_index = {
    let (redeemer, tx) = valid
    (
      ProofMintRedeemer {
        ..redeemer,
        failure_parameters_reference_input_index: 1,
      },
      tx,
    )
  }

test mint__rejects_out_of_bounds_reference_index() fail {
  mint(out_of_bounds_index)
}

test mint__rejects_mismatched_parameters_policy_argument() fail {
  let (redeemer, tx) = valid
  contract.failure_proof.mint(
    fixtures.script_hash,
    other_policy,
    redeemer,
    fixtures.policy_id,
    tx,
  )
}

const no_nft = with_parameters_output(base_proof, unrelated_input.output)

test mint__rejects_missing_parameters_nft() fail {
  mint(no_nft)
}

const wrong_nft_policy =
  with_parameters_output(
    base_proof,
    Output {
      ..parameters_output,
      value: assets.from_lovelace(5_000_000)
        |> assets.add(other_policy, failure_parameters_asset_name, 1),
    },
  )

test mint__rejects_wrong_parameters_nft_policy() fail {
  mint(wrong_nft_policy)
}

const wrong_nft_name =
  with_parameters_output(
    base_proof,
    Output {
      ..parameters_output,
      value: assets.from_lovelace(5_000_000)
        |> assets.add(fixtures.failure_parameters_policy, "OTHER_PARAMETERS", 1),
    },
  )

test mint__rejects_wrong_parameters_nft_name() fail {
  mint(wrong_nft_name)
}

const wrong_nft_quantity =
  with_parameters_output(
    base_proof,
    Output {
      ..parameters_output,
      value: assets.from_lovelace(5_000_000)
        |> assets.add(
            fixtures.failure_parameters_policy,
            failure_parameters_asset_name,
            2,
          ),
    },
  )

test mint__rejects_wrong_parameters_nft_quantity() fail {
  mint(wrong_nft_quantity)
}

const extra_asset_same_policy =
  with_parameters_output(
    base_proof,
    Output {
      ..parameters_output,
      value: parameters_output.value
        |> assets.add(fixtures.failure_parameters_policy, "EXTRA", 1),
    },
  )

test mint__rejects_extra_asset_under_parameters_policy() fail {
  mint(extra_asset_same_policy)
}

const extra_asset_other_policy =
  with_parameters_output(
    base_proof,
    Output {
      ..parameters_output,
      value: parameters_output.value |> assets.add(other_policy, "EXTRA", 1),
    },
  )

test mint__rejects_extra_asset_under_other_policy() fail {
  mint(extra_asset_other_policy)
}

const no_datum =
  with_parameters_output(
    base_proof,
    Output { ..parameters_output, datum: NoDatum },
  )

test mint__rejects_missing_parameters_datum() fail {
  mint(no_datum)
}

const hashed_datum =
  with_parameters_output(
    base_proof,
    Output {
      ..parameters_output,
      datum: DatumHash(
        builtin.blake2b_256(builtin.serialise_data(fixtures.failure_parameters)),
      ),
    },
  )

test mint__rejects_hashed_parameters_datum() fail {
  mint(hashed_datum)
}

const non_record_datum =
  with_parameters_output(
    base_proof,
    Output { ..parameters_output, datum: InlineDatum(builtin.i_data(42)) },
  )

test mint__rejects_non_record_parameters() fail {
  mint(non_record_datum)
}

const wrong_constructor =
  with_parameters_output(
    base_proof,
    Output {
      ..parameters_output,
      datum: InlineDatum(
        builtin.constr_data(
          1,
          [builtin.i_data(17_500_000), builtin.i_data(10_000_000_000)],
        ),
      ),
    },
  )

test mint__rejects_wrong_parameters_constructor() fail {
  mint(wrong_constructor)
}

const missing_field =
  with_parameters_output(
    base_proof,
    Output {
      ..parameters_output,
      datum: InlineDatum(builtin.constr_data(0, [builtin.i_data(17_500_000)])),
    },
  )

test mint__rejects_missing_parameters_field() fail {
  mint(missing_field)
}

const extra_field =
  with_parameters_output(
    base_proof,
    Output {
      ..parameters_output,
      datum: InlineDatum(
        builtin.constr_data(
          0,
          [
            builtin.i_data(17_500_000),
            builtin.i_data(10_000_000_000),
            builtin.i_data(1),
          ],
        ),
      ),
    },
  )

test mint__rejects_extra_parameters_field() fail {
  mint(extra_field)
}

const non_integer_memory =
  with_parameters_output(
    base_proof,
    Output {
      ..parameters_output,
      datum: InlineDatum(
        builtin.constr_data(
          0,
          [builtin.b_data(#"00"), builtin.i_data(10_000_000_000)],
        ),
      ),
    },
  )

test mint__rejects_non_integer_memory() fail {
  mint(non_integer_memory)
}

const non_integer_cpu =
  with_parameters_output(
    base_proof,
    Output {
      ..parameters_output,
      datum: InlineDatum(
        builtin.constr_data(
          0,
          [builtin.i_data(17_500_000), builtin.b_data(#"00")],
        ),
      ),
    },
  )

test mint__rejects_non_integer_cpu() fail {
  mint(non_integer_cpu)
}

const configured_cpu_output =
  Output {
    ..parameters_output,
    datum: InlineDatum(
      FailureParameters {
        ..fixtures.failure_parameters,
        max_cpu: 9_500_000_000,
      },
    ),
  }

const configured_cpu =
  with_parameters_output(
    fixtures.argument_proof(
      fixtures.builtin_arguments,
      bodies.configured_cpu,
      bodies.configured_cpu_mainnet,
    ),
    configured_cpu_output,
  )

test mint__accepts_configured_cpu() {
  mint(configured_cpu)
}

const mismatched_cpu = with_parameters_output(base_proof, configured_cpu_output)

test mint__rejects_mismatched_cpu() fail {
  mint(mismatched_cpu)
}

const configured_memory_output =
  Output {
    ..parameters_output,
    datum: InlineDatum(
      FailureParameters { ..fixtures.failure_parameters, max_mem: 17_000_000 },
    ),
  }

const configured_memory =
  with_parameters_output(
    fixtures.argument_proof(
      fixtures.builtin_arguments,
      bodies.configured_memory,
      bodies.configured_memory_mainnet,
    ),
    configured_memory_output,
  )

test mint__accepts_configured_memory() {
  mint(configured_memory)
}

const mismatched_memory =
  with_parameters_output(base_proof, configured_memory_output)

test mint__rejects_mismatched_memory() fail {
  mint(mismatched_memory)
}
