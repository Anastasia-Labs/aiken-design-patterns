//// Authenticate the live parameters reference input at the proof mint entrypoint.
//// Fixtures are constants so execution costs cover validation only.

use aiken/builtin
use aiken_design_patterns/failure_validation.{
  FailureParameters, failure_parameters_asset_name,
}
use cardano/assets
use cardano/transaction.{
  DatumHash, InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}
use failure_validation.{ProofMintRedeemer} as contract
use tests/failure_validation/bodies
use tests/failure_validation/fixtures.{ProofFixture}

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
