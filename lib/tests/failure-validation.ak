use aiken/builtin
use aiken_design_patterns/failure_validation.{FailedTransactionWitness}
use aiken_design_patterns/transaction_serialization.{ListEncoding}
use cardano/address
use cardano/assets
use cardano/transaction.{
  DatumHash, InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}
use env
use tests/failure_validation/bodies
use tests/failure_validation/fixtures.{ProofFixture}

fn validate(proof: ProofFixture, check_arguments: fn(Data) -> Bool) -> Bool {
  let  
      ProofFixture {
        transaction: Transaction { inputs, reference_inputs, mint, .. },
        witness,
        collateral_return_input_index,
        spending_reference_input_index,
      }
    = proof
  let arguments <- failure_validation.validate_mint(
    own_policy: fixtures.policy_id,
    spend_withdraw_script_hash: fixtures.script_hash,
    spending_cpu: 14_000_000,
    spending_mem: 50_000,
    withdrawal_cpu: 9_986_000_000,
    withdrawal_mem: 17_450_000,
    network_tag: 0,
    inputs: inputs,
    collateral_return_input_index: collateral_return_input_index,
    reference_inputs: reference_inputs,
    spending_reference_input_index: spending_reference_input_index,
    mint: mint,
    witness: witness,
  )
  check_arguments(arguments)
}

test mint__first_input_map() {
  let arguments <- validate(fixtures.first)
  arguments == fixtures.builtin_arguments && env.validate_builtin_arguments(
    arguments,
  )
}

test mint__second_input_map() {
  let arguments <- validate(fixtures.second)
  env.validate_builtin_arguments(arguments)
}

test mint__first_input_list() {
  let arguments <- validate(fixtures.first_list)
  env.validate_builtin_arguments(arguments)
}

test mint__second_input_list() {
  let arguments <- validate(fixtures.second_list)
  env.validate_builtin_arguments(arguments)
}

test mint__first_input_map_with_references() {
  let arguments <- validate(fixtures.first_references)
  env.validate_builtin_arguments(arguments)
}

test mint__second_input_map_with_references() {
  let arguments <- validate(fixtures.second_references)
  env.validate_builtin_arguments(arguments)
}

test mint__first_input_list_with_references() {
  let arguments <- validate(fixtures.first_list_references)
  env.validate_builtin_arguments(arguments)
}

test mint__second_input_list_with_references() {
  let arguments <- validate(fixtures.second_list_references)
  env.validate_builtin_arguments(arguments)
}

test mint__first_input_same_transaction() {
  let arguments <- validate(fixtures.first_same_transaction)
  env.validate_builtin_arguments(arguments)
}

test mint__second_input_same_transaction() {
  let arguments <- validate(fixtures.second_same_transaction)
  env.validate_builtin_arguments(arguments)
}

test mint__propagates_continuation_rejection() {
  let accepted = {
    let _arguments <- validate(fixtures.first)
    False
  }
  !accepted
}

test mint__accepts_arguments_for_builtin_false() {
  let arguments <- validate(fixtures.first)
  env.validate_builtin_arguments(arguments) && !env.apply_builtin(arguments)
}

const one_input = fixtures.with_body(fixtures.first, bodies.one_input)

test mint__rejects_one_input() fail {
  let arguments <- validate(one_input)
  env.validate_builtin_arguments(arguments)
}

const three_inputs = fixtures.with_body(fixtures.first, bodies.three_inputs)

test mint__rejects_three_inputs() fail {
  let arguments <- validate(three_inputs)
  env.validate_builtin_arguments(arguments)
}

const duplicate_inputs =
  fixtures.with_body(fixtures.first, bodies.duplicate_inputs)

test mint__rejects_duplicate_inputs() fail {
  let arguments <- validate(duplicate_inputs)
  env.validate_builtin_arguments(arguments)
}

const wrong_first_flag =
  fixtures.with_body(fixtures.first, bodies.wrong_first_flag)

test mint__rejects_wrong_first_flag() fail {
  let arguments <- validate(wrong_first_flag)
  env.validate_builtin_arguments(arguments)
}

const wrong_second_flag =
  fixtures.with_body(fixtures.second, bodies.wrong_second_flag)

test mint__rejects_wrong_second_flag() fail {
  let arguments <- validate(wrong_second_flag)
  env.validate_builtin_arguments(arguments)
}

const malformed_spending_redeemer =
  fixtures.with_body(fixtures.first, bodies.malformed_spending_redeemer)

test mint__rejects_malformed_spending_redeemer() fail {
  let arguments <- validate(malformed_spending_redeemer)
  env.validate_builtin_arguments(arguments)
}

const wrong_first_pointer =
  fixtures.with_body(fixtures.first, bodies.wrong_first_pointer)

test mint__rejects_wrong_first_pointer() fail {
  let arguments <- validate(wrong_first_pointer)
  env.validate_builtin_arguments(arguments)
}

const wrong_second_pointer =
  fixtures.with_body(fixtures.second, bodies.wrong_second_pointer)

test mint__rejects_wrong_second_pointer() fail {
  let arguments <- validate(wrong_second_pointer)
  env.validate_builtin_arguments(arguments)
}

const missing_withdrawal =
  fixtures.with_body(fixtures.first, bodies.missing_withdrawal)

test mint__rejects_missing_withdrawal() fail {
  let arguments <- validate(missing_withdrawal)
  env.validate_builtin_arguments(arguments)
}

const wrong_withdrawal =
  fixtures.with_body(fixtures.first, bodies.wrong_withdrawal)

test mint__rejects_wrong_withdrawal() fail {
  let arguments <- validate(wrong_withdrawal)
  env.validate_builtin_arguments(arguments)
}

const key_withdrawal = fixtures.with_body(fixtures.first, bodies.key_withdrawal)

test mint__rejects_key_withdrawal() fail {
  let arguments <- validate(key_withdrawal)
  env.validate_builtin_arguments(arguments)
}

const extra_withdrawal =
  fixtures.with_body(fixtures.first, bodies.extra_withdrawal)

test mint__rejects_extra_withdrawal() fail {
  let arguments <- validate(extra_withdrawal)
  env.validate_builtin_arguments(arguments)
}

const nonzero_withdrawal =
  fixtures.with_body(fixtures.first, bodies.nonzero_withdrawal)

test mint__rejects_nonzero_withdrawal() fail {
  let arguments <- validate(nonzero_withdrawal)
  env.validate_builtin_arguments(arguments)
}

const extra_redeemer = fixtures.with_body(fixtures.first, bodies.extra_redeemer)

test mint__rejects_extra_redeemer() fail {
  let arguments <- validate(extra_redeemer)
  env.validate_builtin_arguments(arguments)
}

const extra_spend = fixtures.with_body(fixtures.first, bodies.extra_spend)

test mint__rejects_extra_spend() fail {
  let arguments <- validate(extra_spend)
  env.validate_builtin_arguments(arguments)
}

const missing_spend = fixtures.with_body(fixtures.first, bodies.missing_spend)

test mint__rejects_missing_spend() fail {
  let arguments <- validate(missing_spend)
  env.validate_builtin_arguments(arguments)
}

const wrong_withdrawal_pointer =
  fixtures.with_body(fixtures.first, bodies.wrong_withdrawal_pointer)

test mint__rejects_wrong_withdrawal_pointer() fail {
  let arguments <- validate(wrong_withdrawal_pointer)
  env.validate_builtin_arguments(arguments)
}

const malformed_withdrawal_redeemer =
  fixtures.with_body(fixtures.first, bodies.malformed_withdrawal_redeemer)

test mint__rejects_malformed_withdrawal_redeemer() fail {
  let arguments <- validate(malformed_withdrawal_redeemer)
  env.validate_builtin_arguments(arguments)
}

const wrong_spending_cpu =
  fixtures.with_body(fixtures.first, bodies.wrong_spending_cpu)

test mint__rejects_wrong_spending_cpu() fail {
  let arguments <- validate(wrong_spending_cpu)
  env.validate_builtin_arguments(arguments)
}

const wrong_spending_memory =
  fixtures.with_body(fixtures.first, bodies.wrong_spending_memory)

test mint__rejects_wrong_spending_memory() fail {
  let arguments <- validate(wrong_spending_memory)
  env.validate_builtin_arguments(arguments)
}

const wrong_withdrawal_cpu =
  fixtures.with_body(fixtures.first, bodies.wrong_withdrawal_cpu)

test mint__rejects_wrong_withdrawal_cpu() fail {
  let arguments <- validate(wrong_withdrawal_cpu)
  env.validate_builtin_arguments(arguments)
}

const wrong_withdrawal_memory =
  fixtures.with_body(fixtures.first, bodies.wrong_withdrawal_memory)

test mint__rejects_wrong_withdrawal_memory() fail {
  let arguments <- validate(wrong_withdrawal_memory)
  env.validate_builtin_arguments(arguments)
}

const first_tx = fixtures.first.transaction

const first_witness = fixtures.first.witness

const unrelated_input =
  Input {
    output_reference: OutputReference {
      transaction_id: builtin.replicate_byte(32, 0),
      output_index: 0,
    },
    output: fixtures.ordinary_output,
  }

const shifted_indices = {
    let Transaction { inputs, reference_inputs, .. } = first_tx
    ProofFixture {
      ..fixtures.first,
      collateral_return_input_index: 1,
      spending_reference_input_index: 1,
      transaction: Transaction {
        ..first_tx,
        inputs: [unrelated_input, ..inputs],
        reference_inputs: [
          Input {
            ..unrelated_input,
            output_reference: OutputReference {
              transaction_id: builtin.replicate_byte(32, 0),
              output_index: 1,
            },
          },
          ..reference_inputs
        ],
      },
    }
  }

test mint__selects_actual_inputs_by_index() {
  let arguments <- validate(shifted_indices)
  env.validate_builtin_arguments(arguments)
}

const wrong_collateral_index =
  ProofFixture { ..shifted_indices, collateral_return_input_index: 0 }

test mint__rejects_wrong_collateral_index() fail {
  let arguments <- validate(wrong_collateral_index)
  env.validate_builtin_arguments(arguments)
}

const wrong_reference_index =
  ProofFixture { ..shifted_indices, spending_reference_input_index: 0 }

test mint__rejects_wrong_reference_index() fail {
  let arguments <- validate(wrong_reference_index)
  env.validate_builtin_arguments(arguments)
}

const missing_reference =
  ProofFixture {
    ..fixtures.first,
    transaction: Transaction { ..first_tx, reference_inputs: [] },
  }

test mint__rejects_missing_reference_input() fail {
  let arguments <- validate(missing_reference)
  env.validate_builtin_arguments(arguments)
}

const wrong_reference =
  ProofFixture {
    ..fixtures.first,
    transaction: Transaction {
      ..first_tx,
      reference_inputs: [
        Input {
          output_reference: fixtures.second_other_reference,
          output: fixtures.script_output,
        },
      ],
    },
  }

test mint__rejects_wrong_original_reference() fail {
  let arguments <- validate(wrong_reference)
  env.validate_builtin_arguments(arguments)
}

const wrong_script =
  fixtures.with_script_output(
    fixtures.first,
    Output {
      ..fixtures.script_output,
      address: address.from_script(builtin.replicate_byte(28, 3)),
    },
  )

test mint__rejects_wrong_script_credential() fail {
  let arguments <- validate(wrong_script)
  env.validate_builtin_arguments(arguments)
}

const key_script =
  fixtures.with_script_output(
    fixtures.first,
    Output {
      ..fixtures.script_output,
      address: address.from_verification_key(fixtures.script_hash),
    },
  )

test mint__rejects_key_credential() fail {
  let arguments <- validate(key_script)
  env.validate_builtin_arguments(arguments)
}

const no_datum =
  fixtures.with_script_output(
    fixtures.first,
    Output { ..fixtures.script_output, datum: NoDatum },
  )

test mint__rejects_missing_datum() fail {
  let arguments <- validate(no_datum)
  env.validate_builtin_arguments(arguments)
}

const hashed_datum =
  fixtures.with_script_output(
    fixtures.first,
    Output {
      ..fixtures.script_output,
      datum: DatumHash(
        builtin.blake2b_256(builtin.serialise_data(fixtures.builtin_arguments)),
      ),
    },
  )

test mint__rejects_hashed_datum() fail {
  let arguments <- validate(hashed_datum)
  env.validate_builtin_arguments(arguments)
}

const duplicate_references =
  ProofFixture {
    ..duplicate_inputs,
    witness: FailedTransactionWitness {
      ..first_witness,
      other_input: fixtures.first_script_reference,
    },
  }

test mint__rejects_duplicate_reference_witness() fail {
  let arguments <- validate(duplicate_references)
  env.validate_builtin_arguments(arguments)
}

const tampered_fee =
  ProofFixture {
    ..fixtures.first,
    witness: FailedTransactionWitness { ..first_witness, fee: 1_000_001 },
  }

test mint__rejects_tampered_fee() fail {
  let arguments <- validate(tampered_fee)
  env.validate_builtin_arguments(arguments)
}

const tampered_outputs =
  ProofFixture {
    ..fixtures.first,
    witness: FailedTransactionWitness { ..first_witness, outputs_cbor: #"80" },
  }

test mint__rejects_tampered_outputs() fail {
  let arguments <- validate(tampered_outputs)
  env.validate_builtin_arguments(arguments)
}

const indefinite_outputs =
  fixtures.with_outputs(
    fixtures.first,
    bodies.first_indefinite_outputs,
    bodies.indefinite_outputs,
  )

test mint__accepts_indefinite_outputs() {
  let arguments <- validate(indefinite_outputs)
  env.validate_builtin_arguments(arguments)
}

const noncanonical_outputs =
  fixtures.with_outputs(
    fixtures.first,
    bodies.first_noncanonical_outputs,
    bodies.noncanonical_outputs,
  )

test mint__preserves_noncanonical_output_encoding() {
  let arguments <- validate(noncanonical_outputs)
  env.validate_builtin_arguments(arguments)
}

const inline_datum_output =
  fixtures.with_outputs(
    fixtures.first,
    bodies.first_inline_datum_output,
    bodies.inline_datum_output,
  )

test mint__accepts_inline_datum_output() {
  let arguments <- validate(inline_datum_output)
  env.validate_builtin_arguments(arguments)
}

const reference_script_output =
  fixtures.with_outputs(
    fixtures.first,
    bodies.first_reference_script_output,
    bodies.reference_script_output,
  )

test mint__accepts_reference_script_output() {
  let arguments <- validate(reference_script_output)
  env.validate_builtin_arguments(arguments)
}

const reencoded_outputs =
  ProofFixture { ..indefinite_outputs, witness: first_witness }

test mint__rejects_reencoded_outputs() fail {
  let arguments <- validate(reencoded_outputs)
  env.validate_builtin_arguments(arguments)
}

const truncated_outputs =
  ProofFixture {
    ..fixtures.first,
    witness: FailedTransactionWitness {
      ..first_witness,
      outputs_cbor: builtin.slice_bytearray(
        0,
        builtin.length_of_bytearray(bodies.outputs) - 1,
        bodies.outputs,
      ),
    },
  }

test mint__rejects_truncated_outputs() fail {
  let arguments <- validate(truncated_outputs)
  env.validate_builtin_arguments(arguments)
}

const extended_outputs =
  ProofFixture {
    ..fixtures.first,
    witness: FailedTransactionWitness {
      ..first_witness,
      outputs_cbor: builtin.append_bytearray(bodies.outputs, #"00"),
    },
  }

test mint__rejects_appended_output_bytes() fail {
  let arguments <- validate(extended_outputs)
  env.validate_builtin_arguments(arguments)
}

const tampered_collateral_return = {
    expect [input] = first_tx.inputs
    ProofFixture {
      ..fixtures.first,
      transaction: Transaction {
        ..first_tx,
        inputs: [Input { ..input, output: fixtures.ordinary_output }],
      },
    }
  }

test mint__rejects_tampered_collateral_return() fail {
  let arguments <- validate(tampered_collateral_return)
  env.validate_builtin_arguments(arguments)
}

const tampered_other_input =
  ProofFixture {
    ..fixtures.first,
    witness: FailedTransactionWitness {
      ..first_witness,
      other_input: fixtures.second_other_reference,
    },
  }

test mint__rejects_tampered_other_input() fail {
  let arguments <- validate(tampered_other_input)
  env.validate_builtin_arguments(arguments)
}

const tampered_reference_inputs =
  ProofFixture {
    ..fixtures.first,
    witness: FailedTransactionWitness {
      ..first_witness,
      reference_inputs: fixtures.failed_reference_inputs,
    },
  }

test mint__rejects_tampered_reference_inputs() fail {
  let arguments <- validate(tampered_reference_inputs)
  env.validate_builtin_arguments(arguments)
}

const tampered_cost_model =
  ProofFixture {
    ..fixtures.first,
    witness: FailedTransactionWitness { ..first_witness, cost_model: #"80" },
  }

test mint__rejects_tampered_cost_model() fail {
  let arguments <- validate(tampered_cost_model)
  env.validate_builtin_arguments(arguments)
}

const tampered_encoding =
  ProofFixture {
    ..fixtures.first,
    witness: FailedTransactionWitness {
      ..first_witness,
      redeemer_encoding: ListEncoding,
    },
  }

test mint__rejects_tampered_redeemer_encoding() fail {
  let arguments <- validate(tampered_encoding)
  env.validate_builtin_arguments(arguments)
}

const wrong_nft_name =
  ProofFixture {
    ..fixtures.first,
    transaction: Transaction {
      ..first_tx,
      mint: assets.from_asset(
        fixtures.policy_id,
        builtin.replicate_byte(32, 0),
        1,
      ),
    },
  }

test mint__rejects_wrong_nft_name() fail {
  let arguments <- validate(wrong_nft_name)
  env.validate_builtin_arguments(arguments)
}

const wrong_nft_quantity =
  ProofFixture {
    ..fixtures.first,
    transaction: Transaction {
      ..first_tx,
      mint: assets.from_asset(
        fixtures.policy_id,
        builtin.blake2b_256(bodies.first_map),
        2,
      ),
    },
  }

test mint__rejects_wrong_nft_quantity() fail {
  let arguments <- validate(wrong_nft_quantity)
  env.validate_builtin_arguments(arguments)
}

const extra_nft =
  ProofFixture {
    ..fixtures.first,
    transaction: Transaction {
      ..first_tx,
      mint: assets.add(first_tx.mint, fixtures.policy_id, #"01", 1),
    },
  }

test mint__rejects_extra_nft_under_own_policy() fail {
  let arguments <- validate(extra_nft)
  env.validate_builtin_arguments(arguments)
}

const other_policy =
  ProofFixture {
    ..fixtures.first,
    transaction: Transaction {
      ..first_tx,
      mint: assets.add(first_tx.mint, fixtures.script_hash, #"01", 1),
    },
  }

test mint__allows_other_policies() {
  let arguments <- validate(other_policy)
  env.validate_builtin_arguments(arguments)
}

const raw_arguments =
  builtin.map_data(
    [
      Pair(builtin.i_data(2), builtin.i_data(20)),
      Pair(builtin.i_data(1), builtin.i_data(10)),
      Pair(builtin.i_data(2), builtin.i_data(21)),
    ],
  )

const raw_datum =
  fixtures.with_script_output(
    fixtures.first,
    Output { ..fixtures.script_output, datum: InlineDatum(raw_arguments) },
  )

test mint__passes_raw_datum_to_continuation() {
  let arguments <- validate(raw_datum)
  builtin.serialise_data(arguments) == builtin.serialise_data(raw_arguments)
}
