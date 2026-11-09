use aiken/builtin
use aiken/collection/list
use aiken_design_patterns/failure_validation.{FailedTransactionWitness}
use aiken_design_patterns/transaction_serialization.{ListEncoding}
use cardano/assets
use cardano/transaction.{Input, OutputReference, Transaction}
use env
use tests/failure_validation/bodies
use tests/failure_validation/fixtures.{ProofFixture}

fn validate(proof: ProofFixture, check_arguments: fn(Data) -> Bool) -> Bool {
  let  
      ProofFixture {
        transaction: Transaction { inputs, mint, .. },
        witness,
        collateral_return_input_index,
      }
    = proof
  let arguments <- failure_validation.validate_mint(
    own_policy: fixtures.policy_id,
    withdrawal_script_hash: fixtures.script_hash,
    withdrawal_cpu: 10_000_000_000,
    withdrawal_mem: 17_500_000,
    network_tag: 0,
    inputs: inputs,
    collateral_return_input_index: collateral_return_input_index,
    mint: mint,
    witness: witness,
  )
  check_arguments(arguments)
}

const base_tx = fixtures.base.transaction

const base_witness = fixtures.base.witness

test mint__withdrawal_only_map() {
  let arguments <- validate(fixtures.base)
  arguments == fixtures.builtin_arguments && env.validate_builtin_arguments(
    arguments,
  )
}

const list_encoding =
  fixtures.from_body(
    bodies.withdrawal_list,
    ListEncoding,
    0,
    fixtures.builtin_arguments,
  )

test mint__withdrawal_only_list() {
  let arguments <- validate(list_encoding)
  env.validate_builtin_arguments(arguments)
}

const with_references =
  fixtures.with_body(
    ProofFixture {
      ..fixtures.base,
      witness: FailedTransactionWitness {
        ..base_witness,
        reference_inputs: fixtures.failed_reference_inputs,
      },
    },
    bodies.with_references,
  )

test mint__failed_transaction_reference_inputs() {
  let arguments <- validate(with_references)
  env.validate_builtin_arguments(arguments)
}

const list_with_references = {
    let ProofFixture { witness, .. } = with_references
    fixtures.with_body(
      ProofFixture {
        ..with_references,
        witness: FailedTransactionWitness {
          ..witness,
          redeemer_encoding: ListEncoding,
        },
      },
      bodies.list_with_references,
    )
  }

test mint__list_with_reference_inputs() {
  let arguments <- validate(list_with_references)
  env.validate_builtin_arguments(arguments)
}

const multiple_inputs =
  fixtures.with_body(
    ProofFixture {
      ..fixtures.base,
      witness: FailedTransactionWitness {
        ..base_witness,
        ordinary_inputs: [
          fixtures.ordinary_input,
          OutputReference {
            transaction_id: builtin.replicate_byte(32, 32),
            output_index: 0,
          },
          OutputReference {
            transaction_id: builtin.replicate_byte(32, 128),
            output_index: 1,
          },
        ],
      },
    },
    bodies.multiple_inputs,
  )

test mint__multiple_ordinary_inputs() {
  let arguments <- validate(multiple_inputs)
  env.validate_builtin_arguments(arguments)
}

test mint__propagates_continuation_rejection() {
  let accepted = {
    let _arguments <- validate(fixtures.base)
    False
  }
  !accepted
}

const zero_outputs =
  fixtures.with_outputs(
    fixtures.base,
    bodies.with_zero_outputs,
    bodies.zero_outputs,
    0,
  )

test mint__accepts_zero_outputs() {
  let arguments <- validate(zero_outputs)
  env.validate_builtin_arguments(arguments)
}

const multiple_outputs =
  fixtures.with_outputs(
    fixtures.base,
    bodies.with_multiple_outputs,
    bodies.multiple_outputs,
    3,
  )

test mint__accepts_multiple_outputs() {
  let arguments <- validate(multiple_outputs)
  env.validate_builtin_arguments(arguments)
}

const indefinite_outputs =
  fixtures.with_outputs(
    fixtures.base,
    bodies.with_indefinite_outputs,
    bodies.indefinite_outputs,
    1,
  )

test mint__accepts_indefinite_outputs() {
  let arguments <- validate(indefinite_outputs)
  env.validate_builtin_arguments(arguments)
}

const nonminimal_outputs =
  fixtures.with_outputs(
    fixtures.base,
    bodies.with_nonminimal_outputs,
    bodies.nonminimal_outputs,
    1,
  )

test mint__accepts_nonminimal_outputs() {
  let arguments <- validate(nonminimal_outputs)
  env.validate_builtin_arguments(arguments)
}

const inline_datum_output =
  fixtures.with_outputs(
    fixtures.base,
    bodies.with_inline_datum_output,
    bodies.inline_datum_output,
    1,
  )

test mint__accepts_inline_datum_output() {
  let arguments <- validate(inline_datum_output)
  env.validate_builtin_arguments(arguments)
}

const reference_script_output =
  fixtures.with_outputs(
    fixtures.base,
    bodies.with_reference_script_output,
    bodies.reference_script_output,
    1,
  )

test mint__accepts_reference_script_output() {
  let arguments <- validate(reference_script_output)
  env.validate_builtin_arguments(arguments)
}

const matching_return_output =
  fixtures.with_outputs(
    fixtures.base,
    bodies.with_matching_return_output,
    bodies.matching_return_output,
    1,
  )

test mint__accepts_matching_return_output() {
  let arguments <- validate(matching_return_output)
  env.validate_builtin_arguments(arguments)
}

const missing_withdrawal =
  fixtures.with_body(fixtures.base, bodies.missing_withdrawal)

test mint__rejects_missing_withdrawal() fail {
  let arguments <- validate(missing_withdrawal)
  env.validate_builtin_arguments(arguments)
}

const wrong_withdrawal =
  fixtures.with_body(fixtures.base, bodies.wrong_withdrawal)

test mint__rejects_wrong_withdrawal() fail {
  let arguments <- validate(wrong_withdrawal)
  env.validate_builtin_arguments(arguments)
}

const key_withdrawal = fixtures.with_body(fixtures.base, bodies.key_withdrawal)

test mint__rejects_key_withdrawal() fail {
  let arguments <- validate(key_withdrawal)
  env.validate_builtin_arguments(arguments)
}

const extra_withdrawal =
  fixtures.with_body(fixtures.base, bodies.extra_withdrawal)

test mint__rejects_extra_withdrawal() fail {
  let arguments <- validate(extra_withdrawal)
  env.validate_builtin_arguments(arguments)
}

const nonzero_withdrawal =
  fixtures.with_body(fixtures.base, bodies.nonzero_withdrawal)

test mint__rejects_nonzero_withdrawal() fail {
  let arguments <- validate(nonzero_withdrawal)
  env.validate_builtin_arguments(arguments)
}

const missing_redeemer =
  fixtures.with_body(fixtures.base, bodies.missing_redeemer)

test mint__rejects_missing_redeemer() fail {
  let arguments <- validate(missing_redeemer)
  env.validate_builtin_arguments(arguments)
}

const extra_redeemer = fixtures.with_body(fixtures.base, bodies.extra_redeemer)

test mint__rejects_extra_redeemer() fail {
  let arguments <- validate(extra_redeemer)
  env.validate_builtin_arguments(arguments)
}

const extra_spend = fixtures.with_body(fixtures.base, bodies.extra_spend)

test mint__rejects_extra_spend() fail {
  let arguments <- validate(extra_spend)
  env.validate_builtin_arguments(arguments)
}

const wrong_pointer = fixtures.with_body(fixtures.base, bodies.wrong_pointer)

test mint__rejects_wrong_pointer() fail {
  let arguments <- validate(wrong_pointer)
  env.validate_builtin_arguments(arguments)
}

const wrong_purpose = fixtures.with_body(fixtures.base, bodies.wrong_purpose)

test mint__rejects_wrong_purpose() fail {
  let arguments <- validate(wrong_purpose)
  env.validate_builtin_arguments(arguments)
}

const wrong_cpu = fixtures.with_body(fixtures.base, bodies.wrong_cpu)

test mint__rejects_wrong_cpu() fail {
  let arguments <- validate(wrong_cpu)
  env.validate_builtin_arguments(arguments)
}

const wrong_memory = fixtures.with_body(fixtures.base, bodies.wrong_memory)

test mint__rejects_wrong_memory() fail {
  let arguments <- validate(wrong_memory)
  env.validate_builtin_arguments(arguments)
}

const malformed_shapes =
  [
    fixtures.with_arguments(
      fixtures.base,
      bodies.non_list,
      fixtures.non_list_arguments,
    ),
    fixtures.with_arguments(
      fixtures.base,
      bodies.missing_argument,
      fixtures.missing_argument,
    ),
    fixtures.with_arguments(
      fixtures.base,
      bodies.extra_argument,
      fixtures.extra_argument,
    ),
    fixtures.with_arguments(
      fixtures.base,
      bodies.wrong_key_type,
      fixtures.wrong_key_type,
    ),
    fixtures.with_arguments(
      fixtures.base,
      bodies.wrong_message_type,
      fixtures.wrong_message_type,
    ),
    fixtures.with_arguments(
      fixtures.base,
      bodies.wrong_signature_type,
      fixtures.wrong_signature_type,
    ),
  ]

// Ensure the negative entrypoint fixtures reach the argument continuation.
test mint__authenticates_malformed_shapes_before_continuation() {
  list.all(
    malformed_shapes,
    fn(proof) {
      let ProofFixture { witness, .. } = proof
      let FailedTransactionWitness { builtin_arguments, .. } = witness
      let arguments <- validate(proof)
      builtin.serialise_data(arguments) == builtin.serialise_data(
        builtin_arguments,
      )
    },
  )
}

const raw_map =
  fixtures.with_arguments(
    fixtures.base,
    bodies.raw_map,
    fixtures.raw_map_arguments,
  )

test mint__preserves_argument_map_order_and_duplicate_keys() {
  let arguments <- validate(raw_map)
  builtin.un_map_data(arguments) == builtin.un_map_data(
    fixtures.raw_map_arguments,
  )
}

const reordered_map = {
    let ProofFixture { witness, .. } = raw_map
    ProofFixture {
      ..raw_map,
      witness: FailedTransactionWitness {
        ..witness,
        builtin_arguments: builtin.map_data(
          [
            Pair(builtin.i_data(1), builtin.i_data(10)),
            Pair(builtin.i_data(2), builtin.i_data(20)),
            Pair(builtin.i_data(2), builtin.i_data(21)),
          ],
        ),
      },
    }
  }

test mint__rejects_reordered_arguments() fail {
  let _arguments <- validate(reordered_map)
  True
}

const substituted_arguments =
  ProofFixture {
    ..fixtures.base,
    witness: FailedTransactionWitness {
      ..base_witness,
      builtin_arguments: fixtures.successful_arguments,
    },
  }

test mint__rejects_substituted_arguments() fail {
  let arguments <- validate(substituted_arguments)
  env.validate_builtin_arguments(arguments)
}

const long_message =
  fixtures.with_arguments(
    fixtures.base,
    bodies.long_message,
    fixtures.long_message_arguments,
  )

test mint__authenticates_chunked_argument_bytes() {
  let arguments <- validate(long_message)
  env.validate_builtin_arguments(arguments)
}

const unrelated_input =
  Input {
    output_reference: OutputReference {
      transaction_id: builtin.replicate_byte(32, 0),
      output_index: 0,
    },
    output: fixtures.ordinary_output,
  }

const shifted_index = {
    let Transaction { inputs, .. } = base_tx
    ProofFixture {
      ..fixtures.base,
      collateral_return_input_index: 1,
      transaction: Transaction {
        ..base_tx,
        inputs: [unrelated_input, ..inputs],
      },
    }
  }

test mint__selects_actual_input_by_index() {
  let arguments <- validate(shifted_index)
  env.validate_builtin_arguments(arguments)
}

const wrong_input_index =
  ProofFixture { ..shifted_index, collateral_return_input_index: 0 }

test mint__rejects_wrong_input_index() fail {
  let arguments <- validate(wrong_input_index)
  env.validate_builtin_arguments(arguments)
}

const missing_input_index =
  ProofFixture { ..fixtures.base, collateral_return_input_index: 1 }

test mint__rejects_missing_input_index() fail {
  let arguments <- validate(missing_input_index)
  env.validate_builtin_arguments(arguments)
}

fn with_output_index(proof: ProofFixture, output_index: Int) -> ProofFixture {
  let ProofFixture { transaction, .. } = proof
  let Transaction { inputs, .. } = transaction
  expect [input] = inputs
  let Input { output_reference, .. } = input
  ProofFixture {
    ..proof,
    transaction: Transaction {
      ..transaction,
      inputs: [
        Input {
          ..input,
          output_reference: OutputReference { ..output_reference, output_index },
        },
      ],
    },
  }
}

const output_index_too_small = with_output_index(fixtures.base, 0)

const output_index_too_large = with_output_index(fixtures.base, 2)

test mint__rejects_output_index_below_count() fail {
  let arguments <- validate(output_index_too_small)
  env.validate_builtin_arguments(arguments)
}

test mint__rejects_output_index_above_count() fail {
  let arguments <- validate(output_index_too_large)
  env.validate_builtin_arguments(arguments)
}

// The builtin succeeds and ordinary output 0 exactly matches the declared
// collateral return. Such an ordinary output must never serve as evidence.
const successful_ordinary_output =
  with_output_index(
    fixtures.with_outputs(
      fixtures.with_arguments(
        fixtures.base,
        bodies.successful_matching_return_output,
        fixtures.successful_arguments,
      ),
      bodies.successful_matching_return_output,
      bodies.matching_return_output,
      1,
    ),
    0,
  )

test mint__rejects_successful_transaction_ordinary_output() fail {
  let arguments <- validate(successful_ordinary_output)
  env.validate_builtin_arguments(arguments)
}

const wrong_network =
  fixtures.from_body(
    bodies.builtin_false_mainnet,
    base_witness.redeemer_encoding,
    1,
    fixtures.builtin_arguments,
  )

test mint__rejects_wrong_network_tag() fail {
  let arguments <- validate(wrong_network)
  env.validate_builtin_arguments(arguments)
}

const tampered_fee =
  ProofFixture {
    ..fixtures.base,
    witness: FailedTransactionWitness { ..base_witness, fee: 1_000_001 },
  }

test mint__rejects_tampered_fee() fail {
  let arguments <- validate(tampered_fee)
  env.validate_builtin_arguments(arguments)
}

const tampered_ordinary_inputs =
  ProofFixture {
    ..fixtures.base,
    witness: FailedTransactionWitness {
      ..base_witness,
      ordinary_inputs: [
        OutputReference { ..fixtures.ordinary_input, output_index: 1 },
      ],
    },
  }

test mint__rejects_tampered_ordinary_inputs() fail {
  let arguments <- validate(tampered_ordinary_inputs)
  env.validate_builtin_arguments(arguments)
}

const tampered_collateral_input =
  ProofFixture {
    ..fixtures.base,
    witness: FailedTransactionWitness {
      ..base_witness,
      collateral_input: fixtures.ordinary_input,
    },
  }

test mint__rejects_tampered_collateral_input() fail {
  let arguments <- validate(tampered_collateral_input)
  env.validate_builtin_arguments(arguments)
}

const tampered_total_collateral =
  ProofFixture {
    ..fixtures.base,
    witness: FailedTransactionWitness {
      ..base_witness,
      total_collateral: 1_500_001,
    },
  }

test mint__rejects_tampered_total_collateral() fail {
  let arguments <- validate(tampered_total_collateral)
  env.validate_builtin_arguments(arguments)
}

const tampered_reference_inputs =
  ProofFixture {
    ..fixtures.base,
    witness: FailedTransactionWitness {
      ..base_witness,
      reference_inputs: fixtures.failed_reference_inputs,
    },
  }

test mint__rejects_tampered_reference_inputs() fail {
  let arguments <- validate(tampered_reference_inputs)
  env.validate_builtin_arguments(arguments)
}

const tampered_cost_model =
  ProofFixture {
    ..fixtures.base,
    witness: FailedTransactionWitness { ..base_witness, cost_model: #"80" },
  }

test mint__rejects_tampered_cost_model() fail {
  let arguments <- validate(tampered_cost_model)
  env.validate_builtin_arguments(arguments)
}

const tampered_redeemer_encoding =
  ProofFixture {
    ..fixtures.base,
    witness: FailedTransactionWitness {
      ..base_witness,
      redeemer_encoding: ListEncoding,
    },
  }

test mint__rejects_tampered_redeemer_encoding() fail {
  let arguments <- validate(tampered_redeemer_encoding)
  env.validate_builtin_arguments(arguments)
}

const tampered_outputs =
  ProofFixture {
    ..fixtures.base,
    witness: FailedTransactionWitness { ..base_witness, outputs_cbor: #"80" },
  }

test mint__rejects_tampered_outputs() fail {
  let arguments <- validate(tampered_outputs)
  env.validate_builtin_arguments(arguments)
}

const tampered_reencoded_outputs =
  ProofFixture {
    ..fixtures.base,
    witness: FailedTransactionWitness {
      ..base_witness,
      outputs_cbor: bodies.indefinite_outputs,
    },
  }

test mint__rejects_tampered_reencoded_outputs() fail {
  let arguments <- validate(tampered_reencoded_outputs)
  env.validate_builtin_arguments(arguments)
}

const tampered_truncated_outputs =
  ProofFixture {
    ..fixtures.base,
    witness: FailedTransactionWitness {
      ..base_witness,
      outputs_cbor: builtin.slice_bytearray(
        0,
        builtin.length_of_bytearray(bodies.outputs) - 1,
        bodies.outputs,
      ),
    },
  }

test mint__rejects_tampered_truncated_outputs() fail {
  let arguments <- validate(tampered_truncated_outputs)
  env.validate_builtin_arguments(arguments)
}

const tampered_appended_output_bytes =
  ProofFixture {
    ..fixtures.base,
    witness: FailedTransactionWitness {
      ..base_witness,
      outputs_cbor: builtin.append_bytearray(bodies.outputs, #"00"),
    },
  }

test mint__rejects_tampered_appended_output_bytes() fail {
  let arguments <- validate(tampered_appended_output_bytes)
  env.validate_builtin_arguments(arguments)
}

const tampered_collateral_return = {
    let Transaction { inputs, .. } = base_tx
    expect [input] = inputs
    ProofFixture {
      ..fixtures.base,
      transaction: Transaction {
        ..base_tx,
        inputs: [Input { ..input, output: fixtures.ordinary_output }],
      },
    }
  }

test mint__rejects_tampered_collateral_return() fail {
  let arguments <- validate(tampered_collateral_return)
  env.validate_builtin_arguments(arguments)
}

const wrong_nft_name =
  ProofFixture {
    ..fixtures.base,
    transaction: Transaction {
      ..base_tx,
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
    ..fixtures.base,
    transaction: Transaction {
      ..base_tx,
      mint: assets.from_asset(
        fixtures.policy_id,
        builtin.blake2b_256(bodies.withdrawal_map),
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
    ..fixtures.base,
    transaction: Transaction {
      ..base_tx,
      mint: assets.add(base_tx.mint, fixtures.policy_id, #"01", 1),
    },
  }

test mint__rejects_extra_nft_under_own_policy() fail {
  let arguments <- validate(extra_nft)
  env.validate_builtin_arguments(arguments)
}

const other_policy =
  ProofFixture {
    ..fixtures.base,
    transaction: Transaction {
      ..base_tx,
      mint: assets.add(base_tx.mint, fixtures.script_hash, #"01", 1),
    },
  }

test mint__allows_other_policies() {
  let arguments <- validate(other_policy)
  env.validate_builtin_arguments(arguments)
}
