use aiken/builtin
use aiken/collection/list
use aiken_design_patterns/failure_validation.{
  DirectArguments, FailedTransactionWitness,
}
use aiken_design_patterns/transaction_serialization.{ListEncoding}
use cardano/assets
use cardano/transaction.{Input, OutputReference, Transaction}
use env
use tests/failure_validation/bodies
use tests/failure_validation/fixtures.{ProofFixture}

fn validate(proof: ProofFixture, check_arguments: fn(Data) -> Bool) -> Bool {
  let  
      ProofFixture {
        transaction: Transaction { inputs, reference_inputs, mint, .. },
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
    reference_inputs: reference_inputs,
    collateral_return_input_index: collateral_return_input_index,
    mint: mint,
    witness: witness,
  )
  check_arguments(arguments)
}

const base_tx = fixtures.base.transaction

const base_witness = fixtures.base.witness

test mint__zero_outputs_map() {
  let arguments <- validate(fixtures.base)
  arguments == fixtures.builtin_arguments && env.validate_builtin_arguments(
    arguments,
  )
}

const list_encoding =
  fixtures.from_body(
    bodies.withdrawal_list,
    ListEncoding,
    fixtures.builtin_arguments,
  )

test mint__zero_outputs_list() {
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

const ordered_ordinary_inputs =
  fixtures.with_input_lists(
    fixtures.base,
    bodies.ordinary_inputs_ordered,
    fixtures.ordered_input_references,
    [],
  )

test mint__input_order__accepts_ordinary_lexicographic_order() {
  let arguments <- validate(ordered_ordinary_inputs)
  env.validate_builtin_arguments(arguments)
}

const descending_ordinary_input_ids =
  fixtures.with_input_lists(
    fixtures.base,
    bodies.ordinary_inputs_descending_ids,
    fixtures.descending_input_transaction_ids,
    [],
  )

test mint__input_order__rejects_descending_ordinary_ids() fail {
  let arguments <- validate(descending_ordinary_input_ids)
  env.validate_builtin_arguments(arguments)
}

const descending_ordinary_output_indexes =
  fixtures.with_input_lists(
    fixtures.base,
    bodies.ordinary_inputs_descending_indexes,
    fixtures.descending_input_output_indexes,
    [],
  )

test mint__input_order__rejects_descending_ordinary_indexes() fail {
  let arguments <- validate(descending_ordinary_output_indexes)
  env.validate_builtin_arguments(arguments)
}

const duplicate_ordinary_inputs =
  fixtures.with_input_lists(
    fixtures.base,
    bodies.ordinary_inputs_duplicate,
    fixtures.duplicate_input_references,
    [],
  )

test mint__input_order__rejects_duplicate_ordinary_inputs() fail {
  let arguments <- validate(duplicate_ordinary_inputs)
  env.validate_builtin_arguments(arguments)
}

const ordered_reference_inputs =
  fixtures.with_input_lists(
    fixtures.base,
    bodies.reference_inputs_ordered,
    [fixtures.ordinary_input],
    fixtures.ordered_input_references,
  )

test mint__input_order__accepts_reference_lexicographic_order() {
  let arguments <- validate(ordered_reference_inputs)
  env.validate_builtin_arguments(arguments)
}

const descending_reference_input_ids =
  fixtures.with_input_lists(
    fixtures.base,
    bodies.reference_inputs_descending_ids,
    [fixtures.ordinary_input],
    fixtures.descending_input_transaction_ids,
  )

test mint__input_order__rejects_descending_reference_ids() fail {
  let arguments <- validate(descending_reference_input_ids)
  env.validate_builtin_arguments(arguments)
}

const descending_reference_output_indexes =
  fixtures.with_input_lists(
    fixtures.base,
    bodies.reference_inputs_descending_indexes,
    [fixtures.ordinary_input],
    fixtures.descending_input_output_indexes,
  )

test mint__input_order__rejects_descending_reference_indexes() fail {
  let arguments <- validate(descending_reference_output_indexes)
  env.validate_builtin_arguments(arguments)
}

const duplicate_reference_inputs =
  fixtures.with_input_lists(
    fixtures.base,
    bodies.reference_inputs_duplicate,
    [fixtures.ordinary_input],
    fixtures.duplicate_input_references,
  )

test mint__input_order__rejects_duplicate_reference_inputs() fail {
  let arguments <- validate(duplicate_reference_inputs)
  env.validate_builtin_arguments(arguments)
}

test mint__propagates_continuation_rejection() {
  let accepted = {
    let _arguments <- validate(fixtures.base)
    False
  }
  !accepted
}

// Each candidate has output index zero, so these cases exercise body
// authentication after passing the collateral-return index check.

const one_ordinary_output =
  fixtures.with_body(fixtures.base, bodies.with_one_output)

test mint__rejects_one_ordinary_output() fail {
  let arguments <- validate(one_ordinary_output)
  env.validate_builtin_arguments(arguments)
}

const multiple_ordinary_outputs =
  fixtures.with_body(fixtures.base, bodies.with_multiple_outputs)

test mint__rejects_multiple_ordinary_outputs() fail {
  let arguments <- validate(multiple_ordinary_outputs)
  env.validate_builtin_arguments(arguments)
}

const missing_outputs_field =
  fixtures.with_body(fixtures.base, bodies.missing_outputs)

test mint__rejects_missing_outputs_field() fail {
  let arguments <- validate(missing_outputs_field)
  env.validate_builtin_arguments(arguments)
}

const indefinite_empty_outputs =
  fixtures.with_body(fixtures.base, bodies.indefinite_empty_outputs)

test mint__rejects_indefinite_empty_outputs() fail {
  let arguments <- validate(indefinite_empty_outputs)
  env.validate_builtin_arguments(arguments)
}

const nonminimal_empty_outputs =
  fixtures.with_body(fixtures.base, bodies.nonminimal_empty_outputs)

test mint__rejects_nonminimal_empty_outputs() fail {
  let arguments <- validate(nonminimal_empty_outputs)
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
  fixtures.with_body(
    ProofFixture {
      ..fixtures.base,
      witness: FailedTransactionWitness { ..base_witness, withdrawal_amount: 1 },
    },
    bodies.nonzero_withdrawal,
  )

test mint__accepts_nonzero_withdrawal_amount() {
  let arguments <- validate(nonzero_withdrawal)
  env.validate_builtin_arguments(arguments)
}

const wrong_withdrawal_amount =
  ProofFixture { ..nonzero_withdrawal, witness: base_witness }

test mint__rejects_mismatched_withdrawal_amount() fail {
  let arguments <- validate(wrong_withdrawal_amount)
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
      let arguments <- validate(proof)
      let ProofFixture { witness, .. } = proof
      let FailedTransactionWitness { builtin_redeemer, .. } = witness
      expect DirectArguments(builtin_arguments) = builtin_redeemer
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
        builtin_redeemer: DirectArguments(
          builtin.map_data(
            [
              Pair(builtin.i_data(1), builtin.i_data(10)),
              Pair(builtin.i_data(2), builtin.i_data(20)),
              Pair(builtin.i_data(2), builtin.i_data(21)),
            ],
          ),
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
      builtin_redeemer: DirectArguments(fixtures.successful_arguments),
    },
  }

test mint__rejects_substituted_arguments() fail {
  let arguments <- validate(substituted_arguments)
  env.validate_builtin_arguments(arguments)
}

const reference_arguments =
  fixtures.with_reference_arguments(fixtures.base, bodies.reference_arguments)

test mint__collects_ordered_reference_arguments() {
  let arguments <- validate(reference_arguments)
  builtin.serialise_data(arguments) == builtin.serialise_data(
    fixtures.successful_arguments,
  ) && env.validate_builtin_arguments(arguments)
}

const descending_argument_references =
  fixtures.with_input_lists(
    reference_arguments,
    bodies.reference_arguments_descending_ids,
    [fixtures.ordinary_input],
    [
      fixtures.argument_reference_outref_0,
      fixtures.argument_reference_outref_2,
      fixtures.argument_reference_outref_1,
    ],
  )

test mint__input_order__rejects_descending_reference_argument_ids() fail {
  let arguments <- validate(descending_argument_references)
  env.validate_builtin_arguments(arguments)
}

const duplicate_argument_references =
  fixtures.with_input_lists(
    reference_arguments,
    bodies.reference_arguments_duplicate,
    [fixtures.ordinary_input],
    [
      fixtures.argument_reference_outref_0,
      fixtures.argument_reference_outref_1,
      fixtures.argument_reference_outref_1,
    ],
  )

test mint__input_order__rejects_duplicate_reference_argument_inputs() fail {
  let arguments <- validate(duplicate_argument_references)
  env.validate_builtin_arguments(arguments)
}

const reference_order_attack =
  fixtures.with_body(
    fixtures.reference_order_attack,
    bodies.reference_order_attack,
  )

test mint__reference_order__rejects_preparation_failure_proof() fail {
  let arguments <- validate(reference_order_attack)
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

const nonzero_output_index = with_output_index(fixtures.base, 1)

test mint__rejects_nonzero_collateral_return_index() fail {
  let arguments <- validate(nonzero_output_index)
  env.validate_builtin_arguments(arguments)
}

const one_output_collateral_return = with_output_index(one_ordinary_output, 1)

test mint__rejects_collateral_return_after_ordinary_output() fail {
  let arguments <- validate(one_output_collateral_return)
  env.validate_builtin_arguments(arguments)
}

// The builtin succeeds and ordinary output 0 exactly matches the declared
// collateral return. Body authentication must exclude this candidate.
const successful_ordinary_output =
  fixtures.with_arguments(
    fixtures.base,
    bodies.successful_matching_return_output,
    fixtures.successful_arguments,
  )

test mint__rejects_successful_transaction_ordinary_output() fail {
  let arguments <- validate(successful_ordinary_output)
  env.validate_builtin_arguments(arguments)
}

const wrong_network =
  fixtures.from_body(
    bodies.builtin_false_mainnet,
    base_witness.redeemer_encoding,
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
