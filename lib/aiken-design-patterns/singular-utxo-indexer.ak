use aiken/builtin
use aiken/collection/list
use aiken_design_patterns/utils
use aiken_scott_utils/list as list_extra
use cardano/transaction.{Input, NoDatum, Output, OutputReference}

pub type IndexerValidations {
  double_satisfaction_prevented: Bool,
  rest_of_the_validations: Bool,
}

/// Spend endpoint helper function. By including this in your validator, you'll
/// get an efficient access to your input, and a corresponding output.
///
/// > [!NOTE]
/// > This function has no protection against
/// > [double satisfaction](https://github.com/Plutonomicon/plutonomicon/blob/b6906173c3f98fb5d7b40fd206f9d6fe14d0b03b/vulnerabilities.md#double-satisfaction)
/// > vulnerability, as this can be done in multiple ways depending on the
/// > contract. If you can tolerate some extra overhead, consider using the
/// > multi-utxo-indexer (one-to-one) pattern for a convenient way of preventing
/// > this attack vector. Otherwise, consider tagging your output with input's
/// > output reference.
pub fn one_to_one(
  validation_logic: fn(Int, Input, a, Int, Output) -> IndexerValidations,
  redeemer: a,
  input_index: Int,
  output_index: Int,
  own_ref: OutputReference,
  inputs: List<Input>,
  outputs: List<Output>,
) -> Bool {
  expect Some(Input { output_reference: in_ref, .. } as in_input) =
    inputs |> list.at(input_index)

  expect Some(out_utxo) = outputs |> list.at(output_index)

  // Indicated input must match the spending one.
  expect (own_ref == in_ref)?

  validation_logic(input_index, in_input, redeemer, output_index, out_utxo)
    |> validate_indexer_validations
}

/// Spend endpoint helper function. By including this in your validator, you'll
/// have an efficient access to your input, its corresponding outputs, total
/// output value and count.
///
/// > [!NOTE]
/// > This function has no protection against
/// > [double satisfaction](https://github.com/Plutonomicon/plutonomicon/blob/b6906173c3f98fb5d7b40fd206f9d6fe14d0b03b/vulnerabilities.md#double-satisfaction)
/// > vulnerability, as this can be done in multiple ways depending on the
/// > contract. If you can tolerate some extra overhead, consider using the
/// > multi-utxo-indexer (one-to-many) pattern for a convenient way of
/// > preventing this attack vector.
///
/// Required validation functions are provided with:
/// 1. Input index, `Input` itself, redeemer, output index, and `Output` itself
///    (this validation is executed for each output)
/// 2. Input index, `Input` itself, redeemer, and the list of all `Output`s
///    (this validation is executed only once)
pub fn one_to_many(
  input_output_validator: fn(Int, Input, a, Int, Output) -> IndexerValidations,
  input_collective_outputs_validator: fn(Int, Input, a, List<Output>) -> Bool,
  redeemer: a,
  input_index: Int,
  output_indices: List<Int>,
  own_ref: OutputReference,
  inputs: List<Input>,
  outputs: List<Output>,
) -> Bool {
  expect Some(input) = inputs |> list.at(input_index)

  let
    _,
    all_outputs,
  <-
    list_extra.foldr2(
      output_indices,
      // sufficiently large index to ensure first check passes
      511,
      [],
      fn(curr_ix, prev_ix, outputs_acc, return) {
        if curr_ix < prev_ix {
          expect Some(out_utxo) = outputs |> list.at(curr_ix)
          expect
            input_output_validator(
              input_index,
              input,
              redeemer,
              curr_ix,
              out_utxo,
            )
              |> validate_indexer_validations
          return(curr_ix, list.push(outputs_acc, out_utxo))
        } else {
          fail @"Output indices must be in ascending order"
        }
      },
    )

  // Indicated input must match the spending one.
  expect (own_ref == input.output_reference)?

  input_collective_outputs_validator(input_index, input, redeemer, all_outputs)
}

fn validate_indexer_validations(validations: IndexerValidations) -> Bool {
  let validations_list: Data = builtin.unconstr_fields(validations)

  let expected_validations: Data = [True, True]

  validations_list == expected_validations
}

fn always_true_indexer_validations(_ii, _i, _r, _oi, _o) -> IndexerValidations {
  IndexerValidations {
    double_satisfaction_prevented: True,
    rest_of_the_validations: True,
  }
}

test success__one_to_one(
  script_hash_and_inputs via utils.inputs_with_an_authentic_script_input_fuzzer(
    NoDatum,
  ),
) {
  let (_script_hash, script_input, inputs) = script_hash_and_inputs
  let input_index = utils.find_index_of_first_script_input(inputs)
  one_to_one(
    always_true_indexer_validations,
    0,
    input_index,
    0,
    script_input.output_reference,
    inputs,
    [script_input.output],
  )
}

test fail__one_to_one__bad_outputs(
  script_hash_and_inputs via utils.inputs_with_an_authentic_script_input_fuzzer(
    NoDatum,
  ),
) fail {
  let (_script_hash, script_input, inputs) = script_hash_and_inputs
  let input_index = utils.find_index_of_first_script_input(inputs)
  one_to_one(
    always_true_indexer_validations,
    0,
    input_index,
    0,
    script_input.output_reference,
    inputs,
    [],
  )
}

test success__one_to_many(
  script_hash_and_inputs via utils.inputs_with_an_authentic_script_input_fuzzer(
    NoDatum,
  ),
) {
  let (_script_hash, script_input, inputs) = script_hash_and_inputs
  let input_index = utils.find_index_of_first_script_input(inputs)
  trace Pair(input_index, list.range(0, 9))
  one_to_many(
    always_true_indexer_validations,
    fn(_ii, _i, _r, _os) { True },
    0,
    input_index,
    list.range(0, 9),
    script_input.output_reference,
    inputs,
    list.repeat(script_input.output, 10),
  )
}

test fail__one_to_many__bad_outputs(
  script_hash_and_inputs via utils.inputs_with_an_authentic_script_input_fuzzer(
    NoDatum,
  ),
) fail {
  let (_script_hash, script_input, inputs) = script_hash_and_inputs
  let input_index = utils.find_index_of_first_script_input(inputs)
  one_to_many(
    always_true_indexer_validations,
    fn(_ii, _i, _r, _os) { True },
    0,
    input_index,
    list.range(0, 9),
    script_input.output_reference,
    inputs,
    [],
  )
}
