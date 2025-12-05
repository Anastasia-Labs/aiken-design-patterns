use aiken/builtin
use aiken/crypto.{blake2b_224}
use aiken/fuzz
use aiken_design_patterns/merkelized_validator.{
  ComputationRedeemer, ValidationRedeemer, computation_withdrawal_wrapper,
  delegated_compute, delegated_validation, generic_delegated_validation,
  validation_withdrawal_wrapper,
}
use aiken_design_patterns/utils.{sum_of_squares}
use cardano/address.{Script}
use cardano/transaction.{Withdraw}

fn data_to_ints(d: Data) -> List<Int> {
  expect ints: List<Int> = d
  ints
}

test success__delegated_compute(script_hash via fuzz.bytearray_fixed(28)) {
  let redeemer = ComputationRedeemer { input_arg: [0, 1, 2, 3, 4], result: 30 }
  let redeemer_data: Data = redeemer
  let result =
    [0, 1, 2, 3, 4]
      |> delegated_compute(
          script_hash,
          [Pair(Withdraw(Script(script_hash)), redeemer_data)],
          0,
          data_to_ints,
          builtin.un_i_data,
        )
  and {
    result == 30,
    computation_withdrawal_wrapper(redeemer, sum_of_squares),
  }
}

test fail__delegated_compute__bad_script(
  script_hash via fuzz.bytearray_fixed(28),
) fail {
  let redeemer = ComputationRedeemer { input_arg: [0, 1, 2, 3, 4], result: 30 }
  let redeemer_data: Data = redeemer
  let result =
    [0, 1, 2, 3, 4]
      |> delegated_compute(
          script_hash,
          [Pair(Withdraw(Script(blake2b_224(script_hash))), redeemer_data)],
          0,
          data_to_ints,
          builtin.un_i_data,
        )
  and {
    result == 30,
    computation_withdrawal_wrapper(redeemer, sum_of_squares),
  }
}

test success__delegated_validation(script_hash via fuzz.bytearray_fixed(28)) {
  let redeemer = ValidationRedeemer { input_arg: 42 }
  let redeemer_data: Data = redeemer
  let validated_by_delegation =
    42
      |> delegated_validation(
          script_hash,
          [Pair(Withdraw(Script(script_hash)), redeemer_data)],
          0,
          builtin.un_i_data,
        )
  let input <- validation_withdrawal_wrapper(redeemer)
  and {
    validated_by_delegation,
    input == 42,
  }
}

test fail__delegated_validation__bad_script(
  script_hash via fuzz.bytearray_fixed(28),
) fail {
  let redeemer = ValidationRedeemer { input_arg: 42 }
  let redeemer_data: Data = redeemer
  let validated_by_delegation =
    42
      |> delegated_validation(
          script_hash,
          [Pair(Withdraw(Script(blake2b_224(script_hash))), redeemer_data)],
          0,
          builtin.un_i_data,
        )
  let input <- validation_withdrawal_wrapper(redeemer)
  and {
    validated_by_delegation,
    input == 42,
  }
}

test success__generic_delegated_validation(
  script_hash via fuzz.bytearray_fixed(28),
) {
  let redeemer_data: Data = builtin.i_data(42)
  let rdmr <-
    generic_delegated_validation(
      script_hash,
      [Pair(Withdraw(Script(script_hash)), redeemer_data)],
      0,
    )
  let i = builtin.un_i_data(rdmr)
  i == 42
}

test fail__generic_delegated_validation__bad_script(
  script_hash via fuzz.bytearray_fixed(28),
) fail {
  let redeemer_data: Data = builtin.i_data(42)
  let rdmr <-
    generic_delegated_validation(
      script_hash,
      [Pair(Withdraw(Script(blake2b_224(script_hash))), redeemer_data)],
      0,
    )
  let i = builtin.un_i_data(rdmr)
  i == 42
}
