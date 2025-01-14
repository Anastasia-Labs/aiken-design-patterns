use aiken/builtin
use aiken/crypto.{blake2b_224}
use aiken/fuzz
use aiken_design_patterns/merkelized_validator.{
  WithdrawRedeemer, WithdrawRedeemerIO, delegated_compute, delegated_validation,
  generic_delegated_validation, withdraw, withdraw_io,
}
use aiken_design_patterns/utils.{sum_of_squares}
use cardano/address.{Script}
use cardano/transaction.{Withdraw}

fn data_to_ints(d: Data) -> List<Int> {
  expect ints: List<Int> = d
  ints
}

test success_delegated_compute(script_hash via fuzz.bytearray_fixed(28)) {
  let redeemer = WithdrawRedeemerIO([0, 1, 2, 3, 4], 30)
  let redeemer_data: Data = redeemer
  let result =
    delegated_compute(
      [0, 1, 2, 3, 4],
      script_hash,
      data_to_ints,
      builtin.un_i_data,
      [Pair(Withdraw(Script(script_hash)), redeemer_data)],
    )
  and {
    result == 30,
    withdraw_io(sum_of_squares, redeemer),
  }
}

test fail_delegated_compute(script_hash via fuzz.bytearray_fixed(28)) fail {
  let redeemer = WithdrawRedeemerIO([0, 1, 2, 3, 4], 30)
  let redeemer_data: Data = redeemer
  let result =
    delegated_compute(
      [0, 1, 2, 3, 4],
      script_hash,
      data_to_ints,
      builtin.un_i_data,
      [Pair(Withdraw(Script(blake2b_224(script_hash))), redeemer_data)],
    )
  and {
    result == 30,
    withdraw_io(sum_of_squares, redeemer),
  }
}

test success_delegated_validation(script_hash via fuzz.bytearray_fixed(28)) {
  let redeemer = WithdrawRedeemer(42)
  let redeemer_data: Data = redeemer
  and {
    delegated_validation(
      42,
      script_hash,
      builtin.un_i_data,
      [Pair(Withdraw(Script(script_hash)), redeemer_data)],
    ),
    withdraw(fn(x: Int) { x == 42 }, redeemer),
  }
}

test fail_delegated_validation(script_hash via fuzz.bytearray_fixed(28)) fail {
  let redeemer = WithdrawRedeemer(42)
  let redeemer_data: Data = redeemer
  and {
    delegated_validation(
      42,
      script_hash,
      builtin.un_i_data,
      [Pair(Withdraw(Script(blake2b_224(script_hash))), redeemer_data)],
    ),
    withdraw(fn(x: Int) { x == 42 }, redeemer),
  }
}

test success_generic_delegated_validation(
  script_hash via fuzz.bytearray_fixed(28),
) {
  let redeemer_data: Data = builtin.i_data(42)
  generic_delegated_validation(
    script_hash,
    fn(rdmr: Data) -> Bool {
      let i = builtin.un_i_data(rdmr)
      i == 42
    },
    [Pair(Withdraw(Script(script_hash)), redeemer_data)],
  )
}

test fail_generic_delegated_validation(
  script_hash via fuzz.bytearray_fixed(28),
) fail {
  let redeemer_data: Data = builtin.i_data(42)
  generic_delegated_validation(
    script_hash,
    fn(rdmr: Data) -> Bool {
      let i = builtin.un_i_data(rdmr)
      i == 42
    },
    [Pair(Withdraw(Script(blake2b_224(script_hash))), redeemer_data)],
  )
}
