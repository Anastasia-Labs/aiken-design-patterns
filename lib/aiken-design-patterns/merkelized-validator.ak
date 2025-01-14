//// Since transaction size is limited in Cardano, some validators benefit from a
//// solution which allows them to delegate parts of their logics. This becomes more
//// prominent in cases where such logics can greatly benefit from optimization
//// solutions that trade computation resources for script sizes (e.g. table
//// lookups can take up more space so that costly computations can be averted).
//// 
//// This design pattern offers an interface for off-loading such logics into an
//// external withdrawal script, so that the size of the validator itself can stay
//// within the limits of Cardano.
//// 
//// > [!NOTE]
//// > Be aware that total size of reference scripts is currently limited to 200KiB
//// > (204800 bytes), and they also impose additional fees in an exponential manner.
//// > See [here](https://github.com/IntersectMBO/cardano-ledger/issues/3952) and [here](https://github.com/CardanoSolutions/ogmios/releases/tag/v6.5.0) for
//// > more info.

use aiken/builtin
use aiken/collection/pairs
use aiken/crypto.{ScriptHash, blake2b_224}
use aiken/fuzz
use aiken_design_patterns/utils.{sum_of_squares}
use cardano/address.{Script}
use cardano/transaction.{Redeemer, ScriptPurpose, Withdraw}

/// Datatype for redeemer of the "computation stake validator" to represent
/// input argument(s) and output value(s).
///
/// As a simple example, a summation logic where it adds all its inputs
/// together, can work with a redeemer of
/// type `WithdrawRedeemerIO<List<Int>, Int>`, and a valid redeemer data would
/// be:
/// ```aiken
/// let valid_summation_io =
///   WithdrawRedeemerIO {
///     input_arg: [1, 2, 3, 4, 5],
///     result: 15,
///   }
/// ```
pub type WithdrawRedeemerIO<a, b> {
  input_arg: a,
  result: b,
}

/// Datatype for a delegated validation. Compared to `WithdrawRedeemerIO`, this
/// datatype only carries input argument(s), and simply validates whether the
/// computation passes.
pub type WithdrawRedeemer<a> {
  input_arg: a,
}

/// Given an arbitrary `Data` as input, this function expects to find
/// a `Withdraw` script purpose in `redeemers` for `staking_validator`, with a
/// redeemer of type [`WithdrawRedeemer<Data, Data>`](#withdrawredeemera-b),
/// which will be coerced into your custom datatypes using your provided `Data`
/// validators (`input_data_coercer` and `output_data_coercer`).
pub fn delegated_compute(
  function_input: a,
  staking_validator: ScriptHash,
  input_data_coercer: fn(Data) -> a,
  output_data_coercer: fn(Data) -> b,
  redeemers: Pairs<ScriptPurpose, Redeemer>,
) -> b {
  expect Some(rdmr) =
    redeemers
      |> pairs.get_first(Withdraw(Script(staking_validator)))
  expect WithdrawRedeemerIO { input_arg, result }: WithdrawRedeemerIO<
    Data,
    Data,
  > = rdmr

  let coerced_input = input_data_coercer(input_arg)

  // Given input argument must be identical to the one provided to the
  // withdrawal validator.
  expect (coerced_input == function_input)?

  // Return coerced result
  output_data_coercer(result)
}

/// Similar to [`delegated_compute`](#delegated_compute), with the difference
/// that now values are expected to be returned by the staking script.
pub fn delegated_validation(
  function_input: a,
  staking_validator: ScriptHash,
  input_data_coercer: fn(Data) -> a,
  redeemers: Pairs<ScriptPurpose, Redeemer>,
) -> Bool {
  expect Some(rdmr) =
    redeemers
      |> pairs.get_first(Withdraw(Script(staking_validator)))
  expect WithdrawRedeemer { input_arg }: WithdrawRedeemer<Data> = rdmr

  let coerced_input = input_data_coercer(input_arg)

  // Given input argument must be identical to the one provided to the
  // withdrawal validator.
  coerced_input == function_input
}

pub fn generic_delegated_validation(
  staking_validator: ScriptHash,
  withdraw_redeemer_validator: fn(Data) -> Bool,
  redeemers: Pairs<ScriptPurpose, Redeemer>,
) -> Bool {
  expect Some(rdmr) =
    redeemers
      |> pairs.get_first(Withdraw(Script(staking_validator)))
  withdraw_redeemer_validator(rdmr)
}

/// Helper function for defining your "computation stake validator." The
/// resulting stake validator will carry out the provided `function`'s logic,
/// and `redeemer` must contain the input(s) and expected output(s).
pub fn withdraw_io(
  function: fn(a) -> b,
  redeemer: WithdrawRedeemerIO<a, b>,
) -> Bool {
  let WithdrawRedeemerIO { input_arg, result } = redeemer
  let computed_result = function(input_arg)
  result == computed_result
}

/// Helper function for defining your delegated validation. The resulting stake
/// validator will carry out the provided `validation`'s logic with given
/// input(s) through its redeemer.
pub fn withdraw(
  validation: fn(a) -> Bool,
  redeemer: WithdrawRedeemer<a>,
) -> Bool {
  let WithdrawRedeemer { input_arg } = redeemer
  validation(input_arg)
}

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
