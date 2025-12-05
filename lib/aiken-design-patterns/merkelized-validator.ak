//// Since transaction size is limited in Cardano, some scripts benefit from a
//// solution which allows them to delegate parts of their validations. This
//// becomes more prominent in cases where such validations can greatly benefit
//// from optimization solutions that trade computation resources for script
//// sizes (e.g. table lookups can take up more space so that costly
//// computations can be averted).
//// 
//// This design pattern offers an interface for off-loading such validations
//// into an external observer/withdrawal script, so that the sizes of the
//// scripts themselves can stay within the limits of Cardano.
//// 
//// > [!NOTE]
//// > Be aware that total size of reference scripts is currently limited to
//// > 200KiB (204800 bytes), and they also impose additional fees in an 
//// > exponential manner. See [here](https://github.com/IntersectMBO/cardano-ledger/issues/3952)
//// > and [here](https://github.com/CardanoSolutions/ogmios/releases/tag/v6.5.0)
//// > for more info.

use aiken/crypto.{ScriptHash}
use aiken_design_patterns/utils.{get_withdraw_scripts_redeemer_at}
use cardano/transaction.{Redeemer, ScriptPurpose}

/// Datatype for redeemer of the "computation staking validator" to represent
/// input argument(s) and output value(s).
///
/// As a simple example, a summation logic where it adds all its inputs
/// together, can work with a redeemer of
/// type `ComputationRedeemer<List<Int>, Int>`, and a valid redeemer data would
/// be:
/// ```aiken
/// let valid_summation_io =
///   ComputationRedeemer {
///     input_arg: [1, 2, 3, 4, 5],
///     result: 15,
///   }
/// ```
pub type ComputationRedeemer<a, b> {
  input_arg: a,
  result: b,
}

/// Datatype for a delegated validation. Compared to `ComputationRedeemer`, this
/// datatype only carries input argument(s), and simply validates whether the
/// computation passes.
pub type ValidationRedeemer<a> {
  input_arg: a,
}

/// Given an arbitrary `Data` as input, this function expects to find
/// a `Withdraw` script purpose in `redeemers` for `staking_validator`, with a
/// redeemer of type [`ValidationRedeemer<Data, Data>`](#withdrawredeemera-b),
/// which will be coerced into your custom datatypes using your provided `Data`
/// validators (`input_data_coercer` and `output_data_coercer`).
pub fn delegated_compute(
  function_input: a,
  staking_validator: ScriptHash,
  redeemers: Pairs<ScriptPurpose, Redeemer>,
  redeemer_index: Int,
  input_data_coercer: fn(Data) -> a,
  output_data_coercer: fn(Data) -> b,
) -> b {
  expect ComputationRedeemer { input_arg, result }: ComputationRedeemer<
    Data,
    Data,
  > =
    get_withdraw_scripts_redeemer_at(
      staking_validator,
      redeemers,
      redeemer_index,
    )

  let coerced_input = input_data_coercer(input_arg)

  // Given input argument must be identical to the one provided to the
  // withdrawal validator.
  expect coerced_input == function_input

  // Return coerced result
  output_data_coercer(result)
}

/// Similar to [`delegated_compute`](#delegated_compute), with the difference
/// that no values are expected to be returned by the staking script.
pub fn delegated_validation(
  function_input: a,
  staking_validator: ScriptHash,
  redeemers: Pairs<ScriptPurpose, Redeemer>,
  redeemer_index: Int,
  input_data_coercer: fn(Data) -> a,
) -> Bool {
  expect ValidationRedeemer { input_arg }: ValidationRedeemer<Data> =
    get_withdraw_scripts_redeemer_at(
      staking_validator,
      redeemers,
      redeemer_index,
    )

  let coerced_input = input_data_coercer(input_arg)

  // Given input argument must be identical to the one provided to the
  // withdrawal validator.
  coerced_input == function_input
}

pub fn generic_delegated_validation(
  staking_validator: ScriptHash,
  redeemers: Pairs<ScriptPurpose, Redeemer>,
  redeemer_index: Int,
  withdraw_redeemer_validator: fn(Data) -> Bool,
) -> Bool {
  let rdmr =
    get_withdraw_scripts_redeemer_at(
      staking_validator,
      redeemers,
      redeemer_index,
    )
  withdraw_redeemer_validator(rdmr)
}

/// Helper function for defining your "computation stake validator." The
/// resulting stake validator will carry out the provided `function`'s logic,
/// and `redeemer` must contain the input(s) and expected output(s).
pub fn computation_withdrawal_wrapper(
  redeemer: ComputationRedeemer<a, b>,
  function: fn(a) -> b,
) -> Bool {
  let ComputationRedeemer { input_arg, result } = redeemer
  let computed_result = function(input_arg)
  result == computed_result
}

/// Helper function for defining your delegated validation. The resulting stake
/// validator will carry out the provided `validation`'s logic with given
/// input(s) through its redeemer.
pub fn validation_withdrawal_wrapper(
  redeemer: ValidationRedeemer<a>,
  validation: fn(a) -> Bool,
) -> Bool {
  let ValidationRedeemer { input_arg } = redeemer
  validation(input_arg)
}
