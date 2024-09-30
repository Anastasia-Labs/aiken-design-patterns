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

use aiken/collection/list
use aiken/collection/pairs
use aiken/crypto.{ScriptHash}
use cardano/address.{Script}
use cardano/transaction.{Redeemer, ScriptPurpose, Withdraw}

/// Datatype for redeemer of the "computation stake validator," to represent
/// input arguments and output values.
///
/// As a simple example, a summation logic where it adds all its inputs
/// together, can work with a redeemer of type `WithdrawRedeemer<Int, Int>`, and
/// valid redeemer data would be:
/// ```aiken
/// let valid_summation_io =
///   WithdrawRedeemer {
///     input_args: [1, 2, 3, 4, 5],
///     results: [15],
///   }
/// ```
pub type WithdrawRedeemer<a, b> {
  input_args: List<a>,
  results: List<b>,
}

/// Given a list of inputs, this function expects to find a `Withdraw` script
/// purpose in `redeemers` for `staking_validator`, with a redeemer of type
/// [`WithdrawRedeemer<Data, Data>`](#withdrawredeemera-b), which will be
/// coerced into your custom datatypes using your provided `Data` validators
/// (`input_data_coercer` and `output_data_coercer`).
pub fn delegated_compute(
  function_args: List<a>,
  staking_validator: ScriptHash,
  input_data_coercer: fn(Data) -> a,
  output_data_coercer: fn(Data) -> b,
  redeemers: Pairs<ScriptPurpose, Redeemer>,
) -> List<b> {
  expect Some(rdmr) =
    redeemers
      |> pairs.get_first(Withdraw(Script(staking_validator)))
  expect WithdrawRedeemer { input_args, results }: WithdrawRedeemer<Data, Data> =
    rdmr

  // Given input arguments must be identical to the ones provided to the
  // withdrawal validator.
  expect (list.map(input_args, input_data_coercer) == function_args)?
  results |> list.map(output_data_coercer)
}

/// Helper function for defining your "computation stake validator." The
/// resulting stake validator will carry out the provided `function`'s logic,
/// and `redeemer` must contain the inputs and expected outputs.
pub fn withdraw(
  function: fn(List<a>) -> List<b>,
  redeemer: WithdrawRedeemer<a, b>,
) -> Bool {
  let WithdrawRedeemer { input_args, results } = redeemer
  let computed_results = function(input_args)
  results == computed_results
}
