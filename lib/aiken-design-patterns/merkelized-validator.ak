use aiken/collection/list
use aiken/collection/pairs
use aiken/crypto.{ScriptHash}
use cardano/address.{Script}
use cardano/transaction.{Redeemer, ScriptPurpose, Withdraw}

pub type WithdrawRedeemer<a, b> {
  input_args: List<a>,
  results: List<b>,
}

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

pub fn withdraw(
  function: fn(List<a>) -> List<b>,
  redeemer: WithdrawRedeemer<a, b>,
) -> Bool {
  let WithdrawRedeemer { input_args, results } = redeemer
  let computed_results = function(input_args)
  results == computed_results
}
