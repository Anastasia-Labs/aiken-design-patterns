use aiken/dict.{Dict}
use aiken/transaction.{Redeemer, ScriptContext, ScriptPurpose, WithdrawFrom}
use aiken/transaction/credential.{StakeCredential}

pub type WithdrawRedeemer {
  input_args: List<Data>,
  results: List<Data>,
}

pub fn withdraw(
  function: fn(List<Data>) -> List<Data>,
  redeemer: WithdrawRedeemer,
  ctx: ScriptContext,
) -> Bool {
  expect ScriptContext { purpose: WithdrawFrom(_), .. } = ctx
  let WithdrawRedeemer { input_args, results } = redeemer
  let computed_results = function(input_args)
  results == computed_results
}

pub fn spend(
  staking_validator: StakeCredential,
  function_args: List<Data>,
  expected_outputs: List<Data>,
  redeemers: Dict<ScriptPurpose, Redeemer>,
) -> Bool {
  expect Some(rdmr) = redeemers |> dict.get(WithdrawFrom(staking_validator))
  expect WithdrawRedeemer { input_args, results }: WithdrawRedeemer = rdmr

  // Provided input arguments must be identical to the ones validated by the
  // withdrawal validator.
  expect (input_args == function_args)?

  // Given outputs don't mach with the withdrawal validator's.
  results == expected_outputs
}
