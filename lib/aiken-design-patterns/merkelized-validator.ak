use aiken/dict.{Dict}
use aiken/hash.{Blake2b_224, Hash}
use aiken/transaction.{Redeemer, ScriptContext, ScriptPurpose, WithdrawFrom}
use aiken/transaction/credential.{Inline, Script, ScriptCredential}

pub type WithdrawRedeemer<a, b> {
  input_args: List<a>,
  results: List<b>,
}

pub fn spend(
  staking_validator: Hash<Blake2b_224, Script>,
  function_args: List<Data>,
  expected_outputs: List<Data>,
  redeemers: Dict<ScriptPurpose, Redeemer>,
) -> Bool {
  expect Some(rdmr) =
    redeemers
      |> dict.get(WithdrawFrom(Inline(ScriptCredential(staking_validator))))
  expect WithdrawRedeemer { input_args, results }: WithdrawRedeemer<Data, Data> =
    rdmr

  and {
    // Given input arguments must be identical to the ones provided to the
    // withdrawal validator.
    input_args == function_args,
    // Given outputs don't mach with the withdrawal validator's.
    results == expected_outputs,
  }
}

pub fn withdraw(
  function: fn(List<a>) -> List<b>,
  redeemer: WithdrawRedeemer<a, b>,
  ctx: ScriptContext,
) -> Bool {
  expect ScriptContext { purpose: WithdrawFrom(_), .. } = ctx
  let WithdrawRedeemer { input_args, results } = redeemer
  let computed_results = function(input_args)
  results == computed_results
}
