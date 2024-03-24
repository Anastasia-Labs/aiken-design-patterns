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
  redeemers: Dict<ScriptPurpose, Redeemer>,
) -> List<Data> {
  expect Some(rdmr) =
    redeemers
      |> dict.get(WithdrawFrom(Inline(ScriptCredential(staking_validator))))
  expect WithdrawRedeemer { input_args, results }: WithdrawRedeemer<Data, Data> =
    rdmr

  // Given input arguments must be identical to the ones provided to the
  // withdrawal validator.
  expect (input_args == function_args)?
  results
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
