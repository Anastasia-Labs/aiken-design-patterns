use aiken/transaction.{ScriptContext, Spend, WithdrawFrom}
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
