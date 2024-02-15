use aiken/list
use aiken/transaction.{Input, Output, ScriptContext, Spend, Transaction}

pub fn spend(
  validation_logic: fn(Output, Output) -> Bool,
  redeemer: (Int, Int),
  ctx: ScriptContext,
) -> Bool {
  expect ScriptContext { transaction: tx, purpose: Spend(own_ref) } = ctx

  let Transaction { inputs, outputs, .. } = tx

  let (in_ix, out_ix) = redeemer

  expect Some(Input { output: in_utxo, output_reference: in_ref }) =
    inputs |> list.at(in_ix)

  expect Some(out_utxo) = outputs |> list.at(out_ix)

  // Indicated input must match the spending one.
  expect (own_ref == in_ref)?

  validation_logic(in_utxo, out_utxo)
}
