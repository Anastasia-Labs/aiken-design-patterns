use aiken/collection/list
use cardano/transaction.{Input, Output, OutputReference, Spend, Transaction}

pub fn spend(
  validation_logic: fn(Output, Output) -> Bool,
  redeemer: (Int, Int),
  own_ref: OutputReference,
  tx: Transaction,
) -> Bool {
  let Transaction { inputs, outputs, .. } = tx

  let (in_ix, out_ix) = redeemer

  expect Some(Input { output: in_utxo, output_reference: in_ref }) =
    inputs |> list.at(in_ix)

  expect Some(out_utxo) = outputs |> list.at(out_ix)

  // Indicated input must match the spending one.
  expect (own_ref == in_ref)?

  validation_logic(in_utxo, out_utxo)
}
