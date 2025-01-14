use aiken/collection/list
use cardano/transaction.{Input, Output, OutputReference, Transaction}

/// Spend endpoint helper function. By including this in your validator, you'll
/// get an efficient access to your input, and a corresponding output.
///
/// > [!NOTE]
/// > This function has no protection against
/// > [double satisfaction](https://github.com/Plutonomicon/plutonomicon/blob/b6906173c3f98fb5d7b40fd206f9d6fe14d0b03b/vulnerabilities.md#double-satisfaction)
/// > vulnerability, as this can be done in multiple ways depending on the
/// > contract. If you can tolerate some extra overhead, consider using the
/// > multi-utxo-indexer (one-to-one) pattern for a convenient way of preventing
/// > this attack vector. Otherwise, consider tagging your output with input's
/// > output reference.
pub fn spend(
  validation_logic: fn(Int, Input, a, Int, Output) -> Bool,
  redeemer: a,
  input_index: Int,
  output_index: Int,
  own_ref: OutputReference,
  tx: Transaction,
) -> Bool {
  let Transaction { inputs, outputs, .. } = tx

  expect Some(Input { output_reference: in_ref, .. } as in_input) =
    inputs |> list.at(input_index)

  expect Some(out_utxo) = outputs |> list.at(output_index)

  // Indicated input must match the spending one.
  expect (own_ref == in_ref)?

  validation_logic(input_index, in_input, redeemer, output_index, out_utxo)
}
