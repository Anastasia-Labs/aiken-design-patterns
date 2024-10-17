use aiken/collection/list
use aiken_design_patterns/utils as utils
use cardano/transaction.{Input, NoDatum, Output, OutputReference, Transaction}

/// Spend endpoint helper function. By including this in your validator, you'll
/// an efficient access to your input, and a corresponding output.
///
/// > [!NOTE]
/// > This function has no protection against
/// > [double satisfaction](https://github.com/Plutonomicon/plutonomicon/blob/b6906173c3f98fb5d7b40fd206f9d6fe14d0b03b/vulnerabilities.md#double-satisfaction)
/// > vulnerability, as this can be done in multiple ways depending on the
/// > contract. If you can tolerate some extra overhead, consider using the
/// > multi-utxo-indexer (one-to-one) pattern for a convenient way of preventing
/// > this attack vector.
pub fn spend(
  validation_logic: fn(Output, Output) -> Bool,
  redeemer: Pair<Int, Int>,
  own_ref: OutputReference,
  tx: Transaction,
) -> Bool {
  let Transaction { inputs, outputs, .. } = tx

  let Pair(in_ix, out_ix) = redeemer

  expect Some(Input { output: in_utxo, output_reference: in_ref }) =
    inputs |> list.at(in_ix)

  expect Some(out_utxo) = outputs |> list.at(out_ix)

  // Indicated input must match the spending one.
  expect (own_ref == in_ref)?

  validation_logic(in_utxo, out_utxo)
}

test success_spend(
  script_hash_and_inputs via utils.inputs_with_an_authentic_script_input_fuzzer(NoDatum)
) {
  let (script_hash, script_input, inputs) = script_hash_and_inputs
  expect Some(input_index) = list.indexed_foldr(inputs, 0, fn(i, input, m_i) {
    when m_i is {
      Some(_) -> m_i
      None -> {
        when input.output.address.payment_credential is {
          Script(_) -> Some(i)
          _ -> None
        }
      }
    }
  })
  let tx =
    Transaction {
      ..placeholder,
      inputs,
      outputs: [script_input.output],
    }
  spend(
    fn(_i, _o) { True },
    Pair(input_index, 0),
    script_input.output_reference,
    tx
  )
}
