use aiken/transaction.{
  Input,
  Output,
  OutputReference,
}

// Copied from:
// https://github.com/aiken-lang/fortuna
pub fn resolve_output_reference(
  inputs: List<Input>,
  output_ref: OutputReference
) -> Output {
  expect [input, ..inputs] = inputs

  if input.output_reference == output_ref {
    input.output
  } else {
    resolve_output_reference(inputs, output_ref)
  }
}


