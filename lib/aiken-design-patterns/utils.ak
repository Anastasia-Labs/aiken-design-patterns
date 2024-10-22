use aiken/builtin
use aiken/list.{foldl}
use aiken/transaction.{Input, Output, OutputReference}
use aiken/transaction/value.{AssetName, PolicyId}

/// Copied from [Fortuna](https://github.com/cardano-miners/fortuna/blob/5eeb1bc31b72252b991bbcaf836b128dca6a74b9/lib/fortuna/utils.ak#L6-L17).
pub fn resolve_output_reference(
  inputs: List<Input>,
  output_ref: OutputReference,
) -> Output {
  expect [input, ..] = inputs

  if input.output_reference == output_ref {
    input.output
  } else {
    resolve_output_reference(builtin.tail_list(inputs), output_ref)
  }
}

pub fn authentic_input_is_reproduced_unchanged(
  auth_symbol: PolicyId,
  optional_auth_name: Option<AssetName>,
  in_utxo: Output,
  out_utxo: Output,
) -> Bool {
  expect Output {
    value: in_val,
    datum: in_dat,
    address: in_addr,
    reference_script: None,
  } = in_utxo
  expect Output {
    value: out_val,
    datum: out_dat,
    address: out_addr,
    reference_script: None,
  } = out_utxo

  expect [(in_sym, in_name, in_quantity)] =
    in_val
      |> value.without_lovelace
      |> value.flatten

  let name_is_authentic =
    when optional_auth_name is {
      Some(auth_name) -> in_name == auth_name
      None -> True
    }
  and {
    in_val == out_val,
    in_dat == out_dat,
    in_addr.payment_credential == out_addr.payment_credential,
    in_sym == auth_symbol,
    name_is_authentic,
    in_quantity == 1,
  }
}

pub fn sum_of_squares(xs: List<Int>) -> List<Int> {
  [xs |> foldl(0, fn(x, acc) { acc + x * x })]
}
