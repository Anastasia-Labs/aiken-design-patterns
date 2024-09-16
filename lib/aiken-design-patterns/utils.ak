use aiken/builtin
use aiken/collection/list.{foldl}
use cardano/assets.{AssetName, PolicyId}
use cardano/transaction.{Input, Output, OutputReference}

// Copied over from cardano-miners/fortuna
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
      |> assets.without_lovelace
      |> assets.flatten

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
