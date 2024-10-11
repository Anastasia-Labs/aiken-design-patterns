use aiken/builtin
use aiken/collection/list.{foldl}
use cardano/assets.{AssetName, PolicyId}
use cardano/transaction.{Input, Output, OutputReference}

// Credit for these fold function goes to KtorZ
// {{{
type Fold2<a, b, result> =
  fn(a, b) -> result

type Fold3<a, b, c, result> =
  fn(a, b, c) -> result

type Fold4<a, b, c, d, result> =
  fn(a, b, c, d) -> result

fn do_foldl2(
  self: List<x>,
  with: fn(x, a, b, Fold2<a, b, result>) -> result,
  return: Fold2<a, b, result>,
) -> Fold2<a, b, result> {
  when self is {
    [] -> return
    [x, ..xs] -> do_foldl2(xs, with, fn(a, b) { with(x, a, b, return) })
  }
}

fn do_foldr2(
  self: List<x>,
  with: fn(x, a, b, Fold2<a, b, result>) -> result,
  return: Fold2<a, b, result>,
) -> Fold2<a, b, result> {
  when self is {
    [] -> return
    [x, ..xs] -> {
      let accA, accB <- do_foldr2(xs, with)
      with(x, accA, accB, return)
    }
  }
}

fn do_foldl3(
  self: List<x>,
  with: fn(x, a, b, c, Fold3<a, b, c, result>) -> result,
  return: Fold3<a, b, c, result>,
) -> Fold3<a, b, c, result> {
  when self is {
    [] -> return
    [x, ..xs] -> do_foldl3(xs, with, fn(a, b, c) { with(x, a, b, c, return) })
  }
}

fn do_foldr3(
  self: List<x>,
  with: fn(x, a, b, c, Fold3<a, b, c, result>) -> result,
  return: Fold3<a, b, c, result>,
) -> Fold3<a, b, c, result> {
  when self is {
    [] -> return
    [x, ..xs] -> {
      let accA, accB, accC <- do_foldr3(xs, with)
      with(x, accA, accB, accC, return)
    }
  }
}

fn do_foldl4(
  self: List<x>,
  with: fn(x, a, b, c, d, Fold4<a, b, c, d, result>) -> result,
  return: Fold4<a, b, c, d, result>,
) -> Fold4<a, b, c, d, result> {
  when self is {
    [] -> return
    [x, ..xs] -> do_foldl4(xs, with, fn(a, b, c, d) { with(x, a, b, c, d, return) })
  }
}

fn do_foldr4(
  self: List<x>,
  with: fn(x, a, b, c, d, Fold4<a, b, c, d, result>) -> result,
  return: Fold4<a, b, c, d, result>,
) -> Fold4<a, b, c, d, result> {
  when self is {
    [] -> return
    [x, ..xs] -> {
      let accA, accB, accC, accD <- do_foldr4(xs, with)
      with(x, accA, accB, accC, accD, return)
    }
  }
}

pub fn foldl2(
  self: List<x>,
  zero_a: a,
  zero_b: b,
  with: fn(x, a, b, Fold2<a, b, result>) -> result,
  return: Fold2<a, b, result>,
) -> result {
  do_foldl2(self, with, return)(zero_a, zero_b)
}

pub fn foldr2(
  self: List<x>,
  zero_a: a,
  zero_b: b,
  with: fn(x, a, b, Fold2<a, b, result>) -> result,
  return: Fold2<a, b, result>,
) -> result {
  do_foldr2(self, with, return)(zero_a, zero_b)
}

pub fn foldl3(
  self: List<x>,
  zero_a: a,
  zero_b: b,
  zero_c: c,
  with: fn(x, a, b, c, Fold3<a, b, c, result>) -> result,
  return: Fold3<a, b, c, result>,
) -> result {
  do_foldl3(self, with, return)(zero_a, zero_b, zero_c)
}

pub fn foldr3(
  self: List<x>,
  zero_a: a,
  zero_b: b,
  zero_c: c,
  with: fn(x, a, b, c, Fold3<a, b, c, result>) -> result,
  return: Fold3<a, b, c, result>,
) -> result {
  do_foldr3(self, with, return)(zero_a, zero_b, zero_c)
}

pub fn foldl4(
  self: List<x>,
  zero_a: a,
  zero_b: b,
  zero_c: c,
  zero_d: d,
  with: fn(x, a, b, c, d, Fold4<a, b, c, d, result>) -> result,
  return: Fold4<a, b, c, d, result>,
) -> result {
  do_foldl4(self, with, return)(zero_a, zero_b, zero_c, zero_d)
}

pub fn foldr4(
  self: List<x>,
  zero_a: a,
  zero_b: b,
  zero_c: c,
  zero_d: d,
  with: fn(x, a, b, c, d, Fold4<a, b, c, d, result>) -> result,
  return: Fold4<a, b, c, d, result>,
) -> result {
  do_foldr4(self, with, return)(zero_a, zero_b, zero_c, zero_d)
}
// }}}

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
