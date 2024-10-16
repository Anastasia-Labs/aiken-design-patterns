use aiken/builtin
use aiken/collection/list.{foldl}
use aiken/fuzz
use cardano/address.{Script}
use cardano/assets.{AssetName, PolicyId}
use cardano/transaction.{
  Datum, InlineDatum, Input, NoDatum, Output, OutputReference,
}
use cardano/transaction/output_reference as output_reference

// Credit for these fold functions goes to KtorZ
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
    [x, ..xs] ->
      do_foldl4(xs, with, fn(a, b, c, d) { with(x, a, b, c, d, return) })
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

/// A fuzzer for `Value` with a single asset. Unsafely expects 28 bytes long
/// policy ID to be provided.
pub fn single_specific_asset_value_fuzzer(policyId: ByteArray) -> Fuzzer<Value> {
  let token_name_length <- and_then(fuzz.int_between(0, 32))
  let token_name <- and_then(fuzz.bytearray_fixed(token_name_length))
  let quantity <- and_then(fuzz.int_at_least(1))
  fuzz.constant(assets.from_asset(policyId, token_name, quantity))
}

/// A `Value` fuzzer with a single asset. Randomly generates the policy ID.
pub fn single_asset_value_fuzzer() -> Fuzzer<Value> {
  let policyId <- and_then(fuzz.bytearray_fixed(28))
  single_specific_asset_value_fuzzer(policyId)
}

/// A `Value` fuzzer, guaranteed to include some amount of ADA (minimum must be
/// specified).
pub fn value_fuzzer(min_lovelaces: Int) -> Fuzzer<Value> {
  let lovelace_count <- and_then(fuzz.int_at_least(min_lovelaces))
  let lovelace_value = assets.from_lovelace(lovelace_count)
  let other_assets_values <-
    and_then(fuzz.list_at_most(single_asset_value_fuzzer(), 256))
  fuzz.constant(
    list.foldl(
      other_assets_values,
      lovelace_value,
      fn(v, acc) { assets.merge(v, acc) },
    ),
  )
}

/// Output reference fuzzer, transaction ID with 32 bytes, and output index
/// between 0 and 512.
pub fn output_reference_fuzzer() -> Fuzzer<OutputReference> {
  let ref_bytes <- and_then(fuzz.bytearray_fixed(32))
  let output_index <- and_then(fuzz.int_between(0, 512))
  fuzz.constant(OutputReference { transaction_id: ref_bytes, output_index })
}

/// Simple wallet UTxO fuzzer, with a random number of tokens/NFTs.
pub fn user_output_fuzzer() -> Fuzzer<Output> {
  let pkh <- and_then(fuzz.bytearray_fixed(28))
  let skh <- and_then(fuzz.bytearray_fixed(28))
  let v <- and_then(value_fuzzer(2_000_000))
  fuzz.constant(
    Output {
      address: Address {
        payment_credential: VerificationKey(pkh),
        stake_credential: Some(Inline(VerificationKey(skh))),
      },
      value: v,
      datum: NoDatum,
      reference_script: None,
    },
  )
}

/// Simple wallet UTxO fuzzer, with a random reference output and a random
/// number of tokens/NFTs.
pub fn user_input_fuzzer() -> Fuzzer<Input> {
  let output_reference <- and_then(output_reference_fuzzer())
  let output <- and_then(user_output_fuzzer())
  fuzz.constant(Input { output_reference, output })
}

/// Returns a tuple where its first element is the random script hash (payment
/// part of the UTxO's address). UTxO value is also random, with 2 ADA.
pub fn script_output_fuzzer(
  m_datum: Option<Datum>,
) -> Fuzzer<(ByteArray, Output)> {
  let script_hash <- and_then(fuzz.bytearray_fixed(28))
  let v <- and_then(value_fuzzer(2_000_000))
  fuzz.constant(
    (
      script_hash,
      Output {
        address: Address {
          payment_credential: Script(script_hash),
          stake_credential: None,
        },
        value: v,
        datum: when m_datum is {
          None -> NoDatum
          Some(datum_data) -> InlineDatum(datum_data)
        },
        reference_script: None,
      },
    ),
  )
}

/// UTxO fuzzer, where the value is composed of 2 ADA and a beacon NFT, such
/// that its policy ID is equal to the script credential of the payment part of
/// UTxO's address. This script hash is also returned.
pub fn authentic_script_output_fuzzer(
  m_datum: Option<Datum>,
) -> Fuzzer<(ByteArray, Output)> {
  let script_hash <- and_then(fuzz.bytearray_fixed(28))
  let tn <- and_then(fuzz.bytearray_between(0, 32))
  let lovelace_value = assets.from_lovelace(2_000_000)
  let beacon = assets.from_asset(script_hash, tn, 1)
  let v = assets.merge(lovelace_value, beacon)
  fuzz.constant(
    (
      script_hash,
      Output {
        address: Address {
          payment_credential: Script(script_hash),
          stake_credential: None,
        },
        value: v,
        datum: when m_datum is {
          None -> NoDatum
          Some(datum_data) -> InlineDatum(datum_data)
        },
        reference_script: None,
      },
    ),
  )
}

/// Similar to [`script_output_fuzzer`](#script_output_fuzzer), with an
/// additional randomized wrapper for output reference.
pub fn script_input_fuzzer(m_datum: Option<Datum>) -> Fuzzer<(ByteArray, Input)> {
  let output_reference <- and_then(output_reference_fuzzer())
  let (script_hash, output) <- and_then(script_output_fuzzer(m_datum))
  fuzz.constant((script_hash, Input { output_reference, output }))
}

/// Similar to [`authentic_script_output_fuzzer`](#script_output_fuzzer), with
/// and additional randomized wrapper for output reference.
pub fn authentic_script_input_fuzzer(
  m_datum: Option<Datum>,
) -> Fuzzer<(ByteArray, Input)> {
  let output_reference <- and_then(output_reference_fuzzer())
  let (script_hash, output) <- and_then(authentic_script_output_fuzzer(m_datum))
  fuzz.constant((script_hash, Input { output_reference, output }))
}

/// Simple (non-script) outputs fuzzer.
pub fn user_outputs_fuzzer() -> Fuzzer<List<Output>> {
  fuzz.list_at_least(user_output_fuzzer(), 1)
}

/// Simple (non-script) inputs fuzzer.
pub fn user_inputs_fuzzer() -> Fuzzer<List<Input>> {
  fuzz.list_at_least(user_input_fuzzer(), 1)
}


/// Fuzzer for a sorted list of user/wallet inputs, with the addition of one
/// authentic script input.
pub fn inputs_with_an_authentic_script_input_fuzzer(
  m_datum: Option<Datum>,
) -> Fuzzer<(ByteArray, Input, List<Input>)> {
  let wallet_inputs <- and_then(user_inputs_fuzzer())
  let (spend_script_hash, script_input) <-
    and_then(utils.authentic_script_input_fuzzer(m_datum))
  (
    spend_script_hash,
    script_input,
    [script_input, ..wallet_inputs]
      |> list.sort(
          fn(i0: Input, i1: Input) {
            output_reference.compare(i0.output_reference, i1.output_reference)
          },
        ),
  )
}
