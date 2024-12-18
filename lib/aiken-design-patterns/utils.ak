//// @hidden

use aiken/builtin
use aiken/collection/list.{foldl}
use aiken/crypto.{ScriptHash}
use aiken/fuzz.{and_then}
use cardano/address.{Address, Inline, Script, VerificationKey}
use cardano/assets.{AssetName, PolicyId, Value}
use cardano/transaction.{Datum, Input, NoDatum, Output, OutputReference}
use cardano/transaction/output_reference as output_reference

pub fn sort_inputs(inputs: List<Input>) -> List<Input> {
  inputs
    |> list.sort(
        fn(i0: Input, i1: Input) {
          output_reference.compare(i0.output_reference, i1.output_reference)
        },
      )
}

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

  expect [_, (in_sym, in_name, in_quantity)] = in_val |> assets.flatten

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

pub fn sum_of_squares(xs: List<Int>) -> Int {
  xs |> foldl(0, fn(x, acc) { acc + x * x })
}

/// Given a list of inputs, this function returns the index of the first inputs
/// which its address has a `Script` payment part.
pub fn find_index_of_first_script_input(inputs: List<Input>) -> Int {
  expect Some(input_index) =
    list.indexed_foldr(
      inputs,
      None,
      fn(i, input, m_i) {
        when m_i is {
          Some(_) -> m_i
          None ->
            when input.output.address.payment_credential is {
              Script(_) -> Some(i)
              _ -> None
            }
        }
      },
    )
  input_index
}

/// A fuzzer for `Value` with a single asset. Unsafely expects 28 bytes long
/// policy ID to be provided.
pub fn single_specific_asset_value_fuzzer(policyId: ByteArray) -> Fuzzer<Value> {
  let token_name <- and_then(fuzz.bytearray_between(0, 32))
  let quantity <- and_then(fuzz.int_at_least(1))
  fuzz.constant(assets.from_asset(policyId, token_name, quantity))
}

/// A `Value` fuzzer with a single asset. Randomly generates the policy ID.
pub fn single_asset_value_fuzzer() -> Fuzzer<Value> {
  let policyId <- and_then(fuzz.bytearray_fixed(28))
  single_specific_asset_value_fuzzer(policyId)
}

/// A `Value` fuzzer without any lovelaces.
pub fn mint_fuzzer() -> Fuzzer<Value> {
  let other_assets_values <-
    and_then(fuzz.list_between(single_asset_value_fuzzer(), 1, 10))
  fuzz.constant(
    list.foldl(
      other_assets_values,
      assets.zero,
      fn(v, acc) { assets.merge(v, acc) },
    ),
  )
}

/// A `Value` fuzzer, guaranteed to include some amount of ADA (minimum must be
/// specified).
pub fn value_fuzzer(min_lovelaces: Int) -> Fuzzer<Value> {
  let lovelace_count <- and_then(fuzz.int_at_least(min_lovelaces))
  let lovelace_value = assets.from_lovelace(lovelace_count)
  let other_assets_values <-
    and_then(fuzz.list_at_most(single_asset_value_fuzzer(), 10))
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

/// Given a script hash and datum, this fuzzer generates a UTxO at an address
/// which its payment part is the same as the given script hash.
pub fn specific_script_output_fuzzer(
  script_hash: ScriptHash,
  datum: Datum,
) -> Fuzzer<Output> {
  let v <- and_then(value_fuzzer(2_000_000))
  fuzz.constant(
    Output {
      address: Address {
        payment_credential: Script(script_hash),
        stake_credential: None,
      },
      value: v,
      datum,
      reference_script: None,
    },
  )
}

/// Returns a tuple where its first element is the random script hash (payment
/// part of the UTxO's address). UTxO value is also random, with 2 ADA.
pub fn script_output_fuzzer(datum: Datum) -> Fuzzer<(ByteArray, Output)> {
  let script_hash <- and_then(fuzz.bytearray_fixed(28))
  let utxo <- and_then(specific_script_output_fuzzer(script_hash, datum))
  fuzz.constant((script_hash, utxo))
}

/// UTxO fuzzer, where the value is composed of 2 ADA and a beacon NFT, such
/// that its policy ID is equal to the script credential of the payment part of
/// UTxO's address. This script hash is also returned.
pub fn authentic_script_output_fuzzer(
  datum: Datum,
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
        datum,
        reference_script: None,
      },
    ),
  )
}

/// Similar to [`specific_script_output_fuzzer`](#specific_script_output_fuzzer),
/// with an additional randomized wrapper for output reference.
pub fn specific_script_input_fuzzer(
  script_hash: ScriptHash,
  datum: Datum,
) -> Fuzzer<Input> {
  let output_reference <- and_then(output_reference_fuzzer())
  let output <- and_then(specific_script_output_fuzzer(script_hash, datum))
  fuzz.constant(Input { output_reference, output })
}

/// Similar to [`script_output_fuzzer`](#script_output_fuzzer), with an
/// additional randomized wrapper for output reference.
pub fn script_input_fuzzer(datum: Datum) -> Fuzzer<(ByteArray, Input)> {
  let output_reference <- and_then(output_reference_fuzzer())
  let (script_hash, output) <- and_then(script_output_fuzzer(datum))
  fuzz.constant((script_hash, Input { output_reference, output }))
}

/// Similar to [`authentic_script_output_fuzzer`](#script_output_fuzzer), with
/// and additional randomized wrapper for output reference.
pub fn authentic_script_input_fuzzer(datum: Datum) -> Fuzzer<(ByteArray, Input)> {
  let output_reference <- and_then(output_reference_fuzzer())
  let (script_hash, output) <- and_then(authentic_script_output_fuzzer(datum))
  fuzz.constant((script_hash, Input { output_reference, output }))
}

/// Simple (non-script) outputs fuzzer.
pub fn user_outputs_fuzzer() -> Fuzzer<List<Output>> {
  fuzz.list_between(user_output_fuzzer(), 1, 10)
}

/// Simple (non-script) inputs fuzzer.
pub fn user_inputs_fuzzer() -> Fuzzer<List<Input>> {
  fuzz.list_between(user_input_fuzzer(), 1, 10)
}

/// Fuzzer for a sorted list of user/wallet inputs, with the addition of one
/// authentic script input.
pub fn inputs_with_an_authentic_script_input_fuzzer(
  datum: Datum,
) -> Fuzzer<(ByteArray, Input, List<Input>)> {
  let wallet_inputs <- and_then(user_inputs_fuzzer())
  let (spend_script_hash, script_input) <-
    and_then(authentic_script_input_fuzzer(datum))
  fuzz.constant(
    (
      spend_script_hash,
      script_input,
      [script_input, ..wallet_inputs] |> sort_inputs,
    ),
  )
}
