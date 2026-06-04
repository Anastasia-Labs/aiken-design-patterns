//// @hidden

use aiken/builtin
use aiken/collection/dict
use aiken/collection/list.{foldl}
use aiken/crypto.{ScriptHash, blake2b_224}
use aiken/fuzz.{and_then}
use aiken_scott_utils/types.{Scott3}
use cardano/address.{Address, Inline, Script}
use cardano/assets.{AssetName, Lovelace, PolicyId, Value, ada_policy_id}
use cardano/fuzz as cardano_fuzz
use cardano/transaction.{
  Datum, InlineDatum, Input, NoDatum, Output, OutputReference, Redeemer,
  ScriptPurpose, Withdraw,
}
use cardano/transaction/output_reference as output_reference

pub fn get_withdraw_scripts_redeemer_at(
  withdraw_script_hash: ScriptHash,
  redeemers: Pairs<ScriptPurpose, Redeemer>,
  redeemer_index: Int,
) -> Data {
  expect Some(rdmr_pair) = redeemers |> list.at(redeemer_index)
  expect Withdraw(Script(withdraw_script_hash)) == rdmr_pair.1st
  rdmr_pair.2nd
}

pub fn utxo_is_spent(inputs: List<Input>, utxo_out_ref: OutputReference) -> Bool {
  list.any(inputs, fn(input) { input.output_reference == utxo_out_ref })
}

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

pub fn get_single_asset_from_value_apart_from_ada(
  v: Value,
  return: Scott3<PolicyId, AssetName, Int, result>,
) -> result {
  expect [Pair(sym, tn_qty_pairs)] =
    v
      |> assets.to_dict
      |> dict.delete(assets.ada_policy_id)
      |> dict.to_pairs
  expect [Pair(tn, qty)] = tn_qty_pairs |> dict.to_pairs
  return(sym, tn, qty)
}

test success__get_single_asset_from_value_apart_from_ada(
  nft: Value via single_asset_value_fuzzer(),
) {
  let with_lovelace = assets.merge(nft, assets.from_lovelace(2_000_000))
  let
    policy_id,
    asset_name,
    quantity,
  <- get_single_asset_from_value_apart_from_ada(with_lovelace)
  assets.from_asset(policy_id, asset_name, quantity) == nft
}

test fail__get_single_asset_from_value_apart_from_ada__two_nfts(
  nfts: (Value, Value) via fuzz.both(
    single_asset_value_fuzzer(),
    single_asset_value_fuzzer(),
  ),
) fail {
  let (nft0, nft1) = nfts
  let with_lovelace =
    assets.from_lovelace(2_000_000)
      |> assets.merge(nft0)
      |> assets.merge(nft1)
  let
    _policy_id,
    _asset_name,
    _quantity,
  <- get_single_asset_from_value_apart_from_ada(with_lovelace)
  True
}

pub fn get_lovelace_and_single_nft_name(
  value: Value,
  nft_policy_id: PolicyId,
  return: fn(Lovelace, AssetName) -> result,
) -> result {
  let (ada_tn_qty_dict, rest_of_policies) =
    value
      |> assets.to_dict
      |> dict.expect_pop(ada_policy_id)
  let lovelace_name_qty_pair =
    ada_tn_qty_dict
      |> dict.to_pairs
      |> builtin.head_list
  expect [Pair(nft_policy, nft_name_qty_dict)] =
    rest_of_policies
      |> dict.to_pairs
  expect [Pair(nft_name, nft_qty)] = nft_name_qty_dict |> dict.to_pairs
  expect nft_policy == nft_policy_id
  expect nft_qty == 1
  return(lovelace_name_qty_pair.2nd, nft_name)
}

const test_lovelace = 2_000_000

const test_other_224 = blake2b_224("other_policy")

const test_nft_name = "node_nft"

const test_other_nft_name = "other_nft"

test success__get_lovelace_and_single_nft_name() {
  let value =
    assets.from_lovelace(test_lovelace)
      |> assets.merge(assets.from_asset(test_224_01, test_nft_name, 1))

  let
    lovelace_count,
    nft_name,
  <- get_lovelace_and_single_nft_name(value, test_224_01)

  and {
    lovelace_count == test_lovelace,
    nft_name == test_nft_name,
  }
}

test fail__get_lovelace_and_single_nft_name__nft_quantity_not_one() fail {
  let value =
    assets.from_lovelace(test_lovelace)
      |> assets.merge(assets.from_asset(test_224_01, test_nft_name, 2))

  let
    _lovelace_count,
    _nft_name,
  <- get_lovelace_and_single_nft_name(value, test_224_01)

  True
}

test fail__get_lovelace_and_single_nft_name__more_assets_same_policy() fail {
  let value =
    assets.from_lovelace(test_lovelace)
      |> assets.merge(assets.from_asset(test_224_01, test_nft_name, 1))
      |> assets.merge(assets.from_asset(test_224_01, test_other_nft_name, 1))

  let
    _lovelace_count,
    _nft_name,
  <- get_lovelace_and_single_nft_name(value, test_224_01)

  True
}

test fail__get_lovelace_and_single_nft_name__more_assets_other_policy() fail {
  let value =
    assets.from_lovelace(test_lovelace)
      |> assets.merge(assets.from_asset(test_224_01, test_nft_name, 1))
      |> assets.merge(assets.from_asset(test_other_224, test_other_nft_name, 1))

  let
    _lovelace_count,
    _nft_name,
  <- get_lovelace_and_single_nft_name(value, test_224_01)

  True
}

test fail__get_lovelace_and_single_nft_name__wrong_policy() fail {
  let value =
    assets.from_lovelace(test_lovelace)
      |> assets.merge(assets.from_asset(test_other_224, test_nft_name, 1))

  let
    _lovelace_count,
    _nft_name,
  <- get_lovelace_and_single_nft_name(value, test_224_01)

  True
}

test fail__get_lovelace_and_single_nft_name__only_lovelace() fail {
  let
    _lovelace_count,
    _nft_name,
  <-
    get_lovelace_and_single_nft_name(
      assets.from_lovelace(test_lovelace),
      test_224_01,
    )

  True
}

test fail__get_lovelace_and_single_nft_name__missing_lovelace() fail {
  let
    _lovelace_count,
    _nft_name,
  <-
    get_lovelace_and_single_nft_name(
      assets.from_asset(test_224_01, test_nft_name, 1),
      test_224_01,
    )

  True
}

pub fn authentic_input_is_reproduced_unchanged(
  auth_symbol: PolicyId,
  optional_auth_name: Option<AssetName>,
  in_utxo: Output,
  out_utxo: Output,
) -> Bool {
  let Output {
    value: in_val,
    datum: in_dat,
    address: in_addr,
    reference_script: in_ref_script,
  } = in_utxo
  let Output {
    value: out_val,
    datum: out_dat,
    address: out_addr,
    reference_script: out_ref_script,
  } = out_utxo

  let
    in_sym,
    in_name,
    in_quantity,
  <- get_single_asset_from_value_apart_from_ada(in_val)

  let name_is_authentic =
    when optional_auth_name is {
      Some(auth_name) -> in_name == auth_name
      None -> True
    }
  and {
    in_val == out_val,
    in_dat == out_dat,
    in_addr == out_addr,
    in_ref_script == out_ref_script,
    in_sym == auth_symbol,
    name_is_authentic,
    in_quantity == 1,
  }
}

test success__authentic_input_is_reproduced_unchanged() {
  authentic_input_is_reproduced_unchanged(
    test_224_01,
    None,
    test_utxo_01,
    test_utxo_01,
  )
}

test fail__authentic_input_is_reproduced_unchanged__different_nft() fail {
  authentic_input_is_reproduced_unchanged(
    test_224_01,
    None,
    test_utxo_01,
    test_utxo_02,
  )
}

test fail__authentic_input_is_reproduced_unchanged__different_stake_credential() fail {
  let changed_stake_output =
    Output {
      ..test_utxo_01,
      address: Address {
        payment_credential: Script(test_224_01),
        stake_credential: Some(Inline(Script(test_224_02))),
      },
    }
  authentic_input_is_reproduced_unchanged(
    test_224_01,
    None,
    test_utxo_01,
    changed_stake_output,
  )
}

test perf__authentic_input_helper__single_asset_from_value_apart_from_ada() {
  let in_val = test_utxo_01.value
  let
    in_sym,
    in_name,
    in_quantity,
  <- get_single_asset_from_value_apart_from_ada(in_val)
  and {
    in_sym == test_224_01,
    in_name == #"01",
    in_quantity == 1,
  }
}

test perf__authentic_input_helper__lovelace_and_single_nft_name() {
  let in_val = test_utxo_01.value
  let
    _lovelace_count,
    in_name,
  <- get_lovelace_and_single_nft_name(in_val, test_224_01)
  in_name == #"01"
}

pub fn sum_of_squares(xs: List<Int>) -> Int {
  xs |> foldl(0, fn(x, acc) { acc + x * x })
}

test success__sum_of_squares() {
  sum_of_squares([100, 20, 3, 4, 5]) == 10450
}

test fail__sum_of_squares() fail {
  sum_of_squares([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]) == 1
}

test success__sum_of_squares__singleton(x: Int via fuzz.int()) {
  sum_of_squares([x]) == x * x
}

test success__sum_of_squares__always_non_negative(
  xs: List<Int> via fuzz.list(fuzz.int()),
) {
  let result = sum_of_squares(xs)
  result >= 0
}

const test_list_max_count = 4

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

const test_224_01 = blake2b_224(#"01")

const test_224_02 = blake2b_224(#"02")

const test_utxo_01 =
  Output {
    address: Address {
      payment_credential: Script(test_224_01),
      stake_credential: None,
    },
    value: assets.add(assets.from_lovelace(2_000_000), test_224_01, #"01", 1),
    datum: InlineDatum(1),
    reference_script: None,
  }

const test_utxo_02 =
  Output {
    address: Address {
      payment_credential: Script(test_224_02),
      stake_credential: None,
    },
    value: assets.add(assets.from_lovelace(2_000_000), test_224_02, #"02", 1),
    datum: InlineDatum(1),
    reference_script: None,
  }

/// A fuzzer for `Value` with a single asset. Unsafely expects 28 bytes long
/// policy ID to be provided.
pub fn single_specific_asset_value_fuzzer(policy_id: ByteArray) -> Fuzzer<Value> {
  let token_name <- and_then(cardano_fuzz.asset_name())
  let quantity <- and_then(fuzz.int_at_least(1))
  fuzz.constant(assets.from_asset(policy_id, token_name, quantity))
}

/// A `Value` fuzzer with a single asset. Randomly generates the policy ID.
pub fn single_asset_value_fuzzer() -> Fuzzer<Value> {
  let policy_id <- and_then(cardano_fuzz.policy_id())
  single_specific_asset_value_fuzzer(policy_id)
}

/// A `Value` fuzzer without any lovelaces.
pub fn mint_fuzzer() -> Fuzzer<Value> {
  let other_assets_values <-
    and_then(
      fuzz.list_between(single_asset_value_fuzzer(), 1, test_list_max_count),
    )
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
    and_then(
      fuzz.list_at_most(single_asset_value_fuzzer(), test_list_max_count),
    )
  fuzz.constant(
    list.foldl(
      other_assets_values,
      lovelace_value,
      fn(v, acc) { assets.merge(v, acc) },
    ),
  )
}

/// Simple wallet UTxO fuzzer, with a random number of tokens/NFTs.
pub fn user_output_fuzzer() -> Fuzzer<Output> {
  cardano_fuzz.output_with(
    cardano_fuzz.address_with(
      cardano_fuzz.verification_key(),
      fuzz.map(
        cardano_fuzz.verification_key(),
        fn(stake_credential) { Some(Inline(stake_credential)) },
      ),
    ),
    value_fuzzer(2_000_000),
    fuzz.constant(NoDatum),
    fuzz.constant(None),
  )
}

/// Simple wallet UTxO fuzzer, with a random reference output and a random
/// number of tokens/NFTs.
pub fn user_input_fuzzer() -> Fuzzer<Input> {
  cardano_fuzz.input_with(cardano_fuzz.output_reference(), user_output_fuzzer())
}

/// Given a script hash and datum, this fuzzer generates a UTxO at an address
/// which its payment part is the same as the given script hash.
pub fn specific_script_output_fuzzer(
  script_hash: ScriptHash,
  datum: Datum,
) -> Fuzzer<Output> {
  cardano_fuzz.output_with(
    cardano_fuzz.address_with(
      cardano_fuzz.script_with(fuzz.constant(script_hash)),
      fuzz.constant(None),
    ),
    value_fuzzer(2_000_000),
    fuzz.constant(datum),
    fuzz.constant(None),
  )
}

/// Returns a tuple where its first element is the random script hash (payment
/// part of the UTxO's address). UTxO value is also random, with 2 ADA.
pub fn script_output_fuzzer(datum: Datum) -> Fuzzer<(ByteArray, Output)> {
  let script_hash <- and_then(cardano_fuzz.script_hash())
  let utxo <- and_then(specific_script_output_fuzzer(script_hash, datum))
  fuzz.constant((script_hash, utxo))
}

/// UTxO fuzzer, where the value is composed of 2 ADA and a beacon NFT, such
/// that its policy ID is equal to the script credential of the payment part of
/// UTxO's address. This script hash is also returned.
pub fn authentic_script_output_fuzzer(
  datum: Datum,
) -> Fuzzer<(ByteArray, Output)> {
  let script_hash <- and_then(cardano_fuzz.script_hash())
  let tn <- and_then(cardano_fuzz.asset_name())
  let lovelace_value = assets.from_lovelace(2_000_000)
  let beacon = assets.from_asset(script_hash, tn, 1)
  let v = assets.merge(lovelace_value, beacon)
  let output <-
    and_then(
      cardano_fuzz.output_with(
        cardano_fuzz.address_with(
          cardano_fuzz.script_with(fuzz.constant(script_hash)),
          fuzz.constant(None),
        ),
        fuzz.constant(v),
        fuzz.constant(datum),
        fuzz.constant(None),
      ),
    )
  fuzz.constant((script_hash, output))
}

pub fn authentic_script_output_with_given_asset_name_fuzzer(
  asset_name: AssetName,
  datum: Datum,
) -> Fuzzer<(ByteArray, Output)> {
  let script_hash <- and_then(cardano_fuzz.script_hash())
  let lovelace_value = assets.from_lovelace(2_000_000)
  let beacon = assets.from_asset(script_hash, asset_name, 1)
  let v = assets.merge(lovelace_value, beacon)
  let output <-
    and_then(
      cardano_fuzz.output_with(
        cardano_fuzz.address_with(
          cardano_fuzz.script_with(fuzz.constant(script_hash)),
          fuzz.constant(None),
        ),
        fuzz.constant(v),
        fuzz.constant(datum),
        fuzz.constant(None),
      ),
    )
  fuzz.constant((script_hash, output))
}

/// Similar to [`specific_script_output_fuzzer`](#specific_script_output_fuzzer),
/// with an additional randomized wrapper for output reference.
pub fn specific_script_input_fuzzer(
  script_hash: ScriptHash,
  datum: Datum,
) -> Fuzzer<Input> {
  cardano_fuzz.input_with(
    cardano_fuzz.output_reference(),
    specific_script_output_fuzzer(script_hash, datum),
  )
}

/// Similar to [`script_output_fuzzer`](#script_output_fuzzer), with an
/// additional randomized wrapper for output reference.
pub fn script_input_fuzzer(datum: Datum) -> Fuzzer<(ByteArray, Input)> {
  let (script_hash, output) <- and_then(script_output_fuzzer(datum))
  let input <-
    and_then(
      cardano_fuzz.input_with(
        cardano_fuzz.output_reference(),
        fuzz.constant(output),
      ),
    )
  fuzz.constant((script_hash, input))
}

/// Similar to
/// [`authentic_script_output_fuzzer`](#authentic_script_output_fuzzer), with an
/// additional randomized wrapper for output reference.
pub fn authentic_script_input_fuzzer(datum: Datum) -> Fuzzer<(ByteArray, Input)> {
  let (script_hash, output) <- and_then(authentic_script_output_fuzzer(datum))
  let input <-
    and_then(
      cardano_fuzz.input_with(
        cardano_fuzz.output_reference(),
        fuzz.constant(output),
      ),
    )
  fuzz.constant((script_hash, input))
}

/// Simple (non-script) outputs fuzzer.
pub fn user_outputs_fuzzer() -> Fuzzer<List<Output>> {
  fuzz.list_between(user_output_fuzzer(), 1, test_list_max_count)
}

/// Simple (non-script) inputs fuzzer.
pub fn user_inputs_fuzzer() -> Fuzzer<List<Input>> {
  fuzz.list_between(user_input_fuzzer(), 1, test_list_max_count)
}

fn input_without_list_policy_fuzzer(list_nft_policy: PolicyId) -> Fuzzer<Input> {
  fuzz.such_that(
    cardano_fuzz.input(),
    fn(input) {
      and {
        input.output.value
          |> assets.tokens(list_nft_policy)
          |> dict.is_empty(),
        input.output.address.payment_credential != Script(list_nft_policy),
      }
    },
  )
}

pub fn inputs_with_expected_inputs_fuzzer(
  list_nft_policy: PolicyId,
  expected_inputs: List<Input>,
) -> Fuzzer<List<Input>> {
  let inputs_before <-
    and_then(
      fuzz.list_between(
        input_without_list_policy_fuzzer(list_nft_policy),
        0,
        10,
      ),
    )
  let inputs_after <-
    and_then(
      fuzz.list_between(
        input_without_list_policy_fuzzer(list_nft_policy),
        0,
        10,
      ),
    )
  fuzz.constant(
    list.concat(inputs_before, list.concat(expected_inputs, inputs_after)),
  )
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
