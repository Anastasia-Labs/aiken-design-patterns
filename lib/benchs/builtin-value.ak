//// Compare Assets, cached token dictionaries, and builtin Value operations.
//// Const fixtures are supplied as runtime sampler arguments. Fixture creation
//// is excluded; the measured operations cannot be constant-folded.
//// Every native operation includes conversion from the input Assets.
////
//// The pop fixtures contain one policy and no remaining assets. They measure
//// token-removal operations; the complete policy checks are covered separately
//// in benchs/linked_list_value.
////
//// Samplers have fixed asset counts. Run with --max-size 1; the compiler's
//// projected maximum size does not apply to these constant-size samplers.

use aiken/collection/dict
use aiken/collection/list
use aiken/fuzz
use aiken_design_patterns/utils
use cardano/assets.{AssetName, Assets, ada_policy_id}
use cardano/value

fn sample(x: Assets) -> Sampler<Assets> {
  fn(_) { fuzz.constant(x) }
}

const policy = #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const singleton =
  assets.from_lovelace(2_000_000)
    |> assets.add(policy, "node", 1)

fn singleton_assets(v: Assets) -> Bool {
  let lovelace, name <- utils.get_lovelace_and_single_nft_name(v, policy)
  lovelace == 2_000_000 && name == "node"
}

fn singleton_value(v: Assets) -> Bool {
  let native = value.from_assets(v)
  expect [Pair(ada, [Pair(_, lovelace)]),
        Pair(nft_policy, [Pair(name, qty)])] = value.to_pairs(native)
  expect ada == ada_policy_id
  expect nft_policy == policy
  expect qty == 1
  lovelace == 2_000_000 && name == "node"
}

bench singleton_assets_case(v via sample(singleton)) {
  singleton_assets(v)
}

bench singleton_value_case(v via sample(singleton)) {
  singleton_value(v)
}

fn pop_assets(v: Assets, names: List<AssetName>) -> Bool {
  let initial = assets.tokens(v, policy)
  let rest = list.foldl(
    names,
    initial,
    fn(name, pending) {
      let (qty, remaining) = dict.expect_pop(pending, name)
      expect qty == 1
      remaining
    },
  )
  dict.is_empty(rest)
}

fn pop_value(v: Assets, names: List<AssetName>) -> Bool {
  let initial = value.from_assets(v)
  let rest = list.foldl(
    names,
    initial,
    fn(name, pending) {
      expect value.quantity_of(pending, policy, name) == 1
      value.delete(pending, policy, name)
    },
  )
  value.is_zero(rest)
}

fn lookup_assets(v: Assets, names: List<AssetName>) -> Bool {
  list.all(names, fn(name) { assets.quantity_of(v, policy, name) == 1 })
}

fn lookup_tokens(v: Assets, names: List<AssetName>) -> Bool {
  let tokens = assets.tokens(v, policy)
  list.all(names, fn(name) { dict.get(tokens, name) == Some(1) })
}

fn lookup_value(v: Assets, names: List<AssetName>) -> Bool {
  let native = value.from_assets(v)
  list.all(names, fn(name) { value.quantity_of(native, policy, name) == 1 })
}

const mint_1 = assets.from_asset_list([Pair(policy, [Pair(#"00", 1)])])

const keys_ascending_1 = [#"00"]

bench pop_assets_ascending_1(v via sample(mint_1)) {
  pop_assets(v, keys_ascending_1)
}

bench pop_value_ascending_1(v via sample(mint_1)) {
  pop_value(v, keys_ascending_1)
}

const keys_descending_1 = [#"00"]

bench pop_assets_descending_1(v via sample(mint_1)) {
  pop_assets(v, keys_descending_1)
}

bench pop_value_descending_1(v via sample(mint_1)) {
  pop_value(v, keys_descending_1)
}

bench lookup_assets_1(v via sample(mint_1)) {
  lookup_assets(v, keys_ascending_1)
}

bench lookup_tokens_1(v via sample(mint_1)) {
  lookup_tokens(v, keys_ascending_1)
}

bench lookup_value_1(v via sample(mint_1)) {
  lookup_value(v, keys_ascending_1)
}

const mint_4 =
  assets.from_asset_list(
    [
      Pair(
        policy,
        [Pair(#"00", 1), Pair(#"01", 1), Pair(#"02", 1), Pair(#"03", 1)],
      ),
    ],
  )

const keys_ascending_4 = [#"00", #"01", #"02", #"03"]

bench pop_assets_ascending_4(v via sample(mint_4)) {
  pop_assets(v, keys_ascending_4)
}

bench pop_value_ascending_4(v via sample(mint_4)) {
  pop_value(v, keys_ascending_4)
}

const keys_descending_4 = [#"03", #"02", #"01", #"00"]

bench pop_assets_descending_4(v via sample(mint_4)) {
  pop_assets(v, keys_descending_4)
}

bench pop_value_descending_4(v via sample(mint_4)) {
  pop_value(v, keys_descending_4)
}

bench lookup_assets_4(v via sample(mint_4)) {
  lookup_assets(v, keys_ascending_4)
}

bench lookup_tokens_4(v via sample(mint_4)) {
  lookup_tokens(v, keys_ascending_4)
}

bench lookup_value_4(v via sample(mint_4)) {
  lookup_value(v, keys_ascending_4)
}

const mint_16 =
  assets.from_asset_list(
    [
      Pair(
        policy,
        [
          Pair(#"00", 1), Pair(#"01", 1), Pair(#"02", 1), Pair(#"03", 1),
          Pair(#"04", 1), Pair(#"05", 1), Pair(#"06", 1), Pair(#"07", 1),
          Pair(#"08", 1), Pair(#"09", 1), Pair(#"0a", 1), Pair(#"0b", 1),
          Pair(#"0c", 1), Pair(#"0d", 1), Pair(#"0e", 1), Pair(#"0f", 1),
        ],
      ),
    ],
  )

const keys_ascending_16 =
  [
    #"00", #"01", #"02", #"03", #"04", #"05", #"06", #"07", #"08", #"09", #"0a",
    #"0b", #"0c", #"0d", #"0e", #"0f",
  ]

bench pop_assets_ascending_16(v via sample(mint_16)) {
  pop_assets(v, keys_ascending_16)
}

bench pop_value_ascending_16(v via sample(mint_16)) {
  pop_value(v, keys_ascending_16)
}

const keys_descending_16 =
  [
    #"0f", #"0e", #"0d", #"0c", #"0b", #"0a", #"09", #"08", #"07", #"06", #"05",
    #"04", #"03", #"02", #"01", #"00",
  ]

bench pop_assets_descending_16(v via sample(mint_16)) {
  pop_assets(v, keys_descending_16)
}

bench pop_value_descending_16(v via sample(mint_16)) {
  pop_value(v, keys_descending_16)
}

bench lookup_assets_16(v via sample(mint_16)) {
  lookup_assets(v, keys_ascending_16)
}

bench lookup_tokens_16(v via sample(mint_16)) {
  lookup_tokens(v, keys_ascending_16)
}

bench lookup_value_16(v via sample(mint_16)) {
  lookup_value(v, keys_ascending_16)
}

const mint_64 =
  assets.from_asset_list(
    [
      Pair(
        policy,
        [
          Pair(#"00", 1), Pair(#"01", 1), Pair(#"02", 1), Pair(#"03", 1),
          Pair(#"04", 1), Pair(#"05", 1), Pair(#"06", 1), Pair(#"07", 1),
          Pair(#"08", 1), Pair(#"09", 1), Pair(#"0a", 1), Pair(#"0b", 1),
          Pair(#"0c", 1), Pair(#"0d", 1), Pair(#"0e", 1), Pair(#"0f", 1),
          Pair(#"10", 1), Pair(#"11", 1), Pair(#"12", 1), Pair(#"13", 1),
          Pair(#"14", 1), Pair(#"15", 1), Pair(#"16", 1), Pair(#"17", 1),
          Pair(#"18", 1), Pair(#"19", 1), Pair(#"1a", 1), Pair(#"1b", 1),
          Pair(#"1c", 1), Pair(#"1d", 1), Pair(#"1e", 1), Pair(#"1f", 1),
          Pair(#"20", 1), Pair(#"21", 1), Pair(#"22", 1), Pair(#"23", 1),
          Pair(#"24", 1), Pair(#"25", 1), Pair(#"26", 1), Pair(#"27", 1),
          Pair(#"28", 1), Pair(#"29", 1), Pair(#"2a", 1), Pair(#"2b", 1),
          Pair(#"2c", 1), Pair(#"2d", 1), Pair(#"2e", 1), Pair(#"2f", 1),
          Pair(#"30", 1), Pair(#"31", 1), Pair(#"32", 1), Pair(#"33", 1),
          Pair(#"34", 1), Pair(#"35", 1), Pair(#"36", 1), Pair(#"37", 1),
          Pair(#"38", 1), Pair(#"39", 1), Pair(#"3a", 1), Pair(#"3b", 1),
          Pair(#"3c", 1), Pair(#"3d", 1), Pair(#"3e", 1), Pair(#"3f", 1),
        ],
      ),
    ],
  )

const keys_ascending_64 =
  [
    #"00", #"01", #"02", #"03", #"04", #"05", #"06", #"07", #"08", #"09", #"0a",
    #"0b", #"0c", #"0d", #"0e", #"0f", #"10", #"11", #"12", #"13", #"14", #"15",
    #"16", #"17", #"18", #"19", #"1a", #"1b", #"1c", #"1d", #"1e", #"1f", #"20",
    #"21", #"22", #"23", #"24", #"25", #"26", #"27", #"28", #"29", #"2a", #"2b",
    #"2c", #"2d", #"2e", #"2f", #"30", #"31", #"32", #"33", #"34", #"35", #"36",
    #"37", #"38", #"39", #"3a", #"3b", #"3c", #"3d", #"3e", #"3f",
  ]

bench pop_assets_ascending_64(v via sample(mint_64)) {
  pop_assets(v, keys_ascending_64)
}

bench pop_value_ascending_64(v via sample(mint_64)) {
  pop_value(v, keys_ascending_64)
}

const keys_descending_64 =
  [
    #"3f", #"3e", #"3d", #"3c", #"3b", #"3a", #"39", #"38", #"37", #"36", #"35",
    #"34", #"33", #"32", #"31", #"30", #"2f", #"2e", #"2d", #"2c", #"2b", #"2a",
    #"29", #"28", #"27", #"26", #"25", #"24", #"23", #"22", #"21", #"20", #"1f",
    #"1e", #"1d", #"1c", #"1b", #"1a", #"19", #"18", #"17", #"16", #"15", #"14",
    #"13", #"12", #"11", #"10", #"0f", #"0e", #"0d", #"0c", #"0b", #"0a", #"09",
    #"08", #"07", #"06", #"05", #"04", #"03", #"02", #"01", #"00",
  ]

bench pop_assets_descending_64(v via sample(mint_64)) {
  pop_assets(v, keys_descending_64)
}

bench pop_value_descending_64(v via sample(mint_64)) {
  pop_value(v, keys_descending_64)
}

bench lookup_assets_64(v via sample(mint_64)) {
  lookup_assets(v, keys_ascending_64)
}

bench lookup_tokens_64(v via sample(mint_64)) {
  lookup_tokens(v, keys_ascending_64)
}

bench lookup_value_64(v via sample(mint_64)) {
  lookup_value(v, keys_ascending_64)
}
