use aiken/builtin
use aiken/collection/list
use aiken/crypto.{blake2b_224}
use aiken/fuzz
use aiken_design_patterns/tx_level_minter.{validate_mint, validate_mint_minimal}
use aiken_design_patterns/utils as utils
use cardano/assets.{PolicyId, Value}
use cardano/transaction.{Mint}

fn grab_a_policy_from_mint(m: Value) -> Fuzzer<(PolicyId, Value)> {
  let policies = m |> assets.policies
  fuzz.map(
    fuzz.int_between(0, list.length(policies) - 1),
    fn(i) {
      trace list.length(policies)
      trace i
      expect Some(p) = list.at(policies, i)
      (p, m)
    },
  )
}

test success__validate_mint(
  random_policy_and_mint via fuzz.and_then(
    utils.mint_fuzzer(),
    grab_a_policy_from_mint,
  ),
) {
  let (random_policy, random_mint) = random_policy_and_mint
  let redeemers = [Pair(Mint(random_policy), builtin.i_data(0))]
  let
    _r_data,
    _tn_qty_dict,
  <- validate_mint(random_policy, random_mint, redeemers, 0)
  True
}

test fail__validate_mint__bad_policy(
  random_policy_and_mint via fuzz.and_then(
    utils.mint_fuzzer(),
    grab_a_policy_from_mint,
  ),
) fail {
  let (random_policy, random_mint) = random_policy_and_mint
  let redeemers = [Pair(Mint(random_policy), builtin.i_data(0))]
  // Hashing to get a different policy
  let hashed_policy = blake2b_224(random_policy)
  let
    _r_data,
    _tn_qty_dict,
  <- validate_mint(hashed_policy, random_mint, redeemers, 0)
  True
}

test success__validate_mint_minimal(script_hash via fuzz.bytearray_fixed(28)) {
  let mint = assets.from_asset(script_hash, #"", 1)
  validate_mint_minimal(script_hash, mint)
}

test fail__validate_mint_minimal__bad_policy(
  script_hash via fuzz.bytearray_fixed(28),
) fail {
  let mint = assets.from_asset(script_hash, #"", 1)
  // Hashing to get a different script hash
  let expected_mint_script_hash = blake2b_224(script_hash)
  validate_mint_minimal(expected_mint_script_hash, mint)
}
