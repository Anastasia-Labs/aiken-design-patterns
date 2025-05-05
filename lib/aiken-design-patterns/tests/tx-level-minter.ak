use aiken/builtin
use aiken/collection/list
use aiken/crypto.{blake2b_224}
use aiken/fuzz
use aiken_design_patterns/tx_level_minter.{spend, spend_minimal}
use aiken_design_patterns/utils as utils
use cardano/assets.{PolicyId, Value}
use cardano/transaction.{Mint, Transaction, placeholder}

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

test success_spend(
  random_policy_and_mint via fuzz.and_then(
    utils.mint_fuzzer(),
    grab_a_policy_from_mint,
  ),
) {
  let (random_policy, random_mint) = random_policy_and_mint
  let tx =
    Transaction {
      ..placeholder,
      mint: random_mint,
      redeemers: [Pair(Mint(random_policy), builtin.i_data(0))],
    }
  spend(random_policy, fn(_r_data) { True }, fn(_tn_qty_dict) { True }, tx)
}

test fail_spend(
  random_policy_and_mint via fuzz.and_then(
    utils.mint_fuzzer(),
    grab_a_policy_from_mint,
  ),
) {
  let (random_policy, random_mint) = random_policy_and_mint
  let tx =
    Transaction {
      ..placeholder,
      mint: random_mint,
      redeemers: [Pair(Mint(random_policy), builtin.i_data(0))],
    }
  // Hashing to get a different policy
  let hashed_policy = blake2b_224(random_policy)
  spend(hashed_policy, fn(_r_data) { True }, fn(_tn_qty_dict) { True }, tx)
}

test success_spend_minimal(script_hash via fuzz.bytearray_fixed(28)) {
  let tx =
    Transaction { ..placeholder, mint: assets.from_asset(script_hash, #"", 1) }
  spend_minimal(script_hash, tx)
}

test fail_spend_minimal(script_hash via fuzz.bytearray_fixed(28)) fail {
  let tx =
    Transaction { ..placeholder, mint: assets.from_asset(script_hash, #"", 1) }
  // Hashing to get a different script hash
  let expected_mint_script_hash = blake2b_224(script_hash)
  spend_minimal(expected_mint_script_hash, tx)
}
