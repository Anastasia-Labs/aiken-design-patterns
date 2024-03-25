use aiken/bytearray
use aiken/hash.{blake2b_256}
use aiken/transaction.{InlineDatum, Output}
use aiken/transaction/credential.{Address, ScriptCredential}
use aiken/transaction/value
use aiken_design_patterns/utils.{
  authentic_input_is_reproduced_unchanged, sum_of_squares,
}

fn test_224_01() {
  bytearray.take(blake2b_256(#"01"), 28)
}

fn test_224_02() {
  bytearray.take(blake2b_256(#"02"), 28)
}

fn test_utxo_01() {
  Output {
    address: Address {
      payment_credential: ScriptCredential(test_224_01()),
      stake_credential: None,
    },
    value: value.add(value.from_lovelace(2_000_000), test_224_01(), #"01", 1),
    datum: InlineDatum(1),
    reference_script: None,
  }
}

fn test_utxo_02() {
  Output {
    address: Address {
      payment_credential: ScriptCredential(test_224_02()),
      stake_credential: None,
    },
    value: value.add(value.from_lovelace(2_000_000), test_224_02(), #"02", 1),
    datum: InlineDatum(1),
    reference_script: None,
  }
}

test authentic_utxo_reproduced() {
  authentic_input_is_reproduced_unchanged(
    test_224_01(),
    None,
    test_utxo_01(),
    test_utxo_01(),
  )
}

test unauthentic_utxo_reproduced() fail {
  authentic_input_is_reproduced_unchanged(
    test_224_01(),
    None,
    test_utxo_01(),
    test_utxo_02(),
  )
}

test sum_of_squares_test_ok() {
  sum_of_squares([100, 20, 3, 4, 5]) == [10450]
}

test sum_of_squares_test_fail() fail {
  sum_of_squares([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]) == [1]
}
