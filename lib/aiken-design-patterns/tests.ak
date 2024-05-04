use aiken/bytearray
use aiken/fuzz
use aiken/hash.{blake2b_256}
use aiken/list
use aiken/transaction.{InlineDatum, Output}
use aiken/transaction/credential.{Address, ScriptCredential}
use aiken/transaction/value
use aiken_design_patterns/utils.{
  authentic_input_is_reproduced_unchanged, sum_of_squares,
}

// Generate a bytearray with blake2b_256
fn test_224_01() {
  bytearray.take(blake2b_256(#"01"), 28)
}

// Generate a bytearray with blake2b_256
fn test_224_02() {
  bytearray.take(blake2b_256(#"02"), 28)
}

// Create a UTxO
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

// Create a UTxO
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

// Test case to ensure authentic UTXO is reproduced unchanged
test authentic_utxo_reproduced() {
  authentic_input_is_reproduced_unchanged(
    test_224_01(),
    None,
    test_utxo_01(),
    test_utxo_01(),
  )
}

// Test case to ensure unauthentic UTXO is not reproduced unchanged
test unauthentic_utxo_reproduced() fail {
  authentic_input_is_reproduced_unchanged(
    test_224_01(),
    None,
    test_utxo_01(),
    test_utxo_02(),
  )
}

// Test case for sum_of_squares function with expected output
test sum_of_squares_test_ok() {
  sum_of_squares([100, 20, 3, 4, 5]) == [10450]
}

// Test case for sum_of_squares function with expected failure
test sum_of_squares_test_fail() fail {
  sum_of_squares([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]) == [1]
}

// Property-based test: Testing the identity property with a single-element list
test prop_sum_of_squares_identity(x: Int via fuzz.int()) {
  sum_of_squares([x]) == [x * x]
}

// Property-based test: Testing non-negativity of the sum of squares
test prop_sum_of_squares_non_negative(xs: List<Int> via fuzz.list(fuzz.int())) {
  let result = sum_of_squares(xs)
  expect Some(head) = list.at(result, 0)
  head >= 0
}

// Property-based test: Testing the output always contains exactly one element
test prop_sum_of_squares_length(xs: List<Int> via fuzz.list(fuzz.int())) {
  let result = sum_of_squares(xs)
  list.length(result) == 1
}
