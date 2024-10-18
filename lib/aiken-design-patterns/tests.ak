use aiken/collection/list
use aiken/crypto.{blake2b_256}
use aiken/fuzz
use aiken/math
use aiken/primitive/bytearray
use aiken_design_patterns/utils.{
  authentic_input_is_reproduced_unchanged, foldl2, foldl3, foldl4, foldr2,
  foldr3, foldr4, sum_of_squares,
}
use cardano/address.{Address, Script}
use cardano/assets
use cardano/transaction.{InlineDatum, Output}

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
      payment_credential: Script(test_224_01()),
      stake_credential: None,
    },
    value: assets.add(assets.from_lovelace(2_000_000), test_224_01(), #"01", 1),
    datum: InlineDatum(1),
    reference_script: None,
  }
}

// Create a UTxO
fn test_utxo_02() {
  Output {
    address: Address {
      payment_credential: Script(test_224_02()),
      stake_credential: None,
    },
    value: assets.add(assets.from_lovelace(2_000_000), test_224_02(), #"02", 1),
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

const fold_elems = [2, 3, 4]

const left_acc = math.pow(4, math.pow(3, math.pow(2, 1)))

const right_acc = math.pow(2, math.pow(3, math.pow(4, 1)))

test success_foldr() {
  let acc0 = list.foldr(fold_elems, 1, fn(x, z0) { math.pow(x, z0) })
  trace @"found"
  trace acc0
  trace @"expected"
  trace right_acc
  acc0 == right_acc
}

test success_foldl() {
  let acc0 = list.foldl(fold_elems, 1, fn(x, z0) { math.pow(x, z0) })
  trace @"found"
  trace acc0
  trace @"expected"
  trace left_acc
  acc0 == left_acc
}

test success_foldr2() {
  let
    _,
    acc1,
  <-
    foldr2(
      fold_elems,
      0,
      1,
      fn(x, _z0, z1, return) { return(0, math.pow(x, z1)) },
    )
  trace @"found"
  trace acc1
  trace @"expected"
  trace right_acc
  acc1 == right_acc
}

test success_foldl2() {
  let
    _,
    acc1,
  <-
    foldl2(
      fold_elems,
      0,
      1,
      fn(x, _z0, z1, return) { return(0, math.pow(x, z1)) },
    )
  trace @"found"
  trace acc1
  trace @"expected"
  trace left_acc
  acc1 == left_acc
}

test success_foldr3() {
  let
    _,
    _,
    acc2,
  <-
    foldr3(
      fold_elems,
      0,
      0,
      1,
      fn(x, _z0, _z1, z2, return) { return(0, 0, math.pow(x, z2)) },
    )
  trace @"found"
  trace acc2
  trace @"expected"
  trace right_acc
  acc2 == right_acc
}

test success_foldl3() {
  let
    _,
    _,
    acc2,
  <-
    foldl3(
      fold_elems,
      0,
      0,
      1,
      fn(x, _z0, _z1, z2, return) { return(0, 0, math.pow(x, z2)) },
    )
  trace @"found"
  trace acc2
  trace @"expected"
  trace left_acc
  acc2 == left_acc
}

test success_foldr4() {
  let
    _,
    _,
    _,
    acc3,
  <-
    foldr4(
      fold_elems,
      0,
      0,
      0,
      1,
      fn(x, _z0, _z1, _z2, z3, return) { return(0, 0, 0, math.pow(x, z3)) },
    )
  trace @"found"
  trace acc3
  trace @"expected"
  trace right_acc
  acc3 == right_acc
}

test success_foldl4() {
  let
    _,
    _,
    _,
    acc3,
  <-
    foldl4(
      fold_elems,
      0,
      0,
      0,
      1,
      fn(x, _z0, _z1, _z2, z3, return) { return(0, 0, 0, math.pow(x, z3)) },
    )
  trace @"found"
  trace acc3
  trace @"expected"
  trace left_acc
  acc3 == left_acc
}
