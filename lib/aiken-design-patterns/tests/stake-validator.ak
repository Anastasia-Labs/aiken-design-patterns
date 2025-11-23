use aiken/builtin
use aiken/crypto.{blake2b_224}
use aiken/fuzz
use aiken_design_patterns/stake_validator.{
  validate_withdraw, validate_withdraw_minimal,
}
use cardano/address.{Script}
use cardano/transaction.{Transaction, Withdraw, placeholder}

test success__validate_withdraw(script_hash via fuzz.bytearray_fixed(28)) {
  let redeemers = [Pair(Withdraw(Script(script_hash)), builtin.i_data(0))]
  let withdrawals = [Pair(Script(script_hash), 0)]
  let
    _redeemer_data,
    _withdraw_quantity,
  <- validate_withdraw(script_hash, withdrawals, redeemers)
  True
}

test fail__validate_withdraw(script_hash via fuzz.bytearray_fixed(28)) fail {
  let spend_script = Script(script_hash)
  let redeemers = [Pair(Withdraw(spend_script), builtin.i_data(0))]
  let withdrawals = [Pair(Script(script_hash), 0)]
  // Hashing to get a different script hash
  let expected_withdraw_script_hash = blake2b_224(script_hash)
  let
    _redeemer_data,
    _withdraw_quantity,
  <- validate_withdraw(expected_withdraw_script_hash, withdrawals, redeemers)
  True
}

test success__validate_withdraw_minimal(
  script_hash via fuzz.bytearray_fixed(28),
) {
  let withdrawals = [Pair(Script(script_hash), 0)]
  validate_withdraw_minimal(script_hash, withdrawals)
}

test fail__validate_withdraw_minimal(
  script_hash via fuzz.bytearray_fixed(28),
) fail {
  let spend_script = Script(script_hash)
  let withdrawals = [Pair(spend_script, 0)]
  // Hashing to get a different script hash
  let expected_withdraw_script_hash = blake2b_224(script_hash)
  validate_withdraw_minimal(expected_withdraw_script_hash, withdrawals)
}
