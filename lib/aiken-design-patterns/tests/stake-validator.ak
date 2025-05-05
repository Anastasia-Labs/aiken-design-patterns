use aiken/builtin
use aiken/crypto.{blake2b_224}
use aiken/fuzz
use aiken_design_patterns/stake_validator.{spend, spend_minimal}
use cardano/address.{Script}
use cardano/transaction.{Transaction, Withdraw, placeholder}

test success_spend(script_hash via fuzz.bytearray_fixed(28)) {
  let tx =
    Transaction {
      ..placeholder,
      redeemers: [Pair(Withdraw(Script(script_hash)), builtin.i_data(0))],
      withdrawals: [Pair(Script(script_hash), 0)],
    }
  spend(script_hash, fn(_r_data, _qty) { True }, tx)
}

test fail_spend(script_hash via fuzz.bytearray_fixed(28)) fail {
  let spend_script = Script(script_hash)
  let tx =
    Transaction {
      ..placeholder,
      redeemers: [Pair(Withdraw(spend_script), builtin.i_data(0))],
      withdrawals: [Pair(spend_script, 0)],
    }
  // Hashing to get a different script hash
  let expected_withdraw_script_hash = blake2b_224(script_hash)
  spend(expected_withdraw_script_hash, fn(_r_data, _qty) { True }, tx)
}

test success_spend_minimal(script_hash via fuzz.bytearray_fixed(28)) {
  let tx =
    Transaction { ..placeholder, withdrawals: [Pair(Script(script_hash), 0)] }
  spend_minimal(script_hash, tx)
}

test fail_spend_minimal(script_hash via fuzz.bytearray_fixed(28)) fail {
  let spend_script = Script(script_hash)
  let tx = Transaction { ..placeholder, withdrawals: [Pair(spend_script, 0)] }
  // Hashing to get a different script hash
  let expected_withdraw_script_hash = blake2b_224(script_hash)
  spend_minimal(expected_withdraw_script_hash, tx)
}
