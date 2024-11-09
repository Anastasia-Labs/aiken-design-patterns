use aiken/builtin
use aiken/crypto.{ScriptHash}
use aiken_design_patterns/merkelized_validator.{WithdrawRedeemer} as merkelized_validator
use aiken_design_patterns/utils.{sum_of_squares}
use cardano/address.{Credential}
use cardano/transaction.{OutputReference, Transaction}

// Definition of a custom validator for spending transactions
validator spending_example(stake_validator: ScriptHash) {
  spend(m_x: Option<Int>, y: Int, _own_ref: OutputReference, tx: Transaction) {
    expect Some(x) = m_x
    expect [sum] =
      [x, y]
        |> merkelized_validator.delegated_compute(
            stake_validator,
            fn(_i, x) { builtin.un_i_data(x) },
            fn(_i, x) { builtin.un_i_data(x) },
            tx.redeemers,
          )
    sum < 42
  }

  else(_) {
    fail
  }
}

// Definition of a custom validator for withdrawal transactions
validator logic_example {
  withdraw(
    redeemer: WithdrawRedeemer<Int, Int>,
    _own_credential: Credential,
    _tx: Transaction,
  ) {
    merkelized_validator.withdraw(sum_of_squares, redeemer)
  }

  else(_) {
    fail
  }
}
