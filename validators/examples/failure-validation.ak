//// @hidden

use aiken/crypto.{ScriptHash}
use cardano/address.{Credential, Script}
use cardano/assets.{PolicyId}
use cardano/certificate.{Certificate}
use cardano/transaction.{
  OutputReference, Redeemer, Spend, Transaction, Withdraw,
}

validator delegated_spend(core_script_hash: ScriptHash) {
  spend(
    _m_datum: Option<Data>,
    redeemer: ScriptHash,
    _own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    let Transaction { withdrawals, redeemers, .. } = tx
    expect [Pair(Script(withdraw_script_hash), _)] = withdrawals
    // No need to check for the spend's output reference, or withdrawal script
    // hash, as there can't be any other spend redeemers, and withdrawal is
    // already validated via the withdrawals entry.
    expect [Pair(Spend(_), _), Pair(Withdraw(Script(_)), _)] = redeemers
    // Re-provision of the core script hash via the redeemer allows other
    // scripts to verify this spend logic would have passed given the correct
    // script hash.
    expect redeemer == core_script_hash
    expect withdraw_script_hash == core_script_hash
    True
  }

  else(_) {
    fail
  }
}

validator always_fails_withdrawal {
  publish(_redeemer: Redeemer, _certificate: Certificate, _tx: Transaction) {
    True
  }

  withdraw(
    _redeemer: Redeemer,
    _own_credential: Credential,
    _tx: Transaction,
  ) {
    False
  }

  else(_) {
    fail
  }
}

validator temp_always_mint {
  mint(_redeemer: Redeemer, _policy_id: PolicyId, _tx: Transaction) {
    True
  }

  else(_) {
    fail
  }
}
