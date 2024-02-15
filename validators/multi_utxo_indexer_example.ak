use aiken/transaction.{Output, ScriptContext}
use aiken/transaction/value.{PolicyId}
use aiken_design_patterns/multi_utxo_indexer as multi_utxo_indexer
use aiken_design_patterns/stake_validator as stake_validator

validator(state_token_symbol: PolicyId) {
  fn spend(_datum, _redeemer, ctx: ScriptContext) {
    stake_validator.spend(ctx)
  }

  fn withdraw(redeemer: List<(Int, Int)>, ctx: ScriptContext) {
    multi_utxo_indexer.withdraw(
      fn(in_utxo, out_utxo) {
        let Output { value: in_val, datum: in_dat, .. } = in_utxo

        let Output { value: out_val, datum: out_dat, .. } = out_utxo

        expect [(in_sym, _, in_quantity)] =
          in_val
            |> value.without_lovelace
            |> value.flatten

        and {
          in_val == out_val,
          in_dat == out_dat,
          in_sym == state_token_symbol,
          in_quantity == 1,
        }
      },
      redeemer,
      ctx,
    )
  }
}
