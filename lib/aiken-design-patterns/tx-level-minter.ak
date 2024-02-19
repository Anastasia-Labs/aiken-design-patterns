use aiken/hash.{Blake2b_224, Hash}
use aiken/transaction.{Output, ScriptContext, Spend, Transaction, WithdrawFrom}
use aiken/transaction/credential.{Inline, Script, ScriptCredential}
use aiken/transaction/value.{AssetName, PolicyId, Value}
use fortuna/utils.{resolve_output_reference}

pub fn spend(expected_mint_name: AssetName, ctx: ScriptContext) -> Bool {
  expect ScriptContext { transaction: tx, purpose: Spend(own_ref) } = ctx

  let Transaction { inputs, mint, .. } = tx

  let Output { address: own_addr, value: own_value } =
    resolve_output_reference(inputs, own_ref)

  expect ScriptCredential(own_validator_hash) = own_addr.payment_credential

  // Exactly one asset is expected to be minted.
  expect [(mint_policy, mint_name, mint_quantity)] =
    mint
      |> value.from_minted_value
      |> value.flatten

  let prev_mint_quantity =
    own_value
      |> value.quantity_of(mint_policy, mint_name)

  // If there are no tokens included, expects exactly 1 to be minted, otherwise
  // allows for all previously minted tokens to be burnt.
  let expected_mint_quantity =
    if (prev_mint_quantity == 0) {
      1
    } else {
      -prev_mint_quantity
    }

  // Minted token must have the same policy ID as the spending validator hash
  // (i.e. it is expected to be a multi-validator). Its token name and quantity
  // are specified in the parameters of this helper function.
  and {
    mint_policy == own_validator_hash,
    mint_name == expected_mint_name,
    mint_quantity == expected_mint_quantity,
  }
}

pub fn mint(
  mint_logic: fn(Data, Hash<Blake2b_224, Script>, Transaction) -> Bool,
  redeemer: Data,
  ctx: ScriptContext,
) -> Bool {
  expect ScriptContext { transaction: tx, purpose: Mint(own_policy) } =
    ctx

  mint_logic(redeemer, own_policy, tx)
}

