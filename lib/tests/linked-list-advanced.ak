use aiken/builtin
use aiken/collection/dict
use aiken/crypto.{blake2b_224}
use aiken_design_patterns/linked_list.{
  Element, Root, run_root_with, spend_for_adding_or_removing_an_element,
}
use aiken_design_patterns/linked_list/advanced.{init}
use cardano/address.{Address, Script}
use cardano/assets
use cardano/transaction.{InlineDatum, Output}

const min_lovelace = 2_000_000

const test_root_key = #""

const extra_asset_name = #"6578747261"

const b_data = builtin.b_data(#"00")

test success__advanced_init__extra_policy_assets_and_reference_script() {
  let script_hash = blake2b_224(#"ad")
  let root_mint = assets.from_asset(script_hash, test_root_key, 1)
  let extra_mint = assets.from_asset(script_hash, extra_asset_name, 1)
  let tx_mint = root_mint |> assets.merge(extra_mint)
  let script_output =
    Output {
      address: Address {
        payment_credential: Script(script_hash),
        stake_credential: None,
      },
      value: assets.from_lovelace(min_lovelace) |> assets.merge(root_mint),
      datum: InlineDatum(Element { data: Root(b_data), link: None }),
      reference_script: Some(script_hash),
    }

  init(
    True,
    script_output,
    tx_mint,
    fn(lovelace, other_assets, root_data, ref_script) {
      expect Some(extra_qty) = other_assets |> dict.get(extra_asset_name)
      and {
        lovelace == min_lovelace,
        extra_qty == 1,
        root_data == b_data,
        ref_script == Some(script_hash),
      }
    },
  )
    |> run_root_with(script_hash, test_root_key)
}

test success__advanced_spend_for_adding_or_removing__ignores_extra_assets() {
  let script_hash = blake2b_224(#"ad")
  let node_asset_name = #"4e4f4445"
  let structural_mint = assets.from_asset(script_hash, node_asset_name, 1)
  let extra_mint = assets.from_asset(script_hash, extra_asset_name, 1)

  spend_for_adding_or_removing_an_element(
    script_hash,
    structural_mint |> assets.merge(extra_mint),
  )
}
