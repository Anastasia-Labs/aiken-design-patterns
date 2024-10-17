use aiken/collection/dict
use aiken/crypto.{ScriptHash}
use aiken/fuzz
use aiken/interval
use aiken_design_patterns/tx_level_minter as tx_level_minter
use aiken_design_patterns/utils.{resolve_output_reference}
use cardano/address.{Address, Script}
use cardano/assets
use cardano/transaction.{
  Input, NoDatum, Output, OutputReference, ScriptContext, Transaction,
  placeholder,
}

type SampleSpendRedeemer {
  own_index: Int,
  burn: Bool,
}

type SampleMintRedeemer {
  max_utxos_to_spend: Int,
}

validator example {
  // Sample spend logic on how to use the provided interface. Here we are
  // passing script's own hash as the expected minting policy.
  spend(
    _datum,
    redeemer: SampleRedeemer,
    own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    let Transaction { inputs, mint, .. } = tx

    let SampleSpendRedeemer { own_index, burn } = redeemer

    // Grabbing spending UTxO based on the provided index.
    let Input { output: Output { address: own_addr, .. }, output_reference } =
      list.at(tx.inputs, own_index)

    // Validating that the found UTxO is in fact the spending UTxO.
    expect (own_out_ref == output_reference)?

    // Getting the validator's script hash.
    expect Script(own_hash) = own_addr.payment_credential

    // Utilizing the design pattern, where the underlying logic expects a single
    // "BEACON" token to by either burnt or minted.
    tx_level_minter.spend(
      own_hash,
      fn(redeemer_data) {
        expect SampleMintRedeemer { max_utxos_to_spend } = redeemer_data
        max_utxos_to_spend > 0
      },
      fn(tn_qty_dict) {
        expect [Pair("BEACON", mint_quantity)] = dict.to_pairs(tn_qty_dict)
        if redeemer.burn {
          mint_quantity == -1
        } else {
          mint_quantity == 1
        }
      },
      mint,
    )
  }

  // Sample mint logic that benefits from this design pattern. This example
  // expects a specific number of inputs to be spent in each transaction.
  mint(redeemer: SampleMintRedeemer, own_policy, tx: Transaction) {
    let script_inputs_count =
      tx.inputs
        |> list.foldr(
            0,
            fn(i, acc) {
              when i.output.address is {
                Script(input_script_hash) ->
                  if input_script_hash == own_policy {
                    acc + 1
                  } else {
                    acc
                  }
                _ -> acc
              }
            },
          )
    (script_inputs_count == redeemer.max_utxos_to_spend)?
  }

  else(_) {
    fail
  }
}
