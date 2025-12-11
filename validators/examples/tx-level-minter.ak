//// @hidden

use aiken/collection/dict
use aiken/collection/list
use aiken_design_patterns/tx_level_minter
use cardano/address.{Address, Script}
use cardano/transaction.{Input, Output, OutputReference, Transaction}

pub type SampleSpendRedeemer {
  own_index: Int,
  mint_redeemer_index: Int,
  burn: Bool,
}

pub type SampleMintRedeemer {
  max_utxos_to_spend: Int,
}

validator example {
  // Sample spend logic on how to use the provided interface. Here we are
  // passing script's own hash as the expected minting policy.
  spend(
    _datum,
    redeemer: SampleSpendRedeemer,
    own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    // Grabbing spending UTxO based on the provided index.
    expect Some(Input {
      output: Output { address: own_addr, .. },
      output_reference,
    }) = list.at(tx.inputs, redeemer.own_index)

    // Validating that the found UTxO is in fact the spending UTxO.
    expect own_out_ref == output_reference

    // Getting the validator's script hash.
    expect Script(own_hash) = own_addr.payment_credential

    // Getting access to the mint script's redeemer, and the tokens being
    // minted/burnt using the design pattern. The logic that follows expects a
    // single "BEACON" token to be either burnt or minted.
    let
      redeemer_data,
      tn_qty_dict,
    <-
      tx_level_minter.validate_mint(
        own_hash,
        tx.mint,
        tx.redeemers,
        redeemer.mint_redeemer_index,
      )
    expect SampleMintRedeemer { max_utxos_to_spend } = redeemer_data
    expect max_utxos_to_spend > 0
    expect [Pair("BEACON", mint_quantity)] = dict.to_pairs(tn_qty_dict)
    if redeemer.burn {
      mint_quantity == -1
    } else {
      mint_quantity == 1
    }
  }

  // Sample mint logic to complete the example. This policy expects a specific
  // number of inputs to be spent in each transaction.
  mint(redeemer: SampleMintRedeemer, own_policy, tx: Transaction) {
    let script_inputs_count =
      tx.inputs
        |> list.foldr(
            0,
            fn(i, acc) {
              when i.output.address.payment_credential is {
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
    script_inputs_count == redeemer.max_utxos_to_spend
  }

  else(_) {
    fail
  }
}
