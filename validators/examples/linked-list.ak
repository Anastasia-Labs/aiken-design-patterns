//// @hidden

use aiken/collection/list
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId}
use cardano/transaction.{Input, Output, OutputReference, Transaction}

const root_key = #""

const node_key_prefix = "NODE"

const node_key_prefix_length = bytearray.length(node_key_prefix)

// This example uses fixed-width ordering keys that fill the remaining asset
// name bytes. The mint policy/caller must keep node keys non-empty and unique,
// especially for unordered lists; the library assumes that invariant.
const node_key_length = 32 - node_key_prefix_length

pub type ExampleRootState {
  version: Int,
}

pub type ExampleNodeState {
  label: ByteArray,
}

pub type ExampleListDatum =
  linked_list.Element<ExampleRootState, ExampleNodeState>

pub type ExampleListMintRedeemer {
  Init { root_output_index: Int }
  InsertAscending {
    continued_anchor_output_index: Int,
    new_node_output_index: Int,
  }
}

pub type ExampleListSpendRedeemer {
  PermitListStateTransition { input_index: Int }
  UpdateRootData {
    input_index: Int,
    output_index: Int,
    list_nft_policy: PolicyId,
  }
}

// This example is wired as one multi-purpose validator, so its spend hash and
// policy hash are equal. The library itself only requires passing the actual
// list NFT policy to the helper runners.
validator linked_list_example(init_nonce_input_out_ref: OutputReference) {
  mint(redeemer: ExampleListMintRedeemer, own_policy: PolicyId, tx: Transaction) {
    when redeemer is {
      Init { root_output_index } -> {
        let Transaction { inputs, outputs, mint, .. } = tx

        let root_output = list.expect_at(outputs, root_output_index)

        let nonce_validated = list.any(
          inputs,
          fn(i) { i.output_reference == init_nonce_input_out_ref },
        )

        {
          let root_address, _root_lovelace, root_data <- linked_list.init(
            nonce_validated: nonce_validated,
            produced_element_output: root_output,
            tx_mint: mint,
          )

          // Wrapped data must be correct.
          let expected_root_data: Data = ExampleRootState { version: 0 }
          expect root_data == expected_root_data

          // Root UTxO must be produced at own script payment credential.
          expect  
              Address {
                payment_credential: Script(destination_script_hash),
                ..
              }
            = root_address
          expect destination_script_hash == own_policy

          // Done.
          True
        }
          |> linked_list.run_root_with(own_policy, root_key)
      }

      InsertAscending { continued_anchor_output_index, new_node_output_index } -> {
        let Transaction { inputs, outputs, mint, .. } = tx

        let continued_anchor_output = outputs
          |> list.expect_at(continued_anchor_output_index)

        let new_node_output = outputs |> list.expect_at(new_node_output_index)

        {
          let  
              _anchor_input,
              _anchor_lovelace_change,
              _maybe_anchor_key,
              _anchor_data,
              _new_node_lovelace,
              new_node_key,
              new_node_data,
              _new_node_link
            <- linked_list.insert_ascending(
            continued_anchor_element_output: continued_anchor_output,
            new_node_output: new_node_output,
            inputs: inputs,
            tx_mint: mint,
          )
          expect _node_state: ExampleNodeState = new_node_data
          bytearray.length(new_node_key) == node_key_length
        }
          |> linked_list.run_element_with(
              own_policy,
              root_key,
              node_key_prefix,
              node_key_prefix_length,
            )
      }
    }
  }

  spend(
    _datum: Option<ExampleListDatum>,
    redeemer: ExampleListSpendRedeemer,
    own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    let Transaction { inputs, outputs, mint, .. } = tx

    when redeemer is {
      PermitListStateTransition { input_index } -> {
        expect  
            Input {
              output: Output {
                address: Address { payment_credential: Script(own_hash), .. },
                ..
              },
              output_reference,
            }
          = inputs |> list.expect_at(input_index)

        expect output_reference == own_out_ref

        // This spend-side gate is only safe with the paired list minting
        // policy below, whose structural branches must validate the exact list
        // transition through the matching linked-list mint helpers.
        linked_list.spend_for_adding_or_removing_an_element(own_hash, mint)
      }

      UpdateRootData { input_index, output_index, list_nft_policy } ->
        {
          let  
              element_address,
              lovelace_change,
              maybe_node_key,
              old_data,
              new_data,
              _link
            <- linked_list.spend_for_updating_elements_data(
            element_input_index: input_index,
            continued_element_output_index: output_index,
            element_input_outref: own_out_ref,
            inputs: inputs,
            outputs: outputs,
            tx_mint: mint,
          )

          // Provisioned list NFT policy ID via the redeemer must be correct.
          expect Address { payment_credential: Script(own_hash), .. } = element_address
          expect own_hash == list_nft_policy

          // No ADA can be withdrawn from anchor. But it's allowed to be
          // deposited as changes to datum can increase the min required ADA.
          expect lovelace_change >= 0

          // Spent element must be root.
          expect None = maybe_node_key

          // Root data must increment the version.
          expect ExampleRootState { version: old_version } = old_data
          let expected_new_root_data: Data = ExampleRootState {
            version: old_version + 1,
          }
          expect new_data == expected_new_root_data

          // Done.
          True
        }
          |> linked_list.run_element_with(
              list_nft_policy,
              root_key,
              node_key_prefix,
              node_key_prefix_length,
            )
    }
  }

  else(_) {
    fail
  }
}
