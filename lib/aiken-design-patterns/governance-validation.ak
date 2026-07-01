use aiken/builtin
use aiken/cbor
use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list
use cardano/address.{Address}
use cardano/assets.{PolicyId, Value}
use cardano/transaction.{Input, Output}

pub const root_key: linked_list.RootKey = "PROPOSALS_ROOT"

pub const node_key_prefix: linked_list.NodeKeyPrefix = "GOVV"

pub const node_key_prefix_length: linked_list.NodeKeyPrefixLength =
  bytearray.length(node_key_prefix)

/// This is dedicated to UTxOs outside the linked list namespace; the ones
/// minted after successful passage of a tied builtin cost change governance
/// proposal.
pub const update_auth_prefix: ByteArray = "AUTH"

pub const update_auth_prefix_length: Int = bytearray.length(update_auth_prefix)

pub type Empty =
  ByteArray

@list
pub type ApprovalCriteria {
  builtin_index: Int,
  initial_builtin_cost: Int,
  acceptance_builtin_cost: Int,
}

/// `state` refers to the set of parameters/info that this governance validator
/// allows updating after the corresponding governance proposal passes and
/// changes the specified builtin cost to the new value.
pub type Proposal<state> {
  proposer: VerificationKeyHash,
  mint_script_data_hash: ByteArray,
  approval_criteria: ApprovalCriteria,
  current_state: Data<state>,
  new_state: Data<state>,
  valid_until: Int,
}

pub type Datum<state> =
  linked_list.Element<Empty, Proposal<state>>

/// Linked list `Element` has two constructors, reserving indexes of 0 and 1.
/// Hardcoding index 2 for this datatype allows the "dangling" auth UTxOs not to
/// get mingled with element UTxO datums.
@tag(2)
pub type AuthenticatedStateUpdate<state> {
  script_data_hash: ByteArray,
  cost_model: ByteArray,
  spend_cpu: Int,
  spend_mem: Int,
  mint_cpu: Int,
  mint_mem: Int,
  new_state: Data<state>,
}

pub type SpendRedeemer {
  // Dedicated for adding/removing linked list elements. This passes as long as
  // any mint transaction is present in the transaction. It's up to mint
  // endpoints to disallow invalid spends.
  DelegateToMint
}

pub type MintRedeemer {
  // Initializing the list for proposals.
  Init
  // Inserting a new proposal node in the list. At mint we must validate that
  // the transaction's cost models has a value at the specified index which is
  // the same as `initial_builtin_cost` and different from the
  // `acceptance_builtin_cost`.
  AddProposal
  // Burning a proposal which its corresponding governance proposal has passed,
  // and minting a dedicated NFT outside list namespace which can later be burnt
  // to update the actual `state`.
  // This endpoint shows that the stored `burn_script_data_hash` includes a
  // cost model which the value at its specified index equals the indicated
  // `acceptance_builtin_cost`.
  MintParameterUpdateAuth
  // Burning an authenticated update token (which was minted after successful
  // passage of a specified governance proposal).
  ApplyPassedParameter
  // Retrieval of the proposal deposit by the proposer for proposals that their
  // corresponding governance proposal did not pass, and are past their validity
  // time.
  RemoveExpiredProposal
}

pub fn node_key(approval_criteria: ApprovalCriteria) -> linked_list.NodeKey {
  cbor.serialise(approval_criteria) |> builtin.blake2b_224
}

/// Decodes a given CBOR byte array into an `Int`.
pub fn cbor_int_to_int(cbor_int: ByteArray) -> Int {
  let header = bytearray.at(cbor_int, 0)
  let major_type = header / 32
  let additional_info = header % 32

  expect major_type == 0 || major_type == 1

  let n, next_cursor <- cbor_int_payload(cbor_int, 0, additional_info)

  expect next_cursor == bytearray.length(cbor_int)

  let is_canonical =
    if additional_info == 24 {
      n >= 24
    } else if additional_info == 25 {
      n >= 256
    } else if additional_info == 26 {
      n >= 65536
    } else if additional_info == 27 {
      n >= 4294967296
    } else {
      True
    }

  expect is_canonical

  if major_type == 0 {
    n
  } else {
    -1 - n
  }
}

pub fn builtin_cost_at(cost_model: ByteArray, index: Int) -> Int {
  let length, cursor <- process_cost_model_header(cost_model)

  expect index >= 0
  expect index < length

  do_builtin_cost_at(cost_model, cursor, 0, index)
}

pub fn validate_burn_script_data_hash(
  burn_script_data_hash: ByteArray,
  cost_model: ByteArray,
  spend_cpu: Int,
  spend_mem: Int,
  mint_cpu: Int,
  mint_mem: Int,
) -> Bool {
  let spend_redeemer: SpendRedeemer = DelegateToMint
  let mint_redeemer: MintRedeemer = ApplyPassedParameter

  let redeemers =
    #"a2"
      |> bytearray.concat(#"820000")
      |> bytearray.concat(
          serialise_list_of_two(
            cbor.serialise(spend_redeemer),
            serialise_budget(spend_mem, spend_cpu),
          ),
        )
      |> bytearray.concat(#"820100")
      |> bytearray.concat(
          serialise_list_of_two(
            cbor.serialise(mint_redeemer),
            serialise_budget(mint_mem, mint_cpu),
          ),
        )

  let language_views = #"a102" |> bytearray.concat(cost_model)

  builtin.blake2b_256(bytearray.concat(redeemers, language_views)) == burn_script_data_hash
}

/// Helper for initializing the linked that all proposals will live within. We
/// use a linked list to disallow identical acceptance criteria for multiple
/// proposals. Node keys are derived from mint and burn script data hashes. So
/// no two identical updates to the cost models can coexist.
pub fn init(
  nonce_input_index: Int,
  root_output_index: Int,
  governance_list_address: Address,
  governance_list_nft_policy: PolicyId,
  inputs: List<Input>,
  outputs: List<Output>,
  mint: Value,
) -> Bool {
  {
    let
      root_address,
      _root_lovelace,
      root_data,
    <-
      linked_list.init(
        nonce_validated: {
          expect Some(_) = inputs |> list.at(nonce_input_index)
          True
        },
        produced_element_output: outputs |> list.expect_at(root_output_index),
        tx_mint: mint,
      )
    expect root_address == governance_list_address
    expect builtin.un_b_data(root_data) == #""
    True
  }
    |> linked_list.run_root_with(governance_list_nft_policy, root_key)
}

// ## Internal Helpers

fn serialise_list_of_two(
  serialised_elem_0: ByteArray,
  serialised_elem_1: ByteArray,
) -> ByteArray {
  #"82"
    |> bytearray.concat(serialised_elem_0)
    |> bytearray.concat(serialised_elem_1)
}

fn serialise_budget(mem: Int, cpu: Int) -> ByteArray {
  serialise_list_of_two(cbor.serialise(mem), cbor.serialise(cpu))
}

fn process_cost_model_header(
  cost_model: ByteArray,
  return: fn(Int, Int) -> result,
) -> result {
  let header = bytearray.at(cost_model, 0)

  if header >= 0x80 && header <= 0x97 {
    return(header - 0x80, 1)
  } else if header == 0x98 {
    return(bytearray.at(cost_model, 1), 2)
  } else if header == 0x99 {
    return(bytearray.slice(cost_model, 1, 2) |> bytearray.to_int_big_endian, 3)
  } else {
    fail @"invalid cost model array"
  }
}

fn cbor_int_payload(
  cost_model: ByteArray,
  cursor: Int,
  additional_info: Int,
  return: fn(Int, Int) -> result,
) -> result {
  if additional_info < 24 {
    return(additional_info, cursor + 1)
  } else if additional_info == 24 {
    return(bytearray.at(cost_model, cursor + 1), cursor + 2)
  } else if additional_info == 25 {
    return(
      bytearray.slice(cost_model, cursor + 1, cursor + 2)
        |> bytearray.to_int_big_endian,
      cursor + 3,
    )
  } else if additional_info == 26 {
    return(
      bytearray.slice(cost_model, cursor + 1, cursor + 4)
        |> bytearray.to_int_big_endian,
      cursor + 5,
    )
  } else if additional_info == 27 {
    return(
      bytearray.slice(cost_model, cursor + 1, cursor + 8)
        |> bytearray.to_int_big_endian,
      cursor + 9,
    )
  } else {
    fail @"invalid cbor integer"
  }
}

fn do_builtin_cost_at(
  cost_model: ByteArray,
  cursor: Int,
  current_index: Int,
  target_index: Int,
) -> Int {
  let header = bytearray.at(cost_model, cursor)
  let major_type = header / 32
  let additional_info = header % 32

  expect major_type == 0 || major_type == 1

  if current_index == target_index {
    let n, _next_cursor <- cbor_int_payload(cost_model, cursor, additional_info)
    if major_type == 0 {
      n
    } else {
      -1 - n
    }
  } else {
    let next_cursor =
      if additional_info < 24 {
        cursor + 1
      } else if additional_info == 24 {
        cursor + 2
      } else if additional_info == 25 {
        cursor + 3
      } else if additional_info == 26 {
        cursor + 5
      } else if additional_info == 27 {
        cursor + 9
      } else {
        fail @"invalid cost model integer"
      }

    do_builtin_cost_at(cost_model, next_cursor, current_index + 1, target_index)
  }
}
