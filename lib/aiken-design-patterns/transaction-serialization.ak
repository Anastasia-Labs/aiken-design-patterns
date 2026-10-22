//// CBOR serialization shared by transaction reconstruction patterns.
////
//// Uses definite collections, shortest headers, canonical ledger-field maps,
//// and tag 258 on sets. Plutus Data maps can preserve their original entry order
//// or use canonical ordering. Data byte strings longer than 64 bytes use chunks.
//// Input sets retain caller order; callers supplying witness references must
//// enforce ledger ordering where pointer indices depend on it. Outputs use
//// datum-free encoding or include a supplied inline datum according to the
//// selected mode. Reference scripts are omitted.

use aiken/builtin
use aiken/cbor
use aiken/collection/dict
use aiken/collection/list
use aiken/collection/pairs
use aiken/crypto.{VerificationKeyHash}
use aiken/primitive/bytearray
use cardano/address.{
  Address, Credential, Inline, Pointer, Script, VerificationKey,
}
use cardano/assets.{AssetName, Assets, Lovelace}
use cardano/governance.{GovernanceActionId}
use cardano/transaction.{
  DatumHash, InlineDatum, NoDatum, Output, OutputReference,
}

/// Ledger language-view identifier for the Plutus V3 compilation target.
pub const plutus_language_id = 2

pub const serialised_plutus_language_id = cbor.serialise(plutus_language_id)

pub const set_cbor_tag = serialise_cbor_tag(258)

/// CBOR tag 102 marks the general Plutus Data constructor representation.
const general_plutus_data_constructor_cbor_tag = serialise_cbor_tag(102)

/// Exact redeemer-collection encoding. The active ledger protocol determines
/// which representations are permitted.
pub type RedeemerEncoding {
  ListEncoding
  MapEncoding
}

/// An additional language-view cost model, inserted as its complete CBOR value.
pub type LanguageCostModel {
  language_id: Int,
  cost_model: ByteArray,
}

/// Reconstruct a script-data hash with no datum witnesses. The Plutus V3 cost
/// model and any additional language views are authenticated by the resulting
/// hash only when it is bound to an authenticated transaction body.
pub fn hash_script_data(
  redeemers: ByteArray,
  cost_model: ByteArray,
  other_language_cost_models: List<LanguageCostModel>,
) -> ByteArray {
  let language_views = serialise_language_views(
    cost_model,
    other_language_cost_models,
  )
  builtin.blake2b_256(bytearray.concat(redeemers, language_views))
}

fn serialise_language_views(
  cost_model: ByteArray,
  other_language_cost_models: List<LanguageCostModel>,
) -> ByteArray {
  let entries = list.foldl(
    other_language_cost_models,
    [Pair(serialised_plutus_language_id, cost_model)],
    fn(language_cost_model, entries) {
      let LanguageCostModel { language_id, cost_model: other_cost_model } = language_cost_model
      entries
        |> insert_stable_canonical_map_entry(
            cbor.serialise(language_id),
            other_cost_model,
          )
    },
  )

  serialise_canonical_map_entries(entries)
}

pub fn serialise_list_of_two(
  serialised_elem_0: ByteArray,
  serialised_elem_1: ByteArray,
) -> ByteArray {
  #"82"
    |> bytearray.concat(serialised_elem_0)
    |> bytearray.concat(serialised_elem_1)
}

pub fn serialise_budget(mem: Int, cpu: Int) -> ByteArray {
  serialise_list_of_two(cbor.serialise(mem), cbor.serialise(cpu))
}

pub fn insert_redeemer_entry(
  entries: Pairs<ByteArray, Pair<ByteArray, ByteArray>>,
  tag: Int,
  index: Int,
  redeemer_data: ByteArray,
  budget: ByteArray,
) -> Pairs<ByteArray, Pair<ByteArray, ByteArray>> {
  let serialised_tag = cbor.serialise(tag)
  let serialised_index = cbor.serialise(index)
  let pointer = serialise_list_of_two(serialised_tag, serialised_index)

  // Tags are single-byte values 0 through 5, and ledger indices are
  // non-negative shortest-form integers, so bytewise key order is the
  // ledger's tag-then-index pointer order.
  entries
    |> pairs.insert_by_ascending_key(
        pointer,
        Pair(redeemer_data, budget),
        bytearray.compare,
      )
}

pub fn serialise_redeemer_entries(
  entries: Pairs<ByteArray, Pair<ByteArray, ByteArray>>,
  redeemer_encoding: RedeemerEncoding,
) -> ByteArray {
  when redeemer_encoding is {
    ListEncoding -> {
      // The pointer is `82 || tag || index`; list entries replace that
      // two-element-array header with their four-element-array header.
      let length, body <- list.foldr2(
        entries,
        0,
        "",
        fn(entry, length, body, return) {
          let Pair(pointer, Pair(redeemer_data, budget)) = entry
          return(
            length + 1,
            #"84"
              |> bytearray.concat(bytearray.drop(pointer, 1))
              |> bytearray.concat(redeemer_data)
              |> bytearray.concat(budget)
              |> bytearray.concat(body),
          )
        },
      )

      serialise_definite_list(length, body)
    }
    MapEncoding -> {
      let length, body <- list.foldr2(
        entries,
        0,
        "",
        fn(entry, length, body, return) {
          let Pair(pointer, Pair(redeemer_data, budget)) = entry
          return(
            length + 1,
            pointer
              |> bytearray.concat(serialise_list_of_two(redeemer_data, budget))
              |> bytearray.concat(body),
          )
        },
      )

      serialise_cbor_head(5, length) |> bytearray.concat(body)
    }
  }
}

pub fn serialise_optional_field(
  key: Int,
  value: Option<a>,
  serialise: fn(a) -> ByteArray,
  return: fn(Int, ByteArray) -> result,
) -> result {
  when value is {
    None -> return(0, "")
    Some(value) ->
      return(1, cbor.serialise(key) |> bytearray.concat(serialise(value)))
  }
}

pub fn serialise_nonempty_list_field(
  key: Int,
  values: List<a>,
  serialise: fn(List<a>) -> ByteArray,
  return: fn(Int, ByteArray) -> result,
) -> result {
  when values is {
    [] -> return(0, "")
    _ -> return(1, cbor.serialise(key) |> bytearray.concat(serialise(values)))
  }
}

fn canonical_cbor_key_compare(left: ByteArray, right: ByteArray) -> Ordering {
  let left_length = bytearray.length(left)
  let right_length = bytearray.length(right)

  if left_length < right_length {
    Less
  } else if left_length > right_length {
    Greater
  } else {
    bytearray.compare(left, right)
  }
}

fn insert_canonical_map_entry(
  entries: Pairs<ByteArray, ByteArray>,
  key: ByteArray,
  value: ByteArray,
) -> Pairs<ByteArray, ByteArray> {
  entries
    |> pairs.insert_by_ascending_key(key, value, canonical_cbor_key_compare)
}

fn insert_canonical_set_entry(
  entries: Pairs<ByteArray, ByteArray>,
  item: ByteArray,
) -> Pairs<ByteArray, ByteArray> {
  when entries is {
    [] -> [Pair(item, "")]
    [entry, ..tail] -> {
      let Pair(entry_item, _) = entry
      when bytearray.compare(item, entry_item) is {
        Less -> [Pair(item, ""), ..entries]
        Equal -> entries
        Greater -> [entry, ..insert_canonical_set_entry(tail, item)]
      }
    }
  }
}

/// Plutus maps preserve duplicate entries. Sort by canonical CBOR key while
/// retaining the source order of entries whose encoded keys are equal.
fn insert_stable_canonical_map_entry(
  entries: Pairs<ByteArray, ByteArray>,
  key: ByteArray,
  value: ByteArray,
) -> Pairs<ByteArray, ByteArray> {
  when entries is {
    [] -> [Pair(key, value)]
    [entry, ..tail] -> {
      let Pair(entry_key, _) = entry
      when canonical_cbor_key_compare(key, entry_key) is {
        Less -> [Pair(key, value), ..entries]
        _ -> [entry, ..insert_stable_canonical_map_entry(tail, key, value)]
      }
    }
  }
}

fn serialise_canonical_map_entries(
  entries: Pairs<ByteArray, ByteArray>,
) -> ByteArray {
  let length, body <- list.foldr2(
    entries,
    0,
    "",
    fn(entry, length, body, return) {
      return(
        length + 1,
        entry.1st
          |> bytearray.concat(entry.2nd)
          |> bytearray.concat(body),
      )
    },
  )

  serialise_cbor_head(5, length) |> bytearray.concat(body)
}

pub fn serialise_tx_inputs(
  inputs: List<a>,
  get_reference: fn(a) -> OutputReference,
) -> ByteArray {
  let length, body <- list.foldr2(
    inputs,
    0,
    "",
    fn(input, length, body, return) {
      return(
        length + 1,
        bytearray.concat(serialise_output_reference(get_reference(input)), body),
      )
    },
  )

  set_cbor_tag
    |> bytearray.concat(serialise_definite_list(length, body))
}

fn serialise_output_reference(ref: OutputReference) -> ByteArray {
  let OutputReference { transaction_id, output_index } = ref

  #"82"
    |> bytearray.concat(cbor.serialise(transaction_id))
    |> bytearray.concat(cbor.serialise(output_index))
}

pub fn serialise_tx_outputs(
  outputs: List<Output>,
  network_tag: Int,
  encode_inline_datums: Bool,
  return: fn(Int, ByteArray) -> result,
) -> result {
  let length, body <- list.foldr2(
    outputs,
    0,
    "",
    fn(output, length, body, return) {
      return(
        length + 1,
        bytearray.concat(
          serialise_tx_output(output, network_tag, encode_inline_datums),
          body,
        ),
      )
    },
  )

  return(length, serialise_definite_list(length, body))
}

/// With `encode_inline_datums = False`, encode only address and value, ignoring
/// the supplied datum. With `True`, encode a supplied inline datum or no datum;
/// datum hashes are unsupported in that mode. Reference scripts are always
/// omitted. A body-hash match authenticates the encoded shape of the actual
/// output; ignored witness fields are not authenticated.
pub fn serialise_tx_output(
  output: Output,
  network_tag: Int,
  encode_inline_datums: Bool,
) -> ByteArray {
  let Output { address, value, datum, .. } = output
  let serialised_address = serialise_address(address, network_tag)
  let serialised_value = serialise_output_value(value)
  let datum_to_encode = if encode_inline_datums {
    datum
  } else {
    NoDatum
  }

  when datum_to_encode is {
    NoDatum ->
      #"82"
        |> bytearray.concat(serialised_address)
        |> bytearray.concat(serialised_value)
    DatumHash(_) -> fail @"datum hashes are unsupported"
    InlineDatum(data) ->
      #"a3"
        |> bytearray.concat(#"00")
        |> bytearray.concat(serialised_address)
        |> bytearray.concat(#"01")
        |> bytearray.concat(serialised_value)
        |> bytearray.concat(
            serialise_inline_output_datum(serialise_plutus_data(data, False)),
          )
  }
}

fn serialise_verification_key_hash_set(
  hashes: List<VerificationKeyHash>,
) -> ByteArray {
  let entries = list.foldl(
    hashes,
    [],
    fn(hash, entries) {
      insert_canonical_set_entry(entries, serialise_cbor_bytes(hash))
    },
  )
  let length, body <- serialise_set_entries(entries)
  set_cbor_tag
    |> bytearray.concat(serialise_definite_list(length, body))
}

fn serialise_set_entries(
  entries: Pairs<ByteArray, ByteArray>,
  return: fn(Int, ByteArray) -> result,
) -> result {
  list.foldr2(
    entries,
    0,
    "",
    fn(entry, length, body, next) {
      next(length + 1, entry.1st |> bytearray.concat(body))
    },
    return,
  )
}

pub fn serialise_cbor_text(text: ByteArray) -> ByteArray {
  serialise_cbor_head(3, bytearray.length(text)) |> bytearray.concat(text)
}

pub fn serialise_reward_account(
  network_tag: Int,
  credential: Credential,
) -> ByteArray {
  let bytes = when credential is {
    VerificationKey(hash) -> builtin.cons_bytearray(0xe0 + network_tag, hash)
    Script(hash) -> builtin.cons_bytearray(0xf0 + network_tag, hash)
  }
  serialise_cbor_bytes(bytes)
}

pub fn serialise_withdrawals(
  withdrawals: Pairs<Credential, Lovelace>,
  network_tag: Int,
) -> ByteArray {
  let entries = list.foldl(
    withdrawals,
    [],
    fn(withdrawal, entries) {
      let Pair(credential, amount) = withdrawal
      entries
        |> insert_canonical_map_entry(
            serialise_reward_account(network_tag, credential),
            cbor.serialise(amount),
          )
    },
  )
  serialise_canonical_map_entries(entries)
}

pub fn serialise_governance_action_id(
  action_id: GovernanceActionId,
) -> ByteArray {
  let GovernanceActionId { transaction, proposal_procedure } = action_id
  serialise_list_of_two(
    serialise_cbor_bytes(transaction),
    cbor.serialise(proposal_procedure),
  )
}

fn serialise_inline_output_datum(data: ByteArray) -> ByteArray {
  #"02"
    |> bytearray.concat(#"8201")
    |> bytearray.concat(#"d818")
    |> bytearray.concat(serialise_cbor_bytes(data))
}

/// Encode Plutus Data using definite collections and chunked long byte strings.
/// Set `preserve_map_order` for witness Data that is used after hash
/// authentication: every map retains its exact entry order, including duplicates.
/// Otherwise maps are sorted canonically, preserving duplicate-key order, for
/// reconstruction profiles that require canonical maps.
pub fn serialise_plutus_data(data: Data, preserve_map_order: Bool) -> ByteArray {
  builtin.choose_data(
    data,
    serialise_plutus_constr_data(data, preserve_map_order),
    serialise_plutus_map_data(data, preserve_map_order),
    serialise_plutus_list_data(data, preserve_map_order),
    cbor.serialise(builtin.un_i_data(data)),
    serialise_plutus_bytearray(builtin.un_b_data(data)),
  )
}

fn serialise_plutus_constr_data(
  data: Data,
  preserve_map_order: Bool,
) -> ByteArray {
  let Pair(constructor, fields) = builtin.un_constr_data(data)
  let serialised_fields = serialise_plutus_data_list(fields, preserve_map_order)

  if constructor < 7 {
    serialise_cbor_tag(121 + constructor)
      |> bytearray.concat(serialised_fields)
  } else if constructor < 128 {
    serialise_cbor_tag(1280 + constructor - 7)
      |> bytearray.concat(serialised_fields)
  } else {
    general_plutus_data_constructor_cbor_tag
      |> bytearray.concat(
          serialise_list_of_two(cbor.serialise(constructor), serialised_fields),
        )
  }
}

fn serialise_plutus_list_data(data: Data, preserve_map_order: Bool) -> ByteArray {
  serialise_plutus_data_list(builtin.un_list_data(data), preserve_map_order)
}

fn serialise_plutus_map_data(data: Data, preserve_map_order: Bool) -> ByteArray {
  if preserve_map_order {
    let length, body <- list.foldr2(
      builtin.un_map_data(data),
      0,
      "",
      fn(pair, length, body, return) {
        let Pair(key, value) = pair
        return(
          length + 1,
          serialise_plutus_data(key, True)
            |> bytearray.concat(serialise_plutus_data(value, True))
            |> bytearray.concat(body),
        )
      },
    )
    serialise_cbor_head(5, length) |> bytearray.concat(body)
  } else {
    let entries = list.foldl(
      builtin.un_map_data(data),
      [],
      fn(pair, entries) {
        let Pair(key, value) = pair
        entries
          |> insert_stable_canonical_map_entry(
              serialise_plutus_data(key, False),
              serialise_plutus_data(value, False),
            )
      },
    )
    serialise_canonical_map_entries(entries)
  }
}

fn serialise_plutus_data_list(
  items: List<Data>,
  preserve_map_order: Bool,
) -> ByteArray {
  let length, body <- list.foldr2(
    items,
    0,
    "",
    fn(item, length, body, return) {
      return(
        length + 1,
        serialise_plutus_data(item, preserve_map_order)
          |> bytearray.concat(body),
      )
    },
  )

  serialise_cbor_head(4, length) |> bytearray.concat(body)
}

fn serialise_plutus_bytearray(bytes: ByteArray) -> ByteArray {
  let length = bytearray.length(bytes)

  if length <= 64 {
    serialise_cbor_bytes(bytes)
  } else {
    #"5f"
      |> bytearray.concat(serialise_plutus_bytearray_chunks(bytes, 0, length))
      |> bytearray.concat(#"ff")
  }
}

fn serialise_plutus_bytearray_chunks(
  bytes: ByteArray,
  cursor: Int,
  length: Int,
) -> ByteArray {
  if cursor >= length {
    ""
  } else {
    let chunk_length = if length - cursor > 64 {
      64
    } else {
      length - cursor
    }

    serialise_cbor_bytes(builtin.slice_bytearray(cursor, chunk_length, bytes))
      |> bytearray.concat(
          serialise_plutus_bytearray_chunks(
            bytes,
            cursor + chunk_length,
            length,
          ),
        )
  }
}

pub fn serialise_cbor_bytes(bytes: ByteArray) -> ByteArray {
  serialise_cbor_head(2, bytearray.length(bytes)) |> bytearray.concat(bytes)
}

fn serialise_cbor_tag(tag: Int) -> ByteArray {
  serialise_cbor_head(6, tag)
}

pub fn serialise_cbor_head(major_type: Int, argument: Int) -> ByteArray {
  let major = major_type * 32

  if argument < 24 {
    builtin.cons_bytearray(major + argument, #"")
  } else if argument <= 255 {
    builtin.cons_bytearray(
      major + 24,
      bytearray.from_int_big_endian(argument, 1),
    )
  } else if argument <= 65535 {
    builtin.cons_bytearray(
      major + 25,
      bytearray.from_int_big_endian(argument, 2),
    )
  } else if argument <= 4294967295 {
    builtin.cons_bytearray(
      major + 26,
      bytearray.from_int_big_endian(argument, 4),
    )
  } else {
    builtin.cons_bytearray(
      major + 27,
      bytearray.from_int_big_endian(argument, 8),
    )
  }
}

fn serialise_output_value(value: Assets) -> ByteArray {
  let lovelace = value |> assets.lovelace_of |> cbor.serialise
  let non_ada = value |> assets.without_lovelace

  if non_ada == assets.zero {
    lovelace
  } else {
    #"82"
      |> bytearray.concat(lovelace)
      |> bytearray.concat(serialise_multiasset(non_ada))
  }
}

pub fn serialise_mint(mint: Assets) -> ByteArray {
  serialise_multiasset(mint)
}

fn serialise_multiasset(value: Assets) -> ByteArray {
  let entries = value
    |> assets.to_dict
    |> dict.to_pairs
    |> list.foldl(
        [],
        fn(policy_entry, entries) {
          let Pair(policy, tokens) = policy_entry
          entries
            |> insert_canonical_map_entry(
                serialise_cbor_bytes(policy),
                tokens |> dict.to_pairs |> serialise_asset_quantities,
              )
        },
      )
  serialise_canonical_map_entries(entries)
}

fn serialise_asset_quantities(tokens: Pairs<AssetName, Int>) -> ByteArray {
  let entries = list.foldl(
    tokens,
    [],
    fn(token, entries) {
      let Pair(asset_name, quantity) = token
      entries
        |> insert_canonical_map_entry(
            serialise_cbor_bytes(asset_name),
            cbor.serialise(quantity),
          )
    },
  )
  serialise_canonical_map_entries(entries)
}

fn serialise_address(address: Address, network_tag: Int) -> ByteArray {
  let Address { payment_credential, stake_credential } = address

  let payment_header, payment_credential_bytes <- when payment_credential is {
    Script(credential) ->
      fn(return) { return(16, credential) }
    VerificationKey(credential) ->
      fn(return) { return(0, credential) }
  }

  let stake_header, stake_credential_bytes <- when stake_credential is {
    None ->
      fn(return) { return(96, "") }
    Some(Inline(VerificationKey(credential))) ->
      fn(return) { return(0, credential) }
    Some(Inline(Script(credential))) ->
      fn(return) { return(32, credential) }
    Some(Pointer { slot_number, transaction_index, certificate_index }) ->
      fn(return) {
        return(
          64,
          serialise_variable_length_uint(slot_number)
            |> bytearray.concat(
                serialise_variable_length_uint(transaction_index),
              )
            |> bytearray.concat(
                serialise_variable_length_uint(certificate_index),
              ),
        )
      }
  }

  builtin.cons_bytearray(
    payment_header + stake_header + network_tag,
    bytearray.concat(payment_credential_bytes, stake_credential_bytes),
  )
    |> cbor.serialise
}

fn serialise_variable_length_uint(value: Int) -> ByteArray {
  do_serialise_variable_length_uint(value, True, "")
}

fn do_serialise_variable_length_uint(
  value: Int,
  is_last_group: Bool,
  suffix: ByteArray,
) -> ByteArray {
  let group = value % 128
  let remaining = value / 128
  let byte = if is_last_group {
    group
  } else {
    group + 128
  }
  let bytes = builtin.cons_bytearray(byte, suffix)

  if remaining == 0 {
    bytes
  } else {
    do_serialise_variable_length_uint(remaining, False, bytes)
  }
}

pub fn serialise_extra_signatories(
  extra_signatories: List<VerificationKeyHash>,
) -> ByteArray {
  serialise_verification_key_hash_set(extra_signatories)
}

fn serialise_definite_list(length: Int, body: ByteArray) -> ByteArray {
  serialise_cbor_head(4, length) |> bytearray.concat(body)
}
