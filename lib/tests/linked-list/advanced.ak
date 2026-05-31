use aiken/builtin
use aiken/collection/dict
use aiken/crypto.{ScriptHash, blake2b_224, blake2b_256}
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list.{
  Element, Node, Root, run_element_with, run_node_with, run_root_with,
  spend_for_adding_or_removing_an_element,
}
use aiken_design_patterns/linked_list/advanced.{
  ElementInfo, NodeElementInfo, RootElementInfo, append_unordered, deinit,
  fold_from_root, get_element_info, get_node_element_info, get_root_element_info,
  init, insert_ascending, insert_descending, prepend_unordered, remove,
  spend_for_updating_elements_data,
}
use aiken_design_patterns/linked_list/internal.{
  validate_no_reserved_list_asset_changes,
}
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId, Value}
use cardano/transaction.{InlineDatum, Input, Output, OutputReference}

const min_lovelace = 2_000_000

const test_root_key = #""

const extra_asset_name = #"6578747261"

const b_data = builtin.b_data(#"00")

const test_node_key_prefix = #"4e"

const test_node_key_prefix_length = bytearray.length(test_node_key_prefix)

const new_node_key = #"01"

fn script_output(
  list_nft_policy_id: PolicyId,
  asset_name: ByteArray,
  element: Element<Data, Data>,
) -> Output {
  script_output_with_reference(list_nft_policy_id, asset_name, element, None)
}

fn script_output_with_reference(
  list_nft_policy_id: PolicyId,
  asset_name: ByteArray,
  element: Element<Data, Data>,
  reference_script: Option<ScriptHash>,
) -> Output {
  Output {
    address: Address {
      payment_credential: Script(list_nft_policy_id),
      stake_credential: None,
    },
    value: assets.from_lovelace(min_lovelace)
      |> assets.merge(assets.from_asset(list_nft_policy_id, asset_name, 1)),
    datum: InlineDatum(element),
    reference_script,
  }
}

fn advanced_insert_fixture(
  script_hash: PolicyId,
  extra_asset_change: Value,
  expected_extra_asset_name: ByteArray,
  expected_extra_qty: Int,
) -> Bool {
  let new_node_asset_name = test_node_key_prefix
    |> bytearray.concat(new_node_key)
  let root_input = Input {
    output_reference: OutputReference {
      transaction_id: blake2b_256(#"726f6f74"),
      output_index: 0,
    },
    output: script_output(
      script_hash,
      test_root_key,
      Element { data: Root(b_data), link: None },
    ),
  }
  let continued_root_output = script_output(
    script_hash,
    test_root_key,
    Element { data: Root(b_data), link: Some(new_node_key) },
  )
  let new_node_output = script_output(
    script_hash,
    new_node_asset_name,
    Element { data: Node(b_data), link: None },
  )
  let structural_mint = assets.from_asset(script_hash, new_node_asset_name, 1)
  insert_ascending(
    continued_root_output,
    new_node_output,
    [root_input],
    structural_mint |> assets.merge(extra_asset_change),
    fn(
      _anchor_input,
      _anchor_lovelace_change,
      _anchor_key,
      _anchor_data,
      _continued_anchor_data,
      _new_node_lovelace,
      _new_node_key,
      _new_node_data,
      _new_node_link,
      _new_node_ref_script,
      other_list_assets,
    ) {
      expect Some(qty) = dict.get(other_list_assets, expected_extra_asset_name)
      qty == expected_extra_qty
    },
  )
    |> run_element_with(
        script_hash,
        test_root_key,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}

test success__init__reference_script() {
  let script_hash = blake2b_224(#"ad")
  let reference_script_hash = blake2b_224(script_hash)
  let root_mint = assets.from_asset(script_hash, test_root_key, 1)
  let script_output = Output {
    address: Address {
      payment_credential: Script(script_hash),
      stake_credential: None,
    },
    value: assets.from_lovelace(min_lovelace) |> assets.merge(root_mint),
    datum: InlineDatum(Element { data: Root(b_data), link: None }),
    reference_script: Some(reference_script_hash),
  }

  init(
    True,
    script_output,
    root_mint,
    fn(element_address, lovelace, root_data, ref_script) {
      and {
        element_address == script_output.address,
        lovelace == min_lovelace,
        root_data == b_data,
        ref_script == Some(reference_script_hash),
      }
    },
  )
    |> run_root_with(script_hash, test_root_key)
}

test success__deinit__passes_callback_data() {
  let script_hash = blake2b_224(#"ad")
  let root_input = Input {
    output_reference: OutputReference {
      transaction_id: blake2b_256(#"6164762d6465696e6974"),
      output_index: 0,
    },
    output: script_output(
      script_hash,
      test_root_key,
      Element { data: Root(b_data), link: None },
    ),
  }

  {
    let actual_root_input, root_lovelace, root_data <- deinit(
      [root_input],
      assets.from_asset(script_hash, test_root_key, -1),
    )
    and {
      actual_root_input.output_reference == root_input.output_reference,
      root_lovelace == min_lovelace,
      root_data == b_data,
    }
  }
    |> run_root_with(script_hash, test_root_key)
}

test success__get_element_info__root_reference_script() {
  let script_hash = blake2b_224(#"ad")
  let reference_script_hash = Some(blake2b_224(#"726f6f742d726566"))
  let root_output = script_output_with_reference(
    script_hash,
    test_root_key,
    Element { data: Root(b_data), link: None },
    reference_script_hash,
  )
  let info_callback: ElementInfo<Bool> = fn(
    element_address,
    lovelace,
    m_node_key,
    data,
    link,
    ref_script,
  ) {
    and {
      element_address == root_output.address,
      lovelace == min_lovelace,
      m_node_key == None,
      data == b_data,
      link == None,
      ref_script == reference_script_hash,
    }
  }

  get_element_info(root_output, info_callback)
    |> run_element_with(
        script_hash,
        test_root_key,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}

test success__get_root_element_info__reference_script() {
  let script_hash = blake2b_224(#"ad")
  let reference_script_hash = Some(blake2b_224(#"726f6f742d726566"))
  let root_output = script_output_with_reference(
    script_hash,
    test_root_key,
    Element { data: Root(b_data), link: None },
    reference_script_hash,
  )
  let info_callback: RootElementInfo<Bool> = fn(
    element_address,
    lovelace,
    data,
    link,
    ref_script,
  ) {
    and {
      element_address == root_output.address,
      lovelace == min_lovelace,
      data == b_data,
      link == None,
      ref_script == reference_script_hash,
    }
  }

  get_root_element_info(root_output, info_callback)
    |> run_root_with(script_hash, test_root_key)
}

test success__get_node_element_info__reference_script() {
  let script_hash = blake2b_224(#"ad")
  let node_key = #"01"
  let node_asset_name = test_node_key_prefix |> bytearray.concat(node_key)
  let node_link = Some(#"02")
  let reference_script_hash = Some(blake2b_224(#"6e6f64652d726566"))
  let node_output = script_output_with_reference(
    script_hash,
    node_asset_name,
    Element { data: Node(b_data), link: node_link },
    reference_script_hash,
  )
  let info_callback: NodeElementInfo<Bool> = fn(
    element_address,
    lovelace,
    callback_node_key,
    data,
    link,
    ref_script,
  ) {
    and {
      element_address == node_output.address,
      lovelace == min_lovelace,
      callback_node_key == node_key,
      data == b_data,
      link == node_link,
      ref_script == reference_script_hash,
    }
  }

  get_node_element_info(node_output, info_callback)
    |> run_node_with(
        script_hash,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}

test success__base_spend_helper_detects_same_policy_change() {
  let script_hash = blake2b_224(#"ad")
  let node_asset_name = #"4e4f4445"
  let structural_mint = assets.from_asset(script_hash, node_asset_name, 1)
  let extra_mint = assets.from_asset(script_hash, extra_asset_name, 1)

  spend_for_adding_or_removing_an_element(
    script_hash,
    structural_mint |> assets.merge(extra_mint),
  )
}

test fail__rejects_extra_node_namespace_change() fail {
  validate_no_reserved_list_asset_changes(
    dict.from_pairs([Pair(#"4e01", 1)]),
    test_root_key,
    test_node_key_prefix,
    test_node_key_prefix_length,
  )
}

test fail__rejects_extra_root_key_change() fail {
  validate_no_reserved_list_asset_changes(
    dict.from_pairs([Pair(test_root_key, 1)]),
    test_root_key,
    test_node_key_prefix,
    test_node_key_prefix_length,
  )
}

test success__insert_ascending__same_policy_extra_mint() {
  let script_hash = blake2b_224(#"ad")
  advanced_insert_fixture(
    script_hash,
    assets.from_asset(script_hash, extra_asset_name, 1),
    extra_asset_name,
    1,
  )
}

test success__insert_ascending__same_policy_extra_burn() {
  let script_hash = blake2b_224(#"ad")
  advanced_insert_fixture(
    script_hash,
    assets.from_asset(script_hash, extra_asset_name, -1),
    extra_asset_name,
    -1,
  )
}

test success__insert_ascending__node_anchor_continued_data_and_extra_mint() {
  let script_hash = blake2b_224(#"ad")
  let anchor_node_key = #"00"
  let successor_node_key = #"02"
  let anchor_node_asset_name = test_node_key_prefix
    |> bytearray.concat(anchor_node_key)
  let new_node_asset_name = test_node_key_prefix
    |> bytearray.concat(new_node_key)
  let continued_anchor_data = builtin.b_data(#"01")
  let anchor_input = Input {
    output_reference: OutputReference {
      transaction_id: blake2b_256(#"616e63686f72"),
      output_index: 0,
    },
    output: script_output(
      script_hash,
      anchor_node_asset_name,
      Element { data: Node(b_data), link: Some(successor_node_key) },
    ),
  }
  let continued_anchor_output = script_output(
    script_hash,
    anchor_node_asset_name,
    Element { data: Node(continued_anchor_data), link: Some(new_node_key) },
  )
  let new_node_output = script_output(
    script_hash,
    new_node_asset_name,
    Element { data: Node(b_data), link: Some(successor_node_key) },
  )
  let tx_mint = assets.from_asset(script_hash, new_node_asset_name, 1)
    |> assets.merge(assets.from_asset(script_hash, extra_asset_name, 1))

  insert_ascending(
    continued_anchor_output,
    new_node_output,
    [anchor_input],
    tx_mint,
    fn(
      _anchor_input,
      _anchor_lovelace_change,
      anchor_key,
      spent_anchor_data,
      cont_anchor_data,
      _new_node_lovelace,
      _new_node_key,
      _new_node_data,
      _new_node_link,
      _new_node_ref_script,
      other_list_assets,
    ) {
      expect Some(qty) = dict.get(other_list_assets, extra_asset_name)
      and {
        anchor_key == Some(anchor_node_key),
        spent_anchor_data == b_data,
        cont_anchor_data == continued_anchor_data,
        qty == 1,
      }
    },
  )
    |> run_element_with(
        script_hash,
        test_root_key,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}

test success__insert_ascending__preserves_anchor_reference_script() {
  let script_hash = blake2b_224(#"ad")
  let anchor_ref_script = Some(blake2b_224(#"616e63686f722d726566"))
  let new_node_ref_script = Some(blake2b_224(#"6e65772d6e6f64652d726566"))
  let new_node_asset_name = test_node_key_prefix
    |> bytearray.concat(new_node_key)
  let root_input = Input {
    output_reference: OutputReference {
      transaction_id: blake2b_256(#"726f6f742d726566"),
      output_index: 0,
    },
    output: script_output_with_reference(
      script_hash,
      test_root_key,
      Element { data: Root(b_data), link: None },
      anchor_ref_script,
    ),
  }
  let continued_root_output = script_output_with_reference(
    script_hash,
    test_root_key,
    Element { data: Root(b_data), link: Some(new_node_key) },
    anchor_ref_script,
  )
  let new_node_output = script_output_with_reference(
    script_hash,
    new_node_asset_name,
    Element { data: Node(b_data), link: None },
    new_node_ref_script,
  )

  insert_ascending(
    continued_root_output,
    new_node_output,
    [root_input],
    assets.from_asset(script_hash, new_node_asset_name, 1),
    fn(
      _anchor_input,
      _anchor_lovelace_change,
      _anchor_key,
      _anchor_data,
      _continued_anchor_data,
      _new_node_lovelace,
      _new_node_key,
      _new_node_data,
      _new_node_link,
      callback_new_node_ref_script,
      other_list_assets,
    ) {
      and {
        callback_new_node_ref_script == new_node_ref_script,
        dict.is_empty(other_list_assets),
      }
    },
  )
    |> run_element_with(
        script_hash,
        test_root_key,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}

test success__insert_descending__reference_script_and_extra_mint() {
  let script_hash = blake2b_224(#"ad")
  let new_node_ref_script = Some(blake2b_224(#"646573632d6e65772d726566"))
  let new_node_asset_name = test_node_key_prefix
    |> bytearray.concat(new_node_key)
  let root_input = Input {
    output_reference: OutputReference {
      transaction_id: blake2b_256(#"646573632d726f6f74"),
      output_index: 0,
    },
    output: script_output(
      script_hash,
      test_root_key,
      Element { data: Root(b_data), link: None },
    ),
  }
  let continued_root_output = script_output(
    script_hash,
    test_root_key,
    Element { data: Root(b_data), link: Some(new_node_key) },
  )
  let new_node_output = script_output_with_reference(
    script_hash,
    new_node_asset_name,
    Element { data: Node(b_data), link: None },
    new_node_ref_script,
  )
  let tx_mint = assets.from_asset(script_hash, new_node_asset_name, 1)
    |> assets.merge(assets.from_asset(script_hash, extra_asset_name, 1))

  insert_descending(
    continued_root_output,
    new_node_output,
    [root_input],
    tx_mint,
    fn(
      _anchor_input,
      _anchor_lovelace_change,
      anchor_key,
      _spent_anchor_data,
      _cont_anchor_data,
      _new_node_lovelace,
      callback_new_node_key,
      _new_node_data,
      new_node_link,
      callback_new_node_ref_script,
      other_list_assets,
    ) {
      expect Some(extra_qty) = dict.get(other_list_assets, extra_asset_name)
      and {
        anchor_key == None,
        callback_new_node_key == new_node_key,
        new_node_link == None,
        callback_new_node_ref_script == new_node_ref_script,
        extra_qty == 1,
      }
    },
  )
    |> run_element_with(
        script_hash,
        test_root_key,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}

test success__append_unordered__reference_script_and_extra_mint() {
  let script_hash = blake2b_224(#"ad")
  let new_node_ref_script = Some(blake2b_224(#"617070656e642d726566"))
  let new_node_asset_name = test_node_key_prefix
    |> bytearray.concat(new_node_key)
  let root_input = Input {
    output_reference: OutputReference {
      transaction_id: blake2b_256(#"617070656e642d726f6f74"),
      output_index: 0,
    },
    output: script_output(
      script_hash,
      test_root_key,
      Element { data: Root(b_data), link: None },
    ),
  }
  let continued_root_output = script_output(
    script_hash,
    test_root_key,
    Element { data: Root(b_data), link: Some(new_node_key) },
  )
  let new_node_output = script_output_with_reference(
    script_hash,
    new_node_asset_name,
    Element { data: Node(b_data), link: None },
    new_node_ref_script,
  )
  let tx_mint = assets.from_asset(script_hash, new_node_asset_name, 1)
    |> assets.merge(assets.from_asset(script_hash, extra_asset_name, 1))

  append_unordered(
    continued_root_output,
    new_node_output,
    [root_input],
    tx_mint,
    fn(
      _anchor_input,
      _anchor_lovelace_change,
      anchor_key,
      _spent_anchor_data,
      _cont_anchor_data,
      _new_node_lovelace,
      callback_new_node_key,
      _new_node_data,
      callback_new_node_ref_script,
      other_list_assets,
    ) {
      expect Some(extra_qty) = dict.get(other_list_assets, extra_asset_name)
      and {
        anchor_key == None,
        callback_new_node_key == new_node_key,
        callback_new_node_ref_script == new_node_ref_script,
        extra_qty == 1,
      }
    },
  )
    |> run_element_with(
        script_hash,
        test_root_key,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}

test success__prepend_unordered__reference_script_and_extra_burn() {
  let script_hash = blake2b_224(#"ad")
  let existing_first_node_key = #"02"
  let new_node_ref_script = Some(blake2b_224(#"70726570656e642d726566"))
  let new_node_asset_name = test_node_key_prefix
    |> bytearray.concat(new_node_key)
  let root_input = Input {
    output_reference: OutputReference {
      transaction_id: blake2b_256(#"70726570656e642d726f6f74"),
      output_index: 0,
    },
    output: script_output(
      script_hash,
      test_root_key,
      Element { data: Root(b_data), link: Some(existing_first_node_key) },
    ),
  }
  let continued_root_output = script_output(
    script_hash,
    test_root_key,
    Element { data: Root(b_data), link: Some(new_node_key) },
  )
  let new_node_output = script_output_with_reference(
    script_hash,
    new_node_asset_name,
    Element { data: Node(b_data), link: Some(existing_first_node_key) },
    new_node_ref_script,
  )
  let tx_mint = assets.from_asset(script_hash, new_node_asset_name, 1)
    |> assets.merge(assets.from_asset(script_hash, extra_asset_name, -1))

  prepend_unordered(
    continued_root_output,
    new_node_output,
    [root_input],
    tx_mint,
    fn(
      _root_input,
      _root_lovelace_change,
      _spent_root_data,
      _cont_root_data,
      _new_node_lovelace,
      callback_new_node_key,
      _new_node_data,
      new_node_link,
      callback_new_node_ref_script,
      other_list_assets,
    ) {
      expect Some(extra_qty) = dict.get(other_list_assets, extra_asset_name)
      and {
        callback_new_node_key == new_node_key,
        new_node_link == Some(existing_first_node_key),
        callback_new_node_ref_script == new_node_ref_script,
        extra_qty == -1,
      }
    },
  )
    |> run_element_with(
        script_hash,
        test_root_key,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}

test fail__insert_ascending__rejects_extra_node_prefix_asset_change() fail {
  let script_hash = blake2b_224(#"ad")
  let node_prefixed_extra = test_node_key_prefix |> bytearray.concat(#"ff")
  advanced_insert_fixture(
    script_hash,
    assets.from_asset(script_hash, node_prefixed_extra, 1),
    node_prefixed_extra,
    1,
  )
}

test fail__insert_ascending__rejects_extra_root_key_change() fail {
  let script_hash = blake2b_224(#"ad")
  advanced_insert_fixture(
    script_hash,
    assets.from_asset(script_hash, test_root_key, 1),
    test_root_key,
    1,
  )
}

test success__remove__anchor_removed_data_and_extra_asset_change() {
  let script_hash = blake2b_224(#"ad")
  let removed_node_asset_name = test_node_key_prefix
    |> bytearray.concat(new_node_key)
  let successor_node_key = #"03"
  let continued_anchor_data = builtin.b_data(#"01")
  let removed_node_data = builtin.b_data(#"02")
  let root_input = Input {
    output_reference: OutputReference {
      transaction_id: blake2b_256(#"726f6f742d72656d6f7665"),
      output_index: 0,
    },
    output: script_output(
      script_hash,
      test_root_key,
      Element { data: Root(b_data), link: Some(new_node_key) },
    ),
  }
  let removed_node_input = Input {
    output_reference: OutputReference {
      transaction_id: blake2b_256(#"6e6f64652d72656d6f7665"),
      output_index: 0,
    },
    output: script_output(
      script_hash,
      removed_node_asset_name,
      Element { data: Node(removed_node_data), link: Some(successor_node_key) },
    ),
  }
  let continued_root_output = script_output(
    script_hash,
    test_root_key,
    Element {
      data: Root(continued_anchor_data),
      link: Some(successor_node_key),
    },
  )
  let tx_mint = assets.from_asset(script_hash, removed_node_asset_name, -1)
    |> assets.merge(assets.from_asset(script_hash, extra_asset_name, 1))

  remove(
    root_input.output_reference,
    continued_root_output,
    [root_input, removed_node_input],
    tx_mint,
    fn(
      _anchor_input,
      _anchor_lovelace_change,
      anchor_key,
      spent_anchor_data,
      cont_anchor_data,
      _removing_node_input,
      _removing_node_lovelace,
      removing_node_key,
      callback_removed_node_data,
      removing_node_link,
      other_list_assets,
    ) {
      expect Some(extra_qty) = dict.get(other_list_assets, extra_asset_name)
      and {
        anchor_key == None,
        spent_anchor_data == b_data,
        cont_anchor_data == continued_anchor_data,
        removing_node_key == new_node_key,
        callback_removed_node_data == removed_node_data,
        removing_node_link == Some(successor_node_key),
        extra_qty == 1,
      }
    },
  )
    |> run_element_with(
        script_hash,
        test_root_key,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}

test success__fold_from_root__extra_asset_change() {
  let script_hash = blake2b_224(#"ad")
  let folded_node_asset_name = test_node_key_prefix
    |> bytearray.concat(new_node_key)
  let continued_root_data = builtin.b_data(#"03")
  let root_ref_script = Some(blake2b_224(#"666f6c642d726f6f742d726566"))
  let root_input = Input {
    output_reference: OutputReference {
      transaction_id: blake2b_256(#"666f6c642d726f6f74"),
      output_index: 0,
    },
    output: script_output_with_reference(
      script_hash,
      test_root_key,
      Element { data: Root(b_data), link: Some(new_node_key) },
      root_ref_script,
    ),
  }
  let folded_node_input = Input {
    output_reference: OutputReference {
      transaction_id: blake2b_256(#"666f6c642d6e6f6465"),
      output_index: 1,
    },
    output: script_output(
      script_hash,
      folded_node_asset_name,
      Element { data: Node(b_data), link: None },
    ),
  }
  let continued_root_output = script_output_with_reference(
    script_hash,
    test_root_key,
    Element { data: Root(continued_root_data), link: None },
    root_ref_script,
  )
  let tx_mint = assets.from_asset(script_hash, folded_node_asset_name, -1)
    |> assets.merge(assets.from_asset(script_hash, extra_asset_name, 1))

  fold_from_root(
    root_input.output_reference,
    continued_root_output,
    [root_input, folded_node_input],
    tx_mint,
    fn(
      _root_input,
      _root_lovelace_change,
      _spent_root_data,
      _folded_node_input,
      _folded_node_lovelace,
      folded_node_key,
      _folded_node_data,
      folded_node_link,
      callback_continued_root_data,
      other_list_assets,
    ) {
      expect Some(extra_qty) = dict.get(other_list_assets, extra_asset_name)
      and {
        folded_node_key == new_node_key,
        folded_node_link == None,
        callback_continued_root_data == continued_root_data,
        extra_qty == 1,
      }
    },
  )
    |> run_element_with(
        script_hash,
        test_root_key,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}

test success__spend_for_updating_elements_data__reference_scripts() {
  let script_hash = blake2b_224(#"ad")
  let old_data = builtin.b_data(#"04")
  let new_data = builtin.b_data(#"05")
  let old_ref_script = Some(blake2b_224(#"7570646174652d6f6c642d726566"))
  let new_ref_script = Some(blake2b_224(#"7570646174652d6e65772d726566"))
  let root_input = Input {
    output_reference: OutputReference {
      transaction_id: blake2b_256(#"7570646174652d726f6f74"),
      output_index: 0,
    },
    output: script_output_with_reference(
      script_hash,
      test_root_key,
      Element { data: Root(old_data), link: None },
      old_ref_script,
    ),
  }
  let continued_root_output = script_output_with_reference(
    script_hash,
    test_root_key,
    Element { data: Root(new_data), link: None },
    new_ref_script,
  )

  spend_for_updating_elements_data(
    0,
    0,
    root_input.output_reference,
    [root_input],
    [continued_root_output],
    assets.zero,
    fn(
      element_address,
      lovelace_change,
      element_key,
      callback_old_data,
      callback_old_ref_script,
      callback_new_data,
      callback_new_ref_script,
      link,
    ) {
      and {
        element_address == root_input.output.address,
        lovelace_change == 0,
        element_key == None,
        callback_old_data == old_data,
        callback_old_ref_script == old_ref_script,
        callback_new_data == new_data,
        callback_new_ref_script == new_ref_script,
        link == None,
      }
    },
  )
    |> run_element_with(
        script_hash,
        test_root_key,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}

test fail__remove__rejects_changed_anchor_reference_script() fail {
  let script_hash = blake2b_224(#"ad")
  let reference_script_hash = blake2b_224(script_hash)
  let changed_ref_script = blake2b_224(#"6368616e6765642d726566")
  let node_asset_name = test_node_key_prefix |> bytearray.concat(new_node_key)
  let root_input = Input {
    output_reference: OutputReference {
      transaction_id: blake2b_256(#"726f6f74"),
      output_index: 0,
    },
    output: Output {
      ..script_output(
        script_hash,
        test_root_key,
        Element { data: Root(b_data), link: Some(new_node_key) },
      ),
      reference_script: Some(reference_script_hash),
    },
  }
  let node_input = Input {
    output_reference: OutputReference {
      transaction_id: blake2b_256(#"6e6f6465"),
      output_index: 0,
    },
    output: script_output(
      script_hash,
      node_asset_name,
      Element { data: Node(b_data), link: None },
    ),
  }
  let continued_root_output = Output {
    ..script_output(
      script_hash,
      test_root_key,
      Element { data: Root(b_data), link: None },
    ),
    reference_script: Some(changed_ref_script),
  }
  remove(
    root_input.output_reference,
    continued_root_output,
    [root_input, node_input],
    assets.from_asset(script_hash, node_asset_name, -1),
    fn(
      _anchor_input,
      _anchor_lovelace_change,
      _anchor_key,
      _anchor_data,
      _continued_anchor_data,
      _removing_node_input,
      _removing_node_lovelace,
      _removing_node_key,
      _removing_node_data,
      _removing_node_link,
      _other_list_assets,
    ) {
      True
    },
  )
    |> run_element_with(
        script_hash,
        test_root_key,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}
