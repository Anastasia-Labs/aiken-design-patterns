use aiken/builtin
use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken/fuzz
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list.{
  ElementEval, NodeEval, RootEval, run_element_with, run_node_with,
  run_root_with,
}
use aiken_design_patterns/linked_list/nested.{
  Ascending, Descending, Element, InnerRoot, ListOrdering, Node, Root,
  Unordered, ascending_insert_of_inner_list, deinit,
  descending_insert_of_inner_list, init, insert_into_inner_list,
}
use aiken_design_patterns/utils
use cardano/address.{Address, Script}
use cardano/assets
use cardano/assets.{AssetName, Value}
use cardano/transaction.{InlineDatum, Input, Output, OutputReference}

type GenericElement =
  Element<Data, Data, Data>

type InitArgs {
  InitArgs {
    script_hash: ScriptHash,
    root_output: Output,
    tx_mint: Value,
    root_data: Data,
    root_ref_script: Option<ScriptHash>,
  }
}

type DeinitArgs {
  DeinitArgs {
    script_hash: ScriptHash,
    root_input: Input,
    inputs: List<Input>,
    tx_mint: Value,
    root_data: Data,
  }
}

type InnerRootInsertArgs {
  InnerRootInsertArgs {
    script_hash: ScriptHash,
    ordering: ListOrdering,
    anchor_input: Input,
    inputs: List<Input>,
    continued_anchor_output: Output,
    new_node_output: Output,
    tx_mint: Value,
    anchor_key: ByteArray,
    anchor_data: Data,
    anchor_link: Option<ByteArray>,
    new_node_key: ByteArray,
    new_node_data: Data,
    new_node_link: Option<ByteArray>,
    new_node_ref_script: Option<ScriptHash>,
  }
}

type NodeInsertArgs {
  NodeInsertArgs {
    script_hash: ScriptHash,
    ordering: ListOrdering,
    anchor_input: Input,
    inputs: List<Input>,
    continued_anchor_output: Output,
    new_node_output: Output,
    tx_mint: Value,
    anchor_key: ByteArray,
    anchor_data: Data,
    new_node_key: ByteArray,
    new_node_data: Data,
    new_node_link: Option<ByteArray>,
    new_node_ref_script: Option<ScriptHash>,
  }
}

type WholeInnerListArgs {
  WholeInnerListArgs {
    script_hash: ScriptHash,
    inner_ordering: ListOrdering,
    anchor_input: Input,
    inputs: List<Input>,
    continued_anchor_output: Output,
    new_inner_root_output: Output,
    first_node_output: Output,
    second_node_output: Output,
    tx_mint: Value,
    anchor_data: Data,
    anchor_link: Option<ByteArray>,
    new_inner_root_key: ByteArray,
    new_inner_root_data: Data,
    child_link: Option<ByteArray>,
    new_inner_root_ref_script: Option<ScriptHash>,
    first_node_key: ByteArray,
    first_node_data: Data,
    first_node_ref_script: Option<ScriptHash>,
    second_node_key: ByteArray,
    second_node_data: Data,
    second_node_ref_script: Option<ScriptHash>,
  }
}

type DescendingEmptyInnerListArgs {
  DescendingEmptyInnerListArgs {
    script_hash: ScriptHash,
    inner_ordering: ListOrdering,
    anchor_input: Input,
    inputs: List<Input>,
    continued_anchor_output: Output,
    new_inner_root_output: Output,
    tx_mint: Value,
    anchor_key: ByteArray,
    anchor_data: Data,
    anchor_link: Option<ByteArray>,
    new_inner_root_key: ByteArray,
    new_inner_root_data: Data,
    new_inner_root_ref_script: Option<ScriptHash>,
  }
}

const min_lovelace = 2_000_000

const test_root_key = #""

const test_node_key_prefix = #"4e"

const test_node_key_prefix_length = 1

const extra_asset_name = #"6578747261"

fn key_from_int(n: Int) -> ByteArray {
  n |> bytearray.from_int_big_endian(1)
}

fn node_asset_name(node_key: ByteArray) -> AssetName {
  test_node_key_prefix |> bytearray.concat(node_key)
}

fn element_value(script_hash: ScriptHash, asset_name: AssetName) -> Value {
  assets.from_lovelace(min_lovelace)
    |> assets.merge(assets.from_asset(script_hash, asset_name, 1))
}

fn element_output(
  script_hash: ScriptHash,
  asset_name: AssetName,
  element: GenericElement,
  reference_script: Option<ScriptHash>,
) -> Output {
  Output {
    address: Address {
      payment_credential: Script(script_hash),
      stake_credential: None,
    },
    value: element_value(script_hash, asset_name),
    datum: InlineDatum(element),
    reference_script,
  }
}

fn element_input(
  output_reference: OutputReference,
  script_hash: ScriptHash,
  asset_name: AssetName,
  element: GenericElement,
  reference_script: Option<ScriptHash>,
) -> Input {
  Input {
    output_reference,
    output: element_output(script_hash, asset_name, element, reference_script),
  }
}

fn one_mint(script_hash: ScriptHash, asset_name: AssetName) -> Value {
  assets.from_asset(script_hash, asset_name, 1)
}

fn one_burn(script_hash: ScriptHash, asset_name: AssetName) -> Value {
  assets.from_asset(script_hash, asset_name, -1)
}

fn reference_script_fuzzer(
  script_hash: ScriptHash,
) -> Fuzzer<Option<ScriptHash>> {
  let has_reference_script <- fuzz.and_then(fuzz.bool())
  fuzz.constant(
    if has_reference_script {
      Some(script_hash)
    } else {
      None
    },
  )
}

fn data_fuzzer() -> Fuzzer<Data> {
  let bytes <- fuzz.and_then(fuzz.bytearray_between(0, 32))
  fuzz.constant(builtin.b_data(bytes))
}

fn list_ordering_fuzzer() -> Fuzzer<ListOrdering> {
  let ordering_index <- fuzz.and_then(fuzz.int_between(0, 2))
  fuzz.constant(
    when ordering_index is {
      0 -> Ascending
      1 -> Descending
      _ -> Unordered
    },
  )
}

fn inputs_with_expected_inputs_fuzzer(
  expected_inputs: List<Input>,
) -> Fuzzer<List<Input>> {
  let inputs_before <- fuzz.and_then(fuzz.list_between(utils.user_input_fuzzer(), 0, 10))
  let inputs_after <- fuzz.and_then(fuzz.list_between(utils.user_input_fuzzer(), 0, 10))
  fuzz.constant(
    list.concat(inputs_before, list.concat(expected_inputs, inputs_after)),
  )
}

fn eval_root(eval: RootEval<Bool>, script_hash: ScriptHash) -> Bool {
  eval |> run_root_with(script_hash, test_root_key)
}

fn eval_node(eval: NodeEval<Bool>, script_hash: ScriptHash) -> Bool {
  eval
    |> run_node_with(
        script_hash,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}

fn eval_element(eval: ElementEval<Bool>, script_hash: ScriptHash) -> Bool {
  eval
    |> run_element_with(
        script_hash,
        test_root_key,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}

fn init_fuzzer() -> Fuzzer<InitArgs> {
  let script_hash <- fuzz.and_then(fuzz.bytearray_fixed(28))
  let root_data <- fuzz.and_then(data_fuzzer())
  let root_ref_script <- fuzz.and_then(reference_script_fuzzer(script_hash))
  let root_output =
    element_output(
      script_hash,
      test_root_key,
      Element { data: Root(root_data), link: None },
      root_ref_script,
    )
  let tx_mint =
    one_mint(script_hash, test_root_key)
      |> assets.merge(one_mint(script_hash, extra_asset_name))
  fuzz.constant(
    InitArgs { script_hash, root_output, tx_mint, root_data, root_ref_script },
  )
}

fn deinit_fuzzer() -> Fuzzer<DeinitArgs> {
  let script_hash <- fuzz.and_then(fuzz.bytearray_fixed(28))
  let root_data <- fuzz.and_then(data_fuzzer())
  let output_reference <- fuzz.and_then(utils.output_reference_fuzzer())
  let root_input =
    element_input(
      output_reference,
      script_hash,
      test_root_key,
      Element { data: Root(root_data), link: None },
      None,
    )
  let inputs <- fuzz.and_then(inputs_with_expected_inputs_fuzzer([root_input]))
  let tx_mint =
    one_burn(script_hash, test_root_key)
      |> assets.merge(one_burn(script_hash, extra_asset_name))
  fuzz.constant(DeinitArgs { script_hash, root_input, inputs, tx_mint, root_data })
}

fn ordered_keys_for_inner_root_insert(
  ordering: ListOrdering,
  base_key: Int,
) -> (ByteArray, ByteArray) {
  when ordering is {
    Ascending -> (key_from_int(base_key), key_from_int(base_key + 1))
    Descending -> (key_from_int(base_key + 1), key_from_int(base_key))
    Unordered -> (key_from_int(base_key + 1), key_from_int(base_key))
  }
}

fn ordered_keys_for_node_insert(
  ordering: ListOrdering,
  base_key: Int,
) -> (ByteArray, ByteArray, ByteArray) {
  when ordering is {
    Ascending ->
      (
        key_from_int(base_key),
        key_from_int(base_key + 1),
        key_from_int(base_key + 2),
      )
    Descending ->
      (
        key_from_int(base_key + 2),
        key_from_int(base_key + 1),
        key_from_int(base_key),
      )
    Unordered ->
      (
        key_from_int(base_key + 2),
        key_from_int(base_key),
        key_from_int(base_key + 1),
      )
  }
}

fn insert_inner_root_anchor_fuzzer() -> Fuzzer<InnerRootInsertArgs> {
  let script_hash <- fuzz.and_then(fuzz.bytearray_fixed(28))
  let ordering <- fuzz.and_then(list_ordering_fuzzer())
  let base_key <- fuzz.and_then(fuzz.int_between(1, 80))
  let anchor_key_int <- fuzz.and_then(fuzz.int_between(180, 220))
  let outer_link_int <- fuzz.and_then(fuzz.int_between(221, 250))
  let has_outer_link <- fuzz.and_then(fuzz.bool())
  let anchor_data <- fuzz.and_then(data_fuzzer())
  let new_node_data <- fuzz.and_then(data_fuzzer())
  let anchor_ref_script <- fuzz.and_then(reference_script_fuzzer(script_hash))
  let new_node_ref_script <- fuzz.and_then(reference_script_fuzzer(script_hash))
  let output_reference <- fuzz.and_then(utils.output_reference_fuzzer())
  let (new_node_key, old_child_key) =
    ordered_keys_for_inner_root_insert(ordering, base_key)
  let anchor_key = key_from_int(anchor_key_int)
  let anchor_link =
    if has_outer_link {
      Some(key_from_int(outer_link_int))
    } else {
      None
    }
  let anchor_asset_name = node_asset_name(anchor_key)
  let new_node_asset_name = node_asset_name(new_node_key)
  let anchor_input =
    element_input(
      output_reference,
      script_hash,
      anchor_asset_name,
      Element {
        data: InnerRoot { data: anchor_data, child_link: Some(old_child_key) },
        link: anchor_link,
      },
      anchor_ref_script,
    )
  let inputs <- fuzz.and_then(inputs_with_expected_inputs_fuzzer([anchor_input]))
  let continued_anchor_output =
    element_output(
      script_hash,
      anchor_asset_name,
      Element {
        data: InnerRoot { data: anchor_data, child_link: Some(new_node_key) },
        link: anchor_link,
      },
      anchor_ref_script,
    )
  let new_node_link = Some(old_child_key)
  let new_node_output =
    element_output(
      script_hash,
      new_node_asset_name,
      Element { data: Node(new_node_data), link: new_node_link },
      new_node_ref_script,
    )
  let tx_mint =
    one_mint(script_hash, new_node_asset_name)
      |> assets.merge(one_mint(script_hash, extra_asset_name))

  fuzz.constant(
    InnerRootInsertArgs {
      script_hash,
      ordering,
      anchor_input,
      inputs,
      continued_anchor_output,
      new_node_output,
      tx_mint,
      anchor_key,
      anchor_data,
      anchor_link,
      new_node_key,
      new_node_data,
      new_node_link,
      new_node_ref_script,
    },
  )
}

fn insert_node_anchor_fuzzer() -> Fuzzer<NodeInsertArgs> {
  let script_hash <- fuzz.and_then(fuzz.bytearray_fixed(28))
  let ordering <- fuzz.and_then(list_ordering_fuzzer())
  let base_key <- fuzz.and_then(fuzz.int_between(1, 80))
  let has_next_link <- fuzz.and_then(fuzz.bool())
  let anchor_data <- fuzz.and_then(data_fuzzer())
  let new_node_data <- fuzz.and_then(data_fuzzer())
  let anchor_ref_script <- fuzz.and_then(reference_script_fuzzer(script_hash))
  let new_node_ref_script <- fuzz.and_then(reference_script_fuzzer(script_hash))
  let output_reference <- fuzz.and_then(utils.output_reference_fuzzer())
  let (anchor_key, new_node_key, next_node_key) =
    ordered_keys_for_node_insert(ordering, base_key)
  let anchor_asset_name = node_asset_name(anchor_key)
  let new_node_asset_name = node_asset_name(new_node_key)
  let new_node_link =
    if has_next_link {
      Some(next_node_key)
    } else {
      None
    }
  let anchor_input =
    element_input(
      output_reference,
      script_hash,
      anchor_asset_name,
      Element { data: Node(anchor_data), link: new_node_link },
      anchor_ref_script,
    )
  let inputs <- fuzz.and_then(inputs_with_expected_inputs_fuzzer([anchor_input]))
  let continued_anchor_output =
    element_output(
      script_hash,
      anchor_asset_name,
      Element { data: Node(anchor_data), link: Some(new_node_key) },
      anchor_ref_script,
    )
  let new_node_output =
    element_output(
      script_hash,
      new_node_asset_name,
      Element { data: Node(new_node_data), link: new_node_link },
      new_node_ref_script,
    )
  let tx_mint = one_mint(script_hash, new_node_asset_name)

  fuzz.constant(
    NodeInsertArgs {
      script_hash,
      ordering,
      anchor_input,
      inputs,
      continued_anchor_output,
      new_node_output,
      tx_mint,
      anchor_key,
      anchor_data,
      new_node_key,
      new_node_data,
      new_node_link,
      new_node_ref_script,
    },
  )
}

fn bad_ascending_inner_root_insert_fuzzer() -> Fuzzer<InnerRootInsertArgs> {
  let script_hash <- fuzz.and_then(fuzz.bytearray_fixed(28))
  let base_key <- fuzz.and_then(fuzz.int_between(1, 80))
  let anchor_key_int <- fuzz.and_then(fuzz.int_between(180, 220))
  let anchor_data <- fuzz.and_then(data_fuzzer())
  let new_node_data <- fuzz.and_then(data_fuzzer())
  let output_reference <- fuzz.and_then(utils.output_reference_fuzzer())
  let new_node_key = key_from_int(base_key + 1)
  let old_child_key = key_from_int(base_key)
  let anchor_key = key_from_int(anchor_key_int)
  let anchor_asset_name = node_asset_name(anchor_key)
  let new_node_asset_name = node_asset_name(new_node_key)
  let anchor_input =
    element_input(
      output_reference,
      script_hash,
      anchor_asset_name,
      Element {
        data: InnerRoot { data: anchor_data, child_link: Some(old_child_key) },
        link: None,
      },
      None,
    )
  let inputs <- fuzz.and_then(inputs_with_expected_inputs_fuzzer([anchor_input]))
  let continued_anchor_output =
    element_output(
      script_hash,
      anchor_asset_name,
      Element {
        data: InnerRoot { data: anchor_data, child_link: Some(new_node_key) },
        link: None,
      },
      None,
    )
  let new_node_link = Some(old_child_key)
  let new_node_output =
    element_output(
      script_hash,
      new_node_asset_name,
      Element { data: Node(new_node_data), link: new_node_link },
      None,
    )
  let tx_mint = one_mint(script_hash, new_node_asset_name)

  fuzz.constant(
    InnerRootInsertArgs {
      script_hash,
      ordering: Ascending,
      anchor_input,
      inputs,
      continued_anchor_output,
      new_node_output,
      tx_mint,
      anchor_key,
      anchor_data,
      anchor_link: None,
      new_node_key,
      new_node_data,
      new_node_link,
      new_node_ref_script: None,
    },
  )
}

fn inner_node_keys_for_ordering(
  ordering: ListOrdering,
  base_key: Int,
) -> (ByteArray, ByteArray) {
  when ordering is {
    Ascending -> (key_from_int(base_key), key_from_int(base_key + 1))
    Descending -> (key_from_int(base_key + 1), key_from_int(base_key))
    Unordered -> (key_from_int(base_key + 1), key_from_int(base_key))
  }
}

fn whole_inner_list_fuzzer() -> Fuzzer<WholeInnerListArgs> {
  let script_hash <- fuzz.and_then(fuzz.bytearray_fixed(28))
  let inner_ordering <- fuzz.and_then(list_ordering_fuzzer())
  let outer_base_key <- fuzz.and_then(fuzz.int_between(100, 120))
  let inner_base_key <- fuzz.and_then(fuzz.int_between(1, 80))
  let anchor_data <- fuzz.and_then(data_fuzzer())
  let new_inner_root_data <- fuzz.and_then(data_fuzzer())
  let first_node_data <- fuzz.and_then(data_fuzzer())
  let second_node_data <- fuzz.and_then(data_fuzzer())
  let new_inner_root_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash))
  let first_node_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash))
  let second_node_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash))
  let output_reference <- fuzz.and_then(utils.output_reference_fuzzer())
  let new_inner_root_key = key_from_int(outer_base_key)
  let next_outer_key = key_from_int(outer_base_key + 1)
  let (first_node_key, second_node_key) =
    inner_node_keys_for_ordering(inner_ordering, inner_base_key)
  let new_inner_root_asset_name = node_asset_name(new_inner_root_key)
  let first_node_asset_name = node_asset_name(first_node_key)
  let second_node_asset_name = node_asset_name(second_node_key)
  let anchor_link = Some(next_outer_key)
  let child_link = Some(first_node_key)
  let anchor_input =
    element_input(
      output_reference,
      script_hash,
      test_root_key,
      Element { data: Root(anchor_data), link: anchor_link },
      None,
    )
  let inputs <- fuzz.and_then(inputs_with_expected_inputs_fuzzer([anchor_input]))
  let continued_anchor_output =
    element_output(
      script_hash,
      test_root_key,
      Element { data: Root(anchor_data), link: Some(new_inner_root_key) },
      None,
    )
  let new_inner_root_output =
    element_output(
      script_hash,
      new_inner_root_asset_name,
      Element {
        data: InnerRoot { data: new_inner_root_data, child_link },
        link: anchor_link,
      },
      new_inner_root_ref_script,
    )
  let first_node_output =
    element_output(
      script_hash,
      first_node_asset_name,
      Element { data: Node(first_node_data), link: Some(second_node_key) },
      first_node_ref_script,
    )
  let second_node_output =
    element_output(
      script_hash,
      second_node_asset_name,
      Element { data: Node(second_node_data), link: None },
      second_node_ref_script,
    )
  let tx_mint =
    one_mint(script_hash, new_inner_root_asset_name)
      |> assets.merge(one_mint(script_hash, first_node_asset_name))
      |> assets.merge(one_mint(script_hash, second_node_asset_name))
      |> assets.merge(one_mint(script_hash, extra_asset_name))

  fuzz.constant(
    WholeInnerListArgs {
      script_hash,
      inner_ordering,
      anchor_input,
      inputs,
      continued_anchor_output,
      new_inner_root_output,
      first_node_output,
      second_node_output,
      tx_mint,
      anchor_data,
      anchor_link,
      new_inner_root_key,
      new_inner_root_data,
      child_link,
      new_inner_root_ref_script,
      first_node_key,
      first_node_data,
      first_node_ref_script,
      second_node_key,
      second_node_data,
      second_node_ref_script,
    },
  )
}

fn descending_empty_inner_list_fuzzer() -> Fuzzer<DescendingEmptyInnerListArgs> {
  let script_hash <- fuzz.and_then(fuzz.bytearray_fixed(28))
  let inner_ordering <- fuzz.and_then(list_ordering_fuzzer())
  let outer_base_key <- fuzz.and_then(fuzz.int_between(1, 80))
  let anchor_data <- fuzz.and_then(data_fuzzer())
  let new_inner_root_data <- fuzz.and_then(data_fuzzer())
  let anchor_ref_script <- fuzz.and_then(reference_script_fuzzer(script_hash))
  let new_inner_root_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash))
  let output_reference <- fuzz.and_then(utils.output_reference_fuzzer())
  let anchor_key = key_from_int(outer_base_key + 2)
  let new_inner_root_key = key_from_int(outer_base_key + 1)
  let next_outer_key = key_from_int(outer_base_key)
  let anchor_asset_name = node_asset_name(anchor_key)
  let new_inner_root_asset_name = node_asset_name(new_inner_root_key)
  let anchor_link = Some(next_outer_key)
  let anchor_input =
    element_input(
      output_reference,
      script_hash,
      anchor_asset_name,
      Element {
        data: InnerRoot { data: anchor_data, child_link: None },
        link: anchor_link,
      },
      anchor_ref_script,
    )
  let inputs <- fuzz.and_then(inputs_with_expected_inputs_fuzzer([anchor_input]))
  let continued_anchor_output =
    element_output(
      script_hash,
      anchor_asset_name,
      Element {
        data: InnerRoot { data: anchor_data, child_link: None },
        link: Some(new_inner_root_key),
      },
      anchor_ref_script,
    )
  let new_inner_root_output =
    element_output(
      script_hash,
      new_inner_root_asset_name,
      Element {
        data: InnerRoot { data: new_inner_root_data, child_link: None },
        link: anchor_link,
      },
      new_inner_root_ref_script,
    )
  let tx_mint = one_mint(script_hash, new_inner_root_asset_name)

  fuzz.constant(
    DescendingEmptyInnerListArgs {
      script_hash,
      inner_ordering,
      anchor_input,
      inputs,
      continued_anchor_output,
      new_inner_root_output,
      tx_mint,
      anchor_key,
      anchor_data,
      anchor_link,
      new_inner_root_key,
      new_inner_root_data,
      new_inner_root_ref_script,
    },
  )
}

test success__init__reference_script_and_extra_mint(args via init_fuzzer()) {
  let InitArgs { script_hash, root_output, tx_mint, root_data, root_ref_script } =
    args

  init(
    nonce_validated: True,
    produced_element_output: root_output,
    tx_mint: tx_mint,
    root_validator: fn(lovelace, other_list_assets, data, reference_script) {
      and {
        lovelace == min_lovelace,
        dict.get(other_list_assets, extra_asset_name) == Some(1),
        data == root_data,
        reference_script == root_ref_script,
      }
    },
  )
    |> eval_root(script_hash)
}

test success__deinit__extra_burn(args via deinit_fuzzer()) {
  let DeinitArgs { script_hash, root_input, inputs, tx_mint, root_data } = args

  deinit(
    inputs: inputs,
    tx_mint: tx_mint,
    root_validator: fn(input, lovelace, other_list_assets, data) {
      and {
        input.output_reference == root_input.output_reference,
        lovelace == min_lovelace,
        dict.get(other_list_assets, extra_asset_name) == Some(-1),
        data == root_data,
      }
    },
  )
    |> eval_root(script_hash)
}

test success__insert_into_inner_list__inner_root_anchor(
  args via insert_inner_root_anchor_fuzzer(),
) {
  let InnerRootInsertArgs {
    script_hash,
    ordering,
    anchor_input,
    inputs,
    continued_anchor_output,
    new_node_output,
    tx_mint,
    anchor_key,
    anchor_data,
    anchor_link,
    new_node_key,
    new_node_data,
    new_node_link,
    new_node_ref_script,
  } = args

  insert_into_inner_list(
    ordering_of_inner_node_keys: ordering,
    continued_anchor_element_output: continued_anchor_output,
    new_node_output: new_node_output,
    inputs: inputs,
    tx_mint: tx_mint,
    additional_validations: fn(
      input,
      lovelace_change,
      anchor,
      new_node_lovelace,
      callback_new_node_key,
      callback_new_node_data,
      callback_new_node_link,
      callback_new_node_ref_script,
      other_list_assets,
    ) {
      and {
        input.output_reference == anchor_input.output_reference,
        lovelace_change == 0,
        anchor(
          fn(callback_anchor_key, callback_anchor_data, callback_anchor_link) {
            and {
              callback_anchor_key == anchor_key,
              callback_anchor_data == anchor_data,
              callback_anchor_link == anchor_link,
            }
          },
          fn(_, _) { False },
        ),
        new_node_lovelace == min_lovelace,
        callback_new_node_key == new_node_key,
        callback_new_node_data == new_node_data,
        callback_new_node_link == new_node_link,
        callback_new_node_ref_script == new_node_ref_script,
        dict.get(other_list_assets, extra_asset_name) == Some(1),
      }
    },
  )
    |> eval_node(script_hash)
}

test success__insert_into_inner_list__node_anchor(
  args via insert_node_anchor_fuzzer(),
) {
  let NodeInsertArgs {
    script_hash,
    ordering,
    anchor_input,
    inputs,
    continued_anchor_output,
    new_node_output,
    tx_mint,
    anchor_key,
    anchor_data,
    new_node_key,
    new_node_data,
    new_node_link,
    new_node_ref_script,
  } = args

  insert_into_inner_list(
    ordering_of_inner_node_keys: ordering,
    continued_anchor_element_output: continued_anchor_output,
    new_node_output: new_node_output,
    inputs: inputs,
    tx_mint: tx_mint,
    additional_validations: fn(
      input,
      lovelace_change,
      anchor,
      new_node_lovelace,
      callback_new_node_key,
      callback_new_node_data,
      callback_new_node_link,
      callback_new_node_ref_script,
      other_list_assets,
    ) {
      and {
        input.output_reference == anchor_input.output_reference,
        lovelace_change == 0,
        anchor(fn(_, _, _) { False }, fn(callback_anchor_key, callback_anchor_data) {
          and {
            callback_anchor_key == anchor_key,
            callback_anchor_data == anchor_data,
          }
        }),
        new_node_lovelace == min_lovelace,
        callback_new_node_key == new_node_key,
        callback_new_node_data == new_node_data,
        callback_new_node_link == new_node_link,
        callback_new_node_ref_script == new_node_ref_script,
        dict.is_empty(other_list_assets),
      }
    },
  )
    |> eval_node(script_hash)
}

test fail__insert_into_inner_list__bad_ascending_position(
  args via bad_ascending_inner_root_insert_fuzzer(),
) fail {
  let InnerRootInsertArgs {
    script_hash,
    ordering,
    anchor_input: _anchor_input,
    inputs,
    continued_anchor_output,
    new_node_output,
    tx_mint,
    ..
  } = args

  insert_into_inner_list(
    ordering_of_inner_node_keys: ordering,
    continued_anchor_element_output: continued_anchor_output,
    new_node_output: new_node_output,
    inputs: inputs,
    tx_mint: tx_mint,
    additional_validations: fn(_, _, _, _, _, _, _, _, _) { True },
  )
    |> eval_node(script_hash)
}

test success__ascending_insert_of_inner_list__root_anchor_with_nodes(
  args via whole_inner_list_fuzzer(),
) {
  let WholeInnerListArgs {
    script_hash,
    inner_ordering,
    anchor_input,
    inputs,
    continued_anchor_output,
    new_inner_root_output,
    first_node_output,
    second_node_output,
    tx_mint,
    anchor_data,
    anchor_link,
    new_inner_root_key,
    new_inner_root_data,
    child_link,
    new_inner_root_ref_script,
    first_node_key,
    first_node_data,
    first_node_ref_script,
    second_node_key,
    second_node_data,
    second_node_ref_script,
  } = args

  ascending_insert_of_inner_list(
    ordering_of_inner_node_keys: inner_ordering,
    continued_anchor_element_output: continued_anchor_output,
    new_inner_root_output: new_inner_root_output,
    inputs: inputs,
    inner_node_outputs: [first_node_output, second_node_output],
    tx_mint: tx_mint,
    node_validator: fn(index, lovelace, key, data, link, reference_script) {
      when index is {
        0 ->
          and {
            lovelace == min_lovelace,
            key == first_node_key,
            data == first_node_data,
            link == Some(second_node_key),
            reference_script == first_node_ref_script,
          }
        1 ->
          and {
            lovelace == min_lovelace,
            key == second_node_key,
            data == second_node_data,
            link == None,
            reference_script == second_node_ref_script,
          }
        _ -> False
      }
    },
    additional_validations: fn(
      input,
      lovelace_change,
      anchor_key,
      callback_anchor_data,
      callback_anchor_link,
      new_inner_root_lovelace,
      callback_new_inner_root_key,
      callback_new_inner_root_data,
      callback_child_link,
      callback_new_inner_root_ref_script,
      inner_node_count,
      last_inner_node_key,
      other_list_assets,
    ) {
      and {
        input.output_reference == anchor_input.output_reference,
        lovelace_change == 0,
        anchor_key == None,
        callback_anchor_data == anchor_data,
        callback_anchor_link == anchor_link,
        new_inner_root_lovelace == min_lovelace,
        callback_new_inner_root_key == new_inner_root_key,
        callback_new_inner_root_data == new_inner_root_data,
        callback_child_link == child_link,
        callback_new_inner_root_ref_script == new_inner_root_ref_script,
        inner_node_count == 2,
        last_inner_node_key == Some(second_node_key),
        dict.get(other_list_assets, extra_asset_name) == Some(1),
      }
    },
  )
    |> eval_element(script_hash)
}

test success__descending_insert_of_inner_list__inner_root_anchor_empty_child_list(
  args via descending_empty_inner_list_fuzzer(),
) {
  let DescendingEmptyInnerListArgs {
    script_hash,
    inner_ordering,
    anchor_input,
    inputs,
    continued_anchor_output,
    new_inner_root_output,
    tx_mint,
    anchor_key,
    anchor_data,
    anchor_link,
    new_inner_root_key,
    new_inner_root_data,
    new_inner_root_ref_script,
  } = args

  descending_insert_of_inner_list(
    ordering_of_inner_node_keys: inner_ordering,
    continued_anchor_element_output: continued_anchor_output,
    new_inner_root_output: new_inner_root_output,
    inputs: inputs,
    inner_node_outputs: [],
    tx_mint: tx_mint,
    node_validator: fn(_, _, _, _, _, _) { False },
    additional_validations: fn(
      input,
      lovelace_change,
      callback_anchor_key,
      callback_anchor_data,
      callback_anchor_link,
      new_inner_root_lovelace,
      callback_new_inner_root_key,
      callback_new_inner_root_data,
      child_link,
      callback_new_inner_root_ref_script,
      inner_node_count,
      last_inner_node_key,
      other_list_assets,
    ) {
      and {
        input.output_reference == anchor_input.output_reference,
        lovelace_change == 0,
        callback_anchor_key == Some(anchor_key),
        callback_anchor_data == anchor_data,
        callback_anchor_link == anchor_link,
        new_inner_root_lovelace == min_lovelace,
        callback_new_inner_root_key == new_inner_root_key,
        callback_new_inner_root_data == new_inner_root_data,
        child_link == None,
        callback_new_inner_root_ref_script == new_inner_root_ref_script,
        inner_node_count == 0,
        last_inner_node_key == None,
        dict.is_empty(other_list_assets),
      }
    },
  )
    |> eval_element(script_hash)
}

test fail__ascending_insert_of_inner_list__missing_inner_node_mint(
  args via whole_inner_list_fuzzer(),
) fail {
  let WholeInnerListArgs {
    script_hash,
    inner_ordering,
    anchor_input: _anchor_input,
    inputs,
    continued_anchor_output,
    new_inner_root_output,
    first_node_output,
    second_node_output,
    new_inner_root_key,
    first_node_key,
    ..
  } = args
  let tx_mint =
    one_mint(script_hash, node_asset_name(new_inner_root_key))
      |> assets.merge(one_mint(script_hash, node_asset_name(first_node_key)))

  ascending_insert_of_inner_list(
    ordering_of_inner_node_keys: inner_ordering,
    continued_anchor_element_output: continued_anchor_output,
    new_inner_root_output: new_inner_root_output,
    inputs: inputs,
    inner_node_outputs: [first_node_output, second_node_output],
    tx_mint: tx_mint,
    node_validator: fn(_, _, _, _, _, _) { True },
    additional_validations: fn(_, _, _, _, _, _, _, _, _, _, _, _, _) { True },
  )
    |> eval_element(script_hash)
}

test fail__ascending_insert_of_inner_list__bad_inner_node_link(
  args via whole_inner_list_fuzzer(),
) fail {
  let WholeInnerListArgs {
    script_hash,
    inner_ordering,
    anchor_input: _anchor_input,
    inputs,
    continued_anchor_output,
    new_inner_root_output,
    first_node_output,
    second_node_output,
    tx_mint,
    first_node_data,
    first_node_ref_script,
    ..
  } = args
  let broken_first_node_output =
    Output {
      ..first_node_output,
      datum: InlineDatum(Element { data: Node(first_node_data), link: None }),
      reference_script: first_node_ref_script,
    }

  ascending_insert_of_inner_list(
    ordering_of_inner_node_keys: inner_ordering,
    continued_anchor_element_output: continued_anchor_output,
    new_inner_root_output: new_inner_root_output,
    inputs: inputs,
    inner_node_outputs: [broken_first_node_output, second_node_output],
    tx_mint: tx_mint,
    node_validator: fn(_, _, _, _, _, _) { True },
    additional_validations: fn(_, _, _, _, _, _, _, _, _, _, _, _, _) { True },
  )
    |> eval_element(script_hash)
}
