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
  Ascending, Descending, Element, GenericElement, InnerRoot, ListOrdering, Node,
  Root, Unordered, ascending_insert_of_inner_list, deinit,
  descending_insert_of_inner_list, init, insert_into_inner_list,
}
use cardano/address.{Address, Script}
use cardano/assets.{AssetName, Value}
use cardano/fuzz as cardano_fuzz
use cardano/transaction.{InlineDatum, Input, Output, OutputReference}

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

type InsertIntoInnerListCase {
  InnerRootAnchor
  NodeAnchor
  BadAscendingInnerRootAnchor
}

type InsertIntoInnerListArgs {
  InsertIntoInnerListArgs {
    script_hash: ScriptHash,
    ordering: ListOrdering,
    anchor_case: InsertIntoInnerListCase,
    anchor_input: Input,
    inputs: List<Input>,
    continued_anchor_output: Output,
    new_node_output: Output,
    tx_mint: Value,
    anchor_key: ByteArray,
    anchor_data: Data,
    cont_anchor_data: Data,
    anchor_link: Option<ByteArray>,
    new_node_key: ByteArray,
    new_node_data: Data,
    new_node_link: Option<ByteArray>,
    new_node_ref_script: Option<ScriptHash>,
    expects_extra_asset: Bool,
  }
}

type InsertOfInnerListCase {
  RootAnchorWithNodes
  DescendingInnerRootAnchorEmpty
}

type ExpectedInnerNode {
  ExpectedInnerNode {
    key: ByteArray,
    data: Data,
    link: Option<ByteArray>,
    reference_script: Option<ScriptHash>,
  }
}

type InsertOfInnerListArgs {
  InsertOfInnerListArgs {
    script_hash: ScriptHash,
    inner_ordering: ListOrdering,
    anchor_input: Input,
    inputs: List<Input>,
    continued_anchor_output: Output,
    new_inner_root_output: Output,
    inner_node_outputs: List<Output>,
    tx_mint: Value,
    anchor_key: Option<ByteArray>,
    anchor_data: Data,
    cont_anchor_data: Data,
    anchor_link: Option<ByteArray>,
    new_inner_root_key: ByteArray,
    new_inner_root_data: Data,
    child_link: Option<ByteArray>,
    new_inner_root_ref_script: Option<ScriptHash>,
    expected_inner_nodes: List<ExpectedInnerNode>,
    expected_last_inner_node_key: Option<ByteArray>,
    expects_extra_asset: Bool,
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
  fuzz.one_of([None, Some(script_hash)])
}

fn list_ordering_fuzzer() -> Fuzzer<ListOrdering> {
  fuzz.one_of([Ascending, Descending, Unordered])
}

fn input_without_list_policy_fuzzer(
  list_nft_policy: ScriptHash,
) -> Fuzzer<Input> {
  fuzz.such_that(
    cardano_fuzz.input(),
    fn(input) {
      input.output.value
        |> assets.tokens(list_nft_policy)
        |> dict.is_empty()
    },
  )
}

fn inputs_with_expected_inputs_fuzzer(
  list_nft_policy: ScriptHash,
  expected_inputs: List<Input>,
) -> Fuzzer<List<Input>> {
  let inputs_before <-
    fuzz.and_then(
      fuzz.list_between(
        input_without_list_policy_fuzzer(list_nft_policy),
        0,
        10,
      ),
    )
  let inputs_after <-
    fuzz.and_then(
      fuzz.list_between(
        input_without_list_policy_fuzzer(list_nft_policy),
        0,
        10,
      ),
    )
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

fn init_fuzzer(with_extra_mint: Bool) -> Fuzzer<InitArgs> {
  let script_hash <- fuzz.and_then(fuzz.bytearray_fixed(28))
  let root_data <- fuzz.and_then(fuzz.data())
  let root_ref_script <- fuzz.and_then(reference_script_fuzzer(script_hash))
  let root_output =
    element_output(
      script_hash,
      test_root_key,
      Element { data: Root(root_data), link: None },
      root_ref_script,
    )
  let init_mint = one_mint(script_hash, test_root_key)
  let tx_mint =
    if with_extra_mint {
      init_mint |> assets.merge(one_mint(script_hash, extra_asset_name))
    } else {
      init_mint
    }
  fuzz.constant(
    InitArgs { script_hash, root_output, tx_mint, root_data, root_ref_script },
  )
}

fn deinit_fuzzer(with_extra_mint: Bool) -> Fuzzer<DeinitArgs> {
  let script_hash <- fuzz.and_then(fuzz.bytearray_fixed(28))
  let root_data <- fuzz.and_then(fuzz.data())
  let output_reference <- fuzz.and_then(cardano_fuzz.output_reference())
  let root_input =
    element_input(
      output_reference,
      script_hash,
      test_root_key,
      Element { data: Root(root_data), link: None },
      None,
    )
  let inputs <-
    fuzz.and_then(inputs_with_expected_inputs_fuzzer(script_hash, [root_input]))
  let init_mint = one_burn(script_hash, test_root_key)
  let tx_mint =
    if with_extra_mint {
      init_mint |> assets.merge(one_burn(script_hash, extra_asset_name))
    } else {
      init_mint
    }
  fuzz.constant(
    DeinitArgs { script_hash, root_input, inputs, tx_mint, root_data },
  )
}

fn three_non_root_unique_keys(
  ordering: ListOrdering,
  base_key: Int,
) -> Fuzzer<(ByteArray, ByteArray, ByteArray)> {
  when ordering is {
    Ascending ->
      fuzz.constant(
        (
          key_from_int(base_key),
          key_from_int(base_key + 1),
          key_from_int(base_key + 2),
        ),
      )
    Descending ->
      fuzz.constant(
        (
          key_from_int(base_key + 2),
          key_from_int(base_key + 1),
          key_from_int(base_key),
        ),
      )
    Unordered -> {
      let anchor_key <-
        fuzz.and_then(
          fuzz.bytearray_between(1, 32 - test_node_key_prefix_length),
        )
      let new_node_key <-
        fuzz.and_then(
          fuzz.such_that(
            fuzz.bytearray_between(1, 32 - test_node_key_prefix_length),
            fn(key) { key != anchor_key },
          ),
        )
      let next_node_key <-
        fuzz.and_then(
          fuzz.such_that(
            fuzz.bytearray_between(1, 32 - test_node_key_prefix_length),
            fn(key) { key != anchor_key && key != new_node_key },
          ),
        )
      fuzz.constant((anchor_key, new_node_key, next_node_key))
    }
  }
}

fn insert_into_inner_list_fuzzer(
  anchor_case: InsertIntoInnerListCase,
) -> Fuzzer<InsertIntoInnerListArgs> {
  let script_hash <- fuzz.and_then(fuzz.bytearray_fixed(28))
  let ordering <-
    fuzz.and_then(
      when anchor_case is {
        BadAscendingInnerRootAnchor -> fuzz.constant(Ascending)
        _ -> list_ordering_fuzzer()
      },
    )
  let base_key <- fuzz.and_then(fuzz.int_between(1, 80))
  let anchor_key_int <- fuzz.and_then(fuzz.int_between(180, 220))
  let outer_link_int <- fuzz.and_then(fuzz.int_between(221, 250))
  let has_link <- fuzz.and_then(fuzz.bool())
  let anchor_data <- fuzz.and_then(fuzz.data())
  let cont_anchor_data <- fuzz.and_then(fuzz.data())
  let new_node_data <- fuzz.and_then(fuzz.data())
  let anchor_ref_script <-
    fuzz.and_then(
      when anchor_case is {
        BadAscendingInnerRootAnchor -> fuzz.constant(None)
        _ -> reference_script_fuzzer(script_hash)
      },
    )
  let new_node_ref_script <-
    fuzz.and_then(
      when anchor_case is {
        BadAscendingInnerRootAnchor -> fuzz.constant(None)
        _ -> reference_script_fuzzer(script_hash)
      },
    )
  let output_reference <- fuzz.and_then(cardano_fuzz.output_reference())

  when anchor_case is {
    NodeAnchor -> {
      let (anchor_key, new_node_key, next_node_key) <-
        fuzz.and_then(three_non_root_unique_keys(ordering, base_key))
      let anchor_asset_name = node_asset_name(anchor_key)
      let new_node_asset_name = node_asset_name(new_node_key)
      let new_node_link =
        if has_link {
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
      let inputs <-
        fuzz.and_then(
          inputs_with_expected_inputs_fuzzer(script_hash, [anchor_input]),
        )
      let continued_anchor_output =
        element_output(
          script_hash,
          anchor_asset_name,
          Element { data: Node(cont_anchor_data), link: Some(new_node_key) },
          anchor_ref_script,
        )
      let new_node_output =
        element_output(
          script_hash,
          new_node_asset_name,
          Element { data: Node(new_node_data), link: new_node_link },
          new_node_ref_script,
        )
      fuzz.constant(
        InsertIntoInnerListArgs {
          script_hash,
          ordering,
          anchor_case,
          anchor_input,
          inputs,
          continued_anchor_output,
          new_node_output,
          tx_mint: one_mint(script_hash, new_node_asset_name),
          anchor_key,
          anchor_data,
          cont_anchor_data,
          anchor_link: None,
          new_node_key,
          new_node_data,
          new_node_link,
          new_node_ref_script,
          expects_extra_asset: False,
        },
      )
    }
    InnerRootAnchor | BadAscendingInnerRootAnchor -> {
      let (new_node_key, old_child_key, _) <-
        fuzz.and_then(
          when anchor_case is {
            BadAscendingInnerRootAnchor ->
              three_non_root_unique_keys(Descending, base_key)
            _ -> three_non_root_unique_keys(ordering, base_key)
          },
        )
      let anchor_key = key_from_int(anchor_key_int)
      let anchor_link =
        when anchor_case is {
          BadAscendingInnerRootAnchor -> None
          _ ->
            if has_link {
              Some(key_from_int(outer_link_int))
            } else {
              None
            }
        }
      let anchor_asset_name = node_asset_name(anchor_key)
      let new_node_asset_name = node_asset_name(new_node_key)
      let anchor_input =
        element_input(
          output_reference,
          script_hash,
          anchor_asset_name,
          Element {
            data: InnerRoot {
              data: anchor_data,
              child_link: Some(old_child_key),
            },
            link: anchor_link,
          },
          anchor_ref_script,
        )
      let inputs <-
        fuzz.and_then(
          inputs_with_expected_inputs_fuzzer(script_hash, [anchor_input]),
        )
      let continued_anchor_output =
        element_output(
          script_hash,
          anchor_asset_name,
          Element {
            data: InnerRoot {
              data: cont_anchor_data,
              child_link: Some(new_node_key),
            },
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
      let tx_mint = one_mint(script_hash, new_node_asset_name)
      fuzz.constant(
        InsertIntoInnerListArgs {
          script_hash,
          ordering,
          anchor_case,
          anchor_input,
          inputs,
          continued_anchor_output,
          new_node_output,
          tx_mint: when anchor_case is {
            InnerRootAnchor ->
              tx_mint |> assets.merge(one_mint(script_hash, extra_asset_name))
            _ -> tx_mint
          },
          anchor_key,
          anchor_data,
          cont_anchor_data,
          anchor_link,
          new_node_key,
          new_node_data,
          new_node_link,
          new_node_ref_script,
          expects_extra_asset: anchor_case == InnerRootAnchor,
        },
      )
    }
  }
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

fn insert_of_inner_list_fuzzer(
  scenario: InsertOfInnerListCase,
) -> Fuzzer<InsertOfInnerListArgs> {
  let script_hash <- fuzz.and_then(fuzz.bytearray_fixed(28))
  let inner_ordering <- fuzz.and_then(list_ordering_fuzzer())
  let outer_base_key <-
    fuzz.and_then(
      when scenario is {
        RootAnchorWithNodes -> fuzz.int_between(100, 120)
        DescendingInnerRootAnchorEmpty -> fuzz.int_between(1, 80)
      },
    )
  let inner_base_key <- fuzz.and_then(fuzz.int_between(1, 80))
  let anchor_data <- fuzz.and_then(fuzz.data())
  let cont_anchor_data <- fuzz.and_then(fuzz.data())
  let new_inner_root_data <- fuzz.and_then(fuzz.data())
  let first_node_data <- fuzz.and_then(fuzz.data())
  let second_node_data <- fuzz.and_then(fuzz.data())
  let new_inner_root_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash))
  let first_node_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash))
  let second_node_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash))
  let generated_anchor_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash))
  let output_reference <- fuzz.and_then(cardano_fuzz.output_reference())
  let (
    anchor_key,
    anchor_asset_name,
    new_inner_root_key,
    next_outer_key,
    anchor_ref_script,
    anchor_element_data,
  ) =
    when scenario is {
      RootAnchorWithNodes ->
        (
          None,
          test_root_key,
          key_from_int(outer_base_key),
          key_from_int(outer_base_key + 1),
          None,
          Root(anchor_data),
        )
      DescendingInnerRootAnchorEmpty -> {
        let anchor_key = key_from_int(outer_base_key + 2)
        (
          Some(anchor_key),
          node_asset_name(anchor_key),
          key_from_int(outer_base_key + 1),
          key_from_int(outer_base_key),
          generated_anchor_ref_script,
          InnerRoot { data: anchor_data, child_link: None },
        )
      }
    }
  let (first_node_key, second_node_key) =
    inner_node_keys_for_ordering(inner_ordering, inner_base_key)
  let cont_anchor_element_data =
    when scenario is {
      RootAnchorWithNodes -> Root(cont_anchor_data)
      DescendingInnerRootAnchorEmpty ->
        InnerRoot { data: cont_anchor_data, child_link: None }
    }
  let new_inner_root_asset_name = node_asset_name(new_inner_root_key)
  let first_node_asset_name = node_asset_name(first_node_key)
  let second_node_asset_name = node_asset_name(second_node_key)
  let anchor_link = Some(next_outer_key)
  let child_link =
    when scenario is {
      RootAnchorWithNodes -> Some(first_node_key)
      DescendingInnerRootAnchorEmpty -> None
    }
  let anchor_input =
    element_input(
      output_reference,
      script_hash,
      anchor_asset_name,
      Element { data: anchor_element_data, link: anchor_link },
      anchor_ref_script,
    )
  let inputs <-
    fuzz.and_then(
      inputs_with_expected_inputs_fuzzer(script_hash, [anchor_input]),
    )
  let continued_anchor_output =
    element_output(
      script_hash,
      anchor_asset_name,
      Element { data: cont_anchor_element_data, link: Some(new_inner_root_key) },
      anchor_ref_script,
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
  let expected_first_node =
    ExpectedInnerNode {
      key: first_node_key,
      data: first_node_data,
      link: Some(second_node_key),
      reference_script: first_node_ref_script,
    }
  let expected_second_node =
    ExpectedInnerNode {
      key: second_node_key,
      data: second_node_data,
      link: None,
      reference_script: second_node_ref_script,
    }
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
  let (
    inner_node_outputs,
    expected_inner_nodes,
    expected_last_inner_node_key,
    tx_mint,
    expects_extra_asset,
  ) =
    when scenario is {
      RootAnchorWithNodes ->
        (
          [first_node_output, second_node_output],
          [expected_first_node, expected_second_node],
          Some(second_node_key),
          one_mint(script_hash, new_inner_root_asset_name)
            |> assets.merge(one_mint(script_hash, first_node_asset_name))
            |> assets.merge(one_mint(script_hash, second_node_asset_name))
            |> assets.merge(one_mint(script_hash, extra_asset_name)),
          True,
        )
      DescendingInnerRootAnchorEmpty ->
        ([], [], None, one_mint(script_hash, new_inner_root_asset_name), False)
    }

  fuzz.constant(
    InsertOfInnerListArgs {
      script_hash,
      inner_ordering,
      anchor_input,
      inputs,
      continued_anchor_output,
      new_inner_root_output,
      inner_node_outputs,
      tx_mint,
      anchor_key,
      anchor_data,
      cont_anchor_data,
      anchor_link,
      new_inner_root_key,
      new_inner_root_data,
      child_link,
      new_inner_root_ref_script,
      expected_inner_nodes,
      expected_last_inner_node_key,
      expects_extra_asset,
    },
  )
}

test success__init(args via init_fuzzer(False)) {
  let InitArgs { script_hash, root_output, tx_mint, root_data, root_ref_script } =
    args
  init(
    nonce_validated: True,
    produced_element_output: root_output,
    tx_mint: tx_mint,
    root_validator: fn(lovelace, data, reference_script) {
      and {
        lovelace == min_lovelace,
        data == root_data,
        reference_script == root_ref_script,
      }
    },
  )
    |> eval_root(script_hash)
}

test fail__init__extra_mint(args via init_fuzzer(True)) fail {
  let InitArgs { script_hash, root_output, tx_mint, .. } = args

  init(
    nonce_validated: True,
    produced_element_output: root_output,
    tx_mint: tx_mint,
    root_validator: fn(_lovelace, _data, _reference_script) { True },
  )
    |> eval_root(script_hash)
}

test success__deinit(args via deinit_fuzzer(False)) {
  let DeinitArgs { script_hash, root_input, inputs, tx_mint, root_data } = args

  deinit(
    inputs: inputs,
    tx_mint: tx_mint,
    root_validator: fn(input, lovelace, data) {
      and {
        input.output_reference == root_input.output_reference,
        input.output.datum == InlineDatum(
          Element { data: Root { data: root_data }, link: None },
        ),
        lovelace == min_lovelace,
        data == root_data,
      }
    },
  )
    |> eval_root(script_hash)
}

test fail__deinit__extra_burn(args via deinit_fuzzer(True)) fail {
  let DeinitArgs { script_hash, inputs, tx_mint, .. } = args

  deinit(
    inputs: inputs,
    tx_mint: tx_mint,
    root_validator: fn(_input, _lovelace, _data) { True },
  )
    |> eval_root(script_hash)
}

test success__insert_into_inner_list__inner_root_anchor(
  args via insert_into_inner_list_fuzzer(InnerRootAnchor),
) {
  let InsertIntoInnerListArgs {
    script_hash,
    ordering,
    anchor_input,
    inputs,
    continued_anchor_output,
    new_node_output,
    tx_mint,
    anchor_key,
    anchor_data,
    cont_anchor_data,
    anchor_link,
    new_node_key,
    new_node_data,
    new_node_link,
    new_node_ref_script,
    ..
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
          fn(
            callback_anchor_key,
            callback_anchor_data,
            callback_cont_anchor_data,
            callback_anchor_link,
          ) {
            and {
              callback_anchor_key == anchor_key,
              callback_anchor_data == anchor_data,
              callback_cont_anchor_data == cont_anchor_data,
              callback_anchor_link == anchor_link,
            }
          },
          fn(_, _, _) { False },
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
  args via insert_into_inner_list_fuzzer(NodeAnchor),
) {
  let InsertIntoInnerListArgs {
    script_hash,
    ordering,
    anchor_input,
    inputs,
    continued_anchor_output,
    new_node_output,
    tx_mint,
    anchor_key,
    anchor_data,
    cont_anchor_data,
    new_node_key,
    new_node_data,
    new_node_link,
    new_node_ref_script,
    ..
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
          fn(_, _, _, _) { False },
          fn(
            callback_anchor_key,
            callback_anchor_data,
            callback_cont_anchor_data,
          ) {
            and {
              callback_anchor_key == anchor_key,
              callback_anchor_data == anchor_data,
              callback_cont_anchor_data == cont_anchor_data,
            }
          },
        ),
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
  args via insert_into_inner_list_fuzzer(BadAscendingInnerRootAnchor),
) fail {
  let InsertIntoInnerListArgs {
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
  args via insert_of_inner_list_fuzzer(RootAnchorWithNodes),
) {
  let InsertOfInnerListArgs {
    script_hash,
    inner_ordering,
    anchor_input,
    inputs,
    continued_anchor_output,
    new_inner_root_output,
    inner_node_outputs,
    tx_mint,
    anchor_key,
    anchor_data,
    cont_anchor_data,
    anchor_link,
    new_inner_root_key,
    new_inner_root_data,
    child_link,
    new_inner_root_ref_script,
    expected_inner_nodes,
    expected_last_inner_node_key,
    expects_extra_asset,
  } = args

  ascending_insert_of_inner_list(
    ordering_of_inner_node_keys: inner_ordering,
    continued_anchor_element_output: continued_anchor_output,
    new_inner_root_output: new_inner_root_output,
    inputs: inputs,
    inner_node_outputs: inner_node_outputs,
    tx_mint: tx_mint,
    prepare_state: fn(lovelace, key, data, link, reference_script) {
      expect and {
          lovelace == min_lovelace,
          key == new_inner_root_key,
          data == new_inner_root_data,
          link == child_link,
          reference_script == new_inner_root_ref_script,
        }
      None
    },
    node_validator: fn(
      _state,
      index,
      lovelace,
      key,
      data,
      link,
      reference_script,
    ) {
      expect Some(ExpectedInnerNode {
        key: expected_key,
        data: expected_data,
        link: expected_link,
        reference_script: expected_reference_script,
      }) = list.at(expected_inner_nodes, index)
      expect and {
          lovelace == min_lovelace,
          key == expected_key,
          data == expected_data,
          link == expected_link,
          reference_script == expected_reference_script,
        }
      Some(key)
    },
    final_validator: fn(
      input,
      lovelace_change,
      callback_anchor_key,
      callback_anchor_data,
      callback_cont_anchor_data,
      callback_anchor_link,
      final_state,
      other_list_assets,
    ) {
      and {
        input.output_reference == anchor_input.output_reference,
        lovelace_change == 0,
        callback_anchor_key == anchor_key,
        callback_anchor_data == anchor_data,
        callback_cont_anchor_data == cont_anchor_data,
        callback_anchor_link == anchor_link,
        final_state == expected_last_inner_node_key,
        if expects_extra_asset {
          dict.get(other_list_assets, extra_asset_name) == Some(1)
        } else {
          dict.is_empty(other_list_assets)
        },
      }
    },
  )
    |> eval_element(script_hash)
}

test success__descending_insert_of_inner_list__inner_root_anchor_empty_child_list(
  args via insert_of_inner_list_fuzzer(DescendingInnerRootAnchorEmpty),
) {
  let InsertOfInnerListArgs {
    script_hash,
    inner_ordering,
    anchor_input,
    inputs,
    continued_anchor_output,
    new_inner_root_output,
    inner_node_outputs,
    tx_mint,
    anchor_key,
    anchor_data,
    cont_anchor_data,
    anchor_link,
    new_inner_root_key,
    new_inner_root_data,
    new_inner_root_ref_script,
    expected_inner_nodes,
    expected_last_inner_node_key,
    expects_extra_asset,
    ..
  } = args

  descending_insert_of_inner_list(
    ordering_of_inner_node_keys: inner_ordering,
    continued_anchor_element_output: continued_anchor_output,
    new_inner_root_output: new_inner_root_output,
    inputs: inputs,
    inner_node_outputs: inner_node_outputs,
    tx_mint: tx_mint,
    prepare_state: fn(lovelace, key, data, link, reference_script) {
      expect and {
          lovelace == min_lovelace,
          key == new_inner_root_key,
          data == new_inner_root_data,
          link == None,
          reference_script == new_inner_root_ref_script,
        }
      None
    },
    node_validator: fn(
      _state,
      index,
      lovelace,
      key,
      data,
      link,
      reference_script,
    ) {
      expect Some(ExpectedInnerNode {
        key: expected_key,
        data: expected_data,
        link: expected_link,
        reference_script: expected_reference_script,
      }) = list.at(expected_inner_nodes, index)
      expect and {
          lovelace == min_lovelace,
          key == expected_key,
          data == expected_data,
          link == expected_link,
          reference_script == expected_reference_script,
        }
      Some(key)
    },
    final_validator: fn(
      input,
      lovelace_change,
      callback_anchor_key,
      callback_anchor_data,
      callback_cont_anchor_data,
      callback_anchor_link,
      final_state,
      other_list_assets,
    ) {
      and {
        input.output_reference == anchor_input.output_reference,
        lovelace_change == 0,
        callback_anchor_key == anchor_key,
        callback_anchor_data == anchor_data,
        callback_cont_anchor_data == cont_anchor_data,
        callback_anchor_link == anchor_link,
        final_state == expected_last_inner_node_key,
        if expects_extra_asset {
          dict.get(other_list_assets, extra_asset_name) == Some(1)
        } else {
          dict.is_empty(other_list_assets)
        },
      }
    },
  )
    |> eval_element(script_hash)
}

test fail__ascending_insert_of_inner_list__missing_inner_node_mint(
  args via insert_of_inner_list_fuzzer(RootAnchorWithNodes),
) fail {
  let InsertOfInnerListArgs {
    script_hash,
    inner_ordering,
    anchor_input: _anchor_input,
    inputs,
    continued_anchor_output,
    new_inner_root_output,
    inner_node_outputs,
    new_inner_root_key,
    expected_inner_nodes,
    ..
  } = args
  expect [first_node_output, second_node_output] = inner_node_outputs
  expect [ExpectedInnerNode { key: first_node_key, .. }, ..] =
    expected_inner_nodes
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
    prepare_state: fn(_, _, _, _, _) { True },
    node_validator: fn(state, _, _, _, _, _, _) { state },
    final_validator: fn(_, _, _, _, _, _, _, _) { True },
  )
    |> eval_element(script_hash)
}

test fail__ascending_insert_of_inner_list__bad_inner_node_link(
  args via insert_of_inner_list_fuzzer(RootAnchorWithNodes),
) fail {
  let InsertOfInnerListArgs {
    script_hash,
    inner_ordering,
    anchor_input: _anchor_input,
    inputs,
    continued_anchor_output,
    new_inner_root_output,
    inner_node_outputs,
    tx_mint,
    expected_inner_nodes,
    ..
  } = args
  expect [first_node_output, second_node_output] = inner_node_outputs
  expect [
    ExpectedInnerNode {
      data: first_node_data,
      reference_script: first_node_ref_script,
      ..
    },
    ..
  ] = expected_inner_nodes
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
    prepare_state: fn(_, _, _, _, _) { True },
    node_validator: fn(state, _, _, _, _, _, _) { state },
    final_validator: fn(_, _, _, _, _, _, _, _) { True },
  )
    |> eval_element(script_hash)
}
