use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{ScriptHash, blake2b_224}
use aiken/fuzz
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list.{
  ElementEval, NodeEval, RootEval, run_element_with, run_node_with,
  run_root_with,
}
use aiken_design_patterns/linked_list/nested.{
  Ascending, Descending, Element, GenericElement, InnerRoot, ListOrdering, Node,
  Root, Unordered, deinit, get_element_info, get_inner_root_element_info,
  get_node_element_info, get_root_element_info, init,
  insert_inner_list_ascending, insert_inner_list_descending,
  insert_into_inner_list, spend_for_updating_elements_data,
}
use aiken_design_patterns/utils
use cardano/address.{Address, Script}
use cardano/assets.{AssetName, Value}
use cardano/fuzz as cardano_fuzz
use cardano/transaction.{InlineDatum, Input, Output, OutputReference}

type InitArgs {
  script_hash: ScriptHash,
  root_output: Output,
  tx_mint: Value,
  root_data: Data,
  root_ref_script: Option<ScriptHash>,
}

type DeinitArgs {
  script_hash: ScriptHash,
  root_input: Input,
  inputs: List<Input>,
  tx_mint: Value,
  root_data: Data,
}

type InsertIntoInnerListCase {
  InnerRootAnchor
  NodeAnchor
  BadAscendingInnerRootAnchor
}

type InsertIntoInnerListArgs {
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
  inner_root_outer_link: Option<ByteArray>,
  new_node_key: ByteArray,
  new_node_data: Data,
  new_node_link: Option<ByteArray>,
  new_node_ref_script: Option<ScriptHash>,
  expected_extra_asset_change: Option<Pair<AssetName, Int>>,
}

type NodeAnchorInsertKeys {
  anchor_key: ByteArray,
  new_node_key: ByteArray,
  next_node_key: ByteArray,
}

type InnerRootInsertKeys {
  new_node_key: ByteArray,
  previous_first_child_key: ByteArray,
}

type InsertOfInnerListCase {
  RootAnchorWithNodes
  DescendingOuterAnchorWithEmptyInnerList
}

type UpdateElementCase {
  UpdateRootElement
  UpdateInnerRootElement
  UpdateNodeElement
}

type UpdateMutation {
  UpdateNoMutation
  UpdateBadValidator
  UpdateBadLink
  UpdateBadInputIndex
  UpdateBadOutputIndex
  UpdateMintedListAsset
}

type ExpectedInnerNode {
  key: ByteArray,
  data: Data,
  link: Option<ByteArray>,
  reference_script: Option<ScriptHash>,
}

type InsertOfInnerListArgs {
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
  new_inner_root_child_link: Option<ByteArray>,
  new_inner_root_ref_script: Option<ScriptHash>,
  expected_inner_nodes: List<ExpectedInnerNode>,
  expected_last_inner_node_key: Option<ByteArray>,
  expected_extra_asset_change: Option<Pair<AssetName, Int>>,
}

type UpdateArgs {
  script_hash: ScriptHash,
  element_case: UpdateElementCase,
  element_input: Input,
  continued_element_output: Output,
  element_key: Option<ByteArray>,
  old_data: Data,
  new_data: Data,
  element_link: Option<ByteArray>,
  child_link: Option<ByteArray>,
  old_ref_script: Option<ScriptHash>,
  new_ref_script: Option<ScriptHash>,
}

const min_lovelace = 2_000_000

const test_root_key = #""

const test_node_key_prefix = #"4e"

const test_node_key_prefix_length = bytearray.length(test_node_key_prefix)

const extra_asset_name = #"6578747261"

fn one_byte_key_from_int(n: Int) -> ByteArray {
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

fn alter_output_link(output: Output) -> Output {
  expect InlineDatum(datum_data) = output.datum
  expect Element { data, link }: GenericElement = datum_data
  Output {
    ..output,
    datum: InlineDatum(
      Element {
        data,
        link: when link is {
          None -> Some(#"ff")
          Some(_) -> None
        },
      },
    ),
  }
}

fn alter_reference_script(output: Output, script_hash: ScriptHash) -> Output {
  Output {
    ..output,
    reference_script: Some(
      script_hash |> bytearray.concat("changed-ref") |> blake2b_224,
    ),
  }
}

fn reference_script_fuzzer(
  script_hash: ScriptHash,
  label: ByteArray,
) -> Fuzzer<Option<ScriptHash>> {
  fuzz.one_of(
    [None, Some(script_hash |> bytearray.concat(label) |> blake2b_224)],
  )
}

fn list_ordering_fuzzer() -> Fuzzer<ListOrdering> {
  fuzz.one_of([Ascending, Descending, Unordered])
}

fn eval_root(eval: RootEval<Bool>, script_hash: ScriptHash) -> Bool {
  eval |> run_root_with(script_hash, test_root_key)
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

fn eval_node(eval: NodeEval<Bool>, script_hash: ScriptHash) -> Bool {
  eval
    |> run_node_with(
        script_hash,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}

fn init_fuzzer(with_extra_mint: Bool) -> Fuzzer<InitArgs> {
  let script_hash <- fuzz.and_then(cardano_fuzz.policy_id())
  let root_data <- fuzz.and_then(fuzz.data())
  let root_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash, "init-root"))
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

fn deinit_fuzzer(with_extra_burn: Bool) -> Fuzzer<DeinitArgs> {
  let script_hash <- fuzz.and_then(cardano_fuzz.policy_id())
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
    fuzz.and_then(
      utils.inputs_with_expected_inputs_fuzzer(script_hash, [root_input]),
    )
  let deinit_burn = one_burn(script_hash, test_root_key)
  let tx_mint =
    if with_extra_burn {
      deinit_burn |> assets.merge(one_burn(script_hash, extra_asset_name))
    } else {
      deinit_burn
    }
  fuzz.constant(
    DeinitArgs { script_hash, root_input, inputs, tx_mint, root_data },
  )
}

fn node_anchor_insert_keys(
  ordering: ListOrdering,
  base_key: Int,
) -> Fuzzer<NodeAnchorInsertKeys> {
  when ordering is {
    Ascending ->
      fuzz.constant(
        NodeAnchorInsertKeys {
          anchor_key: one_byte_key_from_int(base_key),
          new_node_key: one_byte_key_from_int(base_key + 1),
          next_node_key: one_byte_key_from_int(base_key + 2),
        },
      )
    Descending ->
      fuzz.constant(
        NodeAnchorInsertKeys {
          anchor_key: one_byte_key_from_int(base_key + 2),
          new_node_key: one_byte_key_from_int(base_key + 1),
          next_node_key: one_byte_key_from_int(base_key),
        },
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
      fuzz.constant(
        NodeAnchorInsertKeys { anchor_key, new_node_key, next_node_key },
      )
    }
  }
}

fn inner_root_insert_keys(
  ordering: ListOrdering,
  base_key: Int,
) -> Fuzzer<InnerRootInsertKeys> {
  when ordering is {
    Ascending ->
      fuzz.constant(
        InnerRootInsertKeys {
          new_node_key: one_byte_key_from_int(base_key),
          previous_first_child_key: one_byte_key_from_int(base_key + 1),
        },
      )
    Descending ->
      fuzz.constant(
        InnerRootInsertKeys {
          new_node_key: one_byte_key_from_int(base_key + 2),
          previous_first_child_key: one_byte_key_from_int(base_key + 1),
        },
      )
    Unordered -> {
      let new_node_key <-
        fuzz.and_then(
          fuzz.bytearray_between(1, 32 - test_node_key_prefix_length),
        )
      let previous_first_child_key <-
        fuzz.and_then(
          fuzz.such_that(
            fuzz.bytearray_between(1, 32 - test_node_key_prefix_length),
            fn(key) { key != new_node_key },
          ),
        )
      fuzz.constant(
        InnerRootInsertKeys { new_node_key, previous_first_child_key },
      )
    }
  }
}

fn insert_into_inner_list_fuzzer(
  anchor_case: InsertIntoInnerListCase,
) -> Fuzzer<InsertIntoInnerListArgs> {
  let script_hash <- fuzz.and_then(cardano_fuzz.policy_id())
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
        _ -> reference_script_fuzzer(script_hash, "insert-anchor")
      },
    )
  let new_node_ref_script <-
    fuzz.and_then(
      when anchor_case is {
        BadAscendingInnerRootAnchor -> fuzz.constant(None)
        _ -> reference_script_fuzzer(script_hash, "insert-new-node")
      },
    )
  let output_reference <- fuzz.and_then(cardano_fuzz.output_reference())

  when anchor_case is {
    NodeAnchor -> {
      let NodeAnchorInsertKeys { anchor_key, new_node_key, next_node_key } <-
        fuzz.and_then(node_anchor_insert_keys(ordering, base_key))
      let anchor_asset_name = node_asset_name(anchor_key)
      let new_node_asset_name = node_asset_name(new_node_key)
      // The node anchor's authenticated link before insertion becomes the new
      // node's expected successor at the callback boundary.
      let previous_anchor_link =
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
          Element { data: Node(anchor_data), link: previous_anchor_link },
          anchor_ref_script,
        )
      let inputs <-
        fuzz.and_then(
          utils.inputs_with_expected_inputs_fuzzer(script_hash, [anchor_input]),
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
          Element { data: Node(new_node_data), link: previous_anchor_link },
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
          inner_root_outer_link: None,
          new_node_key,
          new_node_data,
          new_node_link: previous_anchor_link,
          new_node_ref_script,
          expected_extra_asset_change: None,
        },
      )
    }
    InnerRootAnchor | BadAscendingInnerRootAnchor -> {
      let InnerRootInsertKeys { new_node_key, previous_first_child_key } <-
        fuzz.and_then(
          when anchor_case is {
            BadAscendingInnerRootAnchor -> {
              // These descending-shaped keys intentionally violate the
              // surrounding Ascending insertion case.
              let ascending_order_violation_keys =
                inner_root_insert_keys(Descending, base_key)
              ascending_order_violation_keys
            }
            _ -> inner_root_insert_keys(ordering, base_key)
          },
        )
      let anchor_key = one_byte_key_from_int(anchor_key_int)
      let inner_root_outer_link =
        when anchor_case is {
          BadAscendingInnerRootAnchor -> None
          _ ->
            if has_link {
              Some(one_byte_key_from_int(outer_link_int))
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
              child_link: Some(previous_first_child_key),
            },
            link: inner_root_outer_link,
          },
          anchor_ref_script,
        )
      let inputs <-
        fuzz.and_then(
          utils.inputs_with_expected_inputs_fuzzer(script_hash, [anchor_input]),
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
            link: inner_root_outer_link,
          },
          anchor_ref_script,
        )
      let new_node_link = Some(previous_first_child_key)
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
          inner_root_outer_link,
          new_node_key,
          new_node_data,
          new_node_link,
          new_node_ref_script,
          expected_extra_asset_change: if anchor_case == InnerRootAnchor {
            Some(Pair(extra_asset_name, 1))
          } else {
            None
          },
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
    Ascending ->
      (one_byte_key_from_int(base_key), one_byte_key_from_int(base_key + 1))
    Descending ->
      (one_byte_key_from_int(base_key + 1), one_byte_key_from_int(base_key))
    // Unordered fixtures only care about link shape; key ordering is ignored.
    Unordered ->
      (one_byte_key_from_int(base_key + 1), one_byte_key_from_int(base_key))
  }
}

fn insert_of_inner_list_fuzzer(
  scenario: InsertOfInnerListCase,
) -> Fuzzer<InsertOfInnerListArgs> {
  let script_hash <- fuzz.and_then(cardano_fuzz.policy_id())
  let inner_ordering <- fuzz.and_then(list_ordering_fuzzer())
  let outer_base_key <-
    fuzz.and_then(
      when scenario is {
        RootAnchorWithNodes -> fuzz.int_between(100, 120)
        DescendingOuterAnchorWithEmptyInnerList -> fuzz.int_between(1, 80)
      },
    )
  let inner_base_key <- fuzz.and_then(fuzz.int_between(1, 80))
  let anchor_data <- fuzz.and_then(fuzz.data())
  let cont_anchor_data <- fuzz.and_then(fuzz.data())
  let new_inner_root_data <- fuzz.and_then(fuzz.data())
  let first_node_data <- fuzz.and_then(fuzz.data())
  let second_node_data <- fuzz.and_then(fuzz.data())
  let new_inner_root_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash, "new-inner-root"))
  let first_node_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash, "first-inner-node"))
  let second_node_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash, "second-inner-node"))
  let generated_anchor_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash, "outer-anchor"))
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
          one_byte_key_from_int(outer_base_key),
          one_byte_key_from_int(outer_base_key + 1),
          None,
          Root(anchor_data),
        )
      DescendingOuterAnchorWithEmptyInnerList -> {
        let anchor_key = one_byte_key_from_int(outer_base_key + 2)
        (
          Some(anchor_key),
          node_asset_name(anchor_key),
          one_byte_key_from_int(outer_base_key + 1),
          one_byte_key_from_int(outer_base_key),
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
      DescendingOuterAnchorWithEmptyInnerList ->
        InnerRoot { data: cont_anchor_data, child_link: None }
    }
  let new_inner_root_asset_name = node_asset_name(new_inner_root_key)
  let first_node_asset_name = node_asset_name(first_node_key)
  let second_node_asset_name = node_asset_name(second_node_key)
  let anchor_link = Some(next_outer_key)
  let new_inner_root_child_link =
    when scenario is {
      RootAnchorWithNodes -> Some(first_node_key)
      DescendingOuterAnchorWithEmptyInnerList -> None
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
      utils.inputs_with_expected_inputs_fuzzer(script_hash, [anchor_input]),
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
        data: InnerRoot {
          data: new_inner_root_data,
          child_link: new_inner_root_child_link,
        },
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
    expected_extra_asset_change,
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
          Some(Pair(extra_asset_name, 1)),
        )
      DescendingOuterAnchorWithEmptyInnerList ->
        ([], [], None, one_mint(script_hash, new_inner_root_asset_name), None)
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
      new_inner_root_child_link,
      new_inner_root_ref_script,
      expected_inner_nodes,
      expected_last_inner_node_key,
      expected_extra_asset_change,
    },
  )
}

fn update_fuzzer(element_case: UpdateElementCase) -> Fuzzer<UpdateArgs> {
  let script_hash <- fuzz.and_then(cardano_fuzz.policy_id())
  let output_reference <- fuzz.and_then(cardano_fuzz.output_reference())
  let element_key_int <- fuzz.and_then(fuzz.int_between(1, 80))
  let element_link_int <- fuzz.and_then(fuzz.int_between(81, 160))
  let child_link_int <- fuzz.and_then(fuzz.int_between(161, 240))
  let old_data <- fuzz.and_then(fuzz.data())
  let new_data <- fuzz.and_then(fuzz.data())
  let element_link <-
    fuzz.and_then(
      fuzz.one_of([None, Some(one_byte_key_from_int(element_link_int))]),
    )
  let child_link <-
    fuzz.and_then(
      fuzz.one_of([None, Some(one_byte_key_from_int(child_link_int))]),
    )
  let old_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash, "update-old-ref"))
  let new_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash, "update-new-ref"))
  let element_key =
    when element_case is {
      UpdateRootElement -> None
      _ -> Some(one_byte_key_from_int(element_key_int))
    }
  let asset_name =
    when element_key is {
      None -> test_root_key
      Some(key) -> node_asset_name(key)
    }
  let old_element_data =
    when element_case is {
      UpdateRootElement -> Root(old_data)
      UpdateInnerRootElement -> InnerRoot { data: old_data, child_link }
      UpdateNodeElement -> Node(old_data)
    }
  let new_element_data =
    when element_case is {
      UpdateRootElement -> Root(new_data)
      UpdateInnerRootElement -> InnerRoot { data: new_data, child_link }
      UpdateNodeElement -> Node(new_data)
    }
  let element_input =
    element_input(
      output_reference,
      script_hash,
      asset_name,
      Element { data: old_element_data, link: element_link },
      old_ref_script,
    )
  let continued_element_output =
    element_output(
      script_hash,
      asset_name,
      Element { data: new_element_data, link: element_link },
      new_ref_script,
    )
  fuzz.constant(
    UpdateArgs {
      script_hash,
      element_case,
      element_input,
      continued_element_output,
      element_key,
      old_data,
      new_data,
      element_link,
      child_link,
      old_ref_script,
      new_ref_script,
    },
  )
}

test success__init(args via init_fuzzer(False)) {
  let InitArgs { script_hash, root_output, tx_mint, root_data, root_ref_script } =
    args
  {
    let
      address,
      lovelace,
      data,
      reference_script,
    <-
      init(
        nonce_validated: True,
        produced_element_output: root_output,
        tx_mint: tx_mint,
      )
    and {
      address == root_output.address,
      lovelace == min_lovelace,
      data == root_data,
      reference_script == root_ref_script,
    }
  }
    |> eval_root(script_hash)
}

test fail__init__extra_mint(args via init_fuzzer(True)) fail {
  let InitArgs { script_hash, root_output, tx_mint, .. } = args

  {
    let
      _address,
      _lovelace,
      _data,
      _reference_script,
    <-
      init(
        nonce_validated: True,
        produced_element_output: root_output,
        tx_mint: tx_mint,
      )
    True
  }
    |> eval_root(script_hash)
}

test success__deinit(args via deinit_fuzzer(False)) {
  let DeinitArgs { script_hash, root_input, inputs, tx_mint, root_data } = args

  {
    let input, lovelace, data <- deinit(inputs: inputs, tx_mint: tx_mint)
    and {
      input.output_reference == root_input.output_reference,
      input.output.datum == InlineDatum(
        Element { data: Root { data: root_data }, link: None },
      ),
      lovelace == min_lovelace,
      data == root_data,
    }
  }
    |> eval_root(script_hash)
}

test fail__deinit__extra_burn(args via deinit_fuzzer(True)) fail {
  let DeinitArgs { script_hash, inputs, tx_mint, .. } = args

  {
    let _input, _lovelace, _data <- deinit(inputs: inputs, tx_mint: tx_mint)
    True
  }
    |> eval_root(script_hash)
}

fn run_update_case(update_args: UpdateArgs, mutation: UpdateMutation) -> Bool {
  let UpdateArgs {
    script_hash,
    element_case,
    element_input,
    continued_element_output,
    element_key,
    old_data,
    new_data,
    element_link,
    child_link,
    old_ref_script,
    new_ref_script,
  } = update_args
  let input_index =
    when mutation is {
      UpdateBadInputIndex -> 1
      _ -> 0
    }
  let output_index =
    when mutation is {
      UpdateBadOutputIndex -> 1
      _ -> 0
    }
  let outputs =
    when mutation is {
      UpdateBadLink -> [alter_output_link(continued_element_output)]
      UpdateBadOutputIndex ->
        [continued_element_output, alter_output_link(continued_element_output)]
      _ -> [continued_element_output]
    }
  let mint_value =
    when mutation is {
      UpdateMintedListAsset -> one_mint(script_hash, test_root_key)
      _ -> assets.zero
    }

  {
    let
      element_address,
      lovelace_change,
      preserved_element_link,
      updated_element,
      callback_old_ref_script,
      callback_new_ref_script,
    <-
      spend_for_updating_elements_data(
        input_index,
        output_index,
        element_input.output_reference,
        [element_input],
        outputs,
        mint_value,
      )
    expect element_address == element_input.output.address
    expect lovelace_change == 0
    expect preserved_element_link == element_link
    expect callback_old_ref_script == old_ref_script
    expect callback_new_ref_script == new_ref_script
    expect
      updated_element(
        fn(root_data, continued_root_data) {
          when element_case is {
            UpdateRootElement ->
              root_data == old_data && continued_root_data == new_data
            _ -> False
          }
        },
        fn(
          callback_inner_root_key,
          callback_inner_root_data,
          callback_continued_inner_root_data,
          callback_child_link,
        ) {
          when element_case is {
            UpdateInnerRootElement -> {
              expect Some(expected_key) = element_key
              and {
                callback_inner_root_key == expected_key,
                callback_inner_root_data == old_data,
                callback_continued_inner_root_data == new_data,
                callback_child_link == child_link,
              }
            }
            _ -> False
          }
        },
        fn(callback_node_key, callback_node_data, callback_continued_node_data) {
          when element_case is {
            UpdateNodeElement -> {
              expect Some(expected_key) = element_key
              and {
                callback_node_key == expected_key,
                callback_node_data == old_data,
                callback_continued_node_data == new_data,
              }
            }
            _ -> False
          }
        },
      )
    when mutation is {
      UpdateBadValidator -> False
      _ -> True
    }
  }
    |> eval_element(script_hash)
}

fn run_get_element_info_case(update_args: UpdateArgs) -> Bool {
  let UpdateArgs {
    script_hash,
    element_case,
    element_input,
    element_key,
    old_data,
    element_link,
    child_link,
    old_ref_script,
    ..
  } = update_args

  {
    let
      element_address,
      lovelace,
      callback_link,
      element_info,
      ref_script,
    <- get_element_info(element_input.output)
    expect element_address == element_input.output.address
    expect lovelace == min_lovelace
    expect callback_link == element_link
    expect ref_script == old_ref_script
    expect
      element_info(
        fn(root_data) {
          when element_case is {
            UpdateRootElement -> root_data == old_data
            _ -> False
          }
        },
        fn(
          callback_inner_root_key,
          callback_inner_root_data,
          callback_child_link,
        ) {
          when element_case is {
            UpdateInnerRootElement -> {
              expect Some(expected_key) = element_key
              and {
                callback_inner_root_key == expected_key,
                callback_inner_root_data == old_data,
                callback_child_link == child_link,
              }
            }
            _ -> False
          }
        },
        fn(callback_node_key, callback_node_data) {
          when element_case is {
            UpdateNodeElement -> {
              expect Some(expected_key) = element_key
              and {
                callback_node_key == expected_key,
                callback_node_data == old_data,
              }
            }
            _ -> False
          }
        },
      )
    True
  }
    |> eval_element(script_hash)
}

fn run_get_root_element_info_case(update_args: UpdateArgs) -> Bool {
  let UpdateArgs {
    script_hash,
    element_input,
    old_data,
    element_link,
    old_ref_script,
    ..
  } = update_args

  {
    let
      element_address,
      lovelace,
      root_data,
      root_link,
      ref_script,
    <- get_root_element_info(element_input.output)
    expect element_address == element_input.output.address
    expect lovelace == min_lovelace
    expect root_data == old_data
    expect root_link == element_link
    expect ref_script == old_ref_script
    True
  }
    |> eval_root(script_hash)
}

fn run_get_inner_root_element_info_case(update_args: UpdateArgs) -> Bool {
  let UpdateArgs {
    script_hash,
    element_input,
    element_key,
    old_data,
    element_link,
    child_link,
    old_ref_script,
    ..
  } = update_args

  {
    let
      element_address,
      lovelace,
      inner_root_key,
      inner_root_data,
      outer_link,
      callback_child_link,
      ref_script,
    <- get_inner_root_element_info(element_input.output)
    expect Some(expected_key) = element_key
    expect element_address == element_input.output.address
    expect lovelace == min_lovelace
    expect inner_root_key == expected_key
    expect inner_root_data == old_data
    expect outer_link == element_link
    expect callback_child_link == child_link
    expect ref_script == old_ref_script
    True
  }
    |> eval_node(script_hash)
}

fn run_get_node_element_info_case(update_args: UpdateArgs) -> Bool {
  let UpdateArgs {
    script_hash,
    element_input,
    element_key,
    old_data,
    element_link,
    old_ref_script,
    ..
  } = update_args

  {
    let
      element_address,
      lovelace,
      node_key,
      node_data,
      node_link,
      ref_script,
    <- get_node_element_info(element_input.output)
    expect Some(expected_key) = element_key
    expect element_address == element_input.output.address
    expect lovelace == min_lovelace
    expect node_key == expected_key
    expect node_data == old_data
    expect node_link == element_link
    expect ref_script == old_ref_script
    True
  }
    |> eval_node(script_hash)
}

test success__spend_for_updating_elements_data__root(
  args via update_fuzzer(UpdateRootElement),
) {
  run_update_case(args, UpdateNoMutation)
}

test success__spend_for_updating_elements_data__inner_root(
  args via update_fuzzer(UpdateInnerRootElement),
) {
  run_update_case(args, UpdateNoMutation)
}

test success__spend_for_updating_elements_data__node(
  args via update_fuzzer(UpdateNodeElement),
) {
  run_update_case(args, UpdateNoMutation)
}

test fail__spend_for_updating_elements_data__bad_additional_validator(
  args via update_fuzzer(UpdateInnerRootElement),
) fail {
  run_update_case(args, UpdateBadValidator)
}

test fail__spend_for_updating_elements_data__bad_link(
  args via update_fuzzer(UpdateInnerRootElement),
) fail {
  run_update_case(args, UpdateBadLink)
}

test fail__spend_for_updating_elements_data__minted_list_asset(
  args via update_fuzzer(UpdateInnerRootElement),
) fail {
  run_update_case(args, UpdateMintedListAsset)
}

test fail__spend_for_updating_elements_data__bad_input_index(
  args via update_fuzzer(UpdateInnerRootElement),
) fail {
  run_update_case(args, UpdateBadInputIndex)
}

test fail__spend_for_updating_elements_data__bad_output_index(
  args via update_fuzzer(UpdateInnerRootElement),
) fail {
  run_update_case(args, UpdateBadOutputIndex)
}

test success__get_element_info__root(args via update_fuzzer(UpdateRootElement)) {
  run_get_element_info_case(args)
}

test success__get_element_info__inner_root(
  args via update_fuzzer(UpdateInnerRootElement),
) {
  run_get_element_info_case(args)
}

test success__get_element_info__node(args via update_fuzzer(UpdateNodeElement)) {
  run_get_element_info_case(args)
}

test fail__get_element_info__bad_node_prefix(
  args via update_fuzzer(UpdateNodeElement),
) fail {
  let UpdateArgs { script_hash, element_input, .. } = args

  {
    let
      _address,
      _lovelace,
      _link,
      _element_info,
      _ref_script,
    <- get_element_info(element_input.output)
    True
  }
    |> run_element_with(script_hash, test_root_key, #"ff", 1)
}

test success__get_root_element_info(args via update_fuzzer(UpdateRootElement)) {
  run_get_root_element_info_case(args)
}

test fail__get_root_element_info__inner_root(
  args via update_fuzzer(UpdateInnerRootElement),
) fail {
  let UpdateArgs { script_hash, element_input, .. } = args

  {
    let
      _address,
      _lovelace,
      _data,
      _link,
      _ref_script,
    <- get_root_element_info(element_input.output)
    True
  }
    |> eval_root(script_hash)
}

test fail__get_root_element_info__node(
  args via update_fuzzer(UpdateNodeElement),
) fail {
  let UpdateArgs { script_hash, element_input, .. } = args

  {
    let
      _address,
      _lovelace,
      _data,
      _link,
      _ref_script,
    <- get_root_element_info(element_input.output)
    True
  }
    |> eval_root(script_hash)
}

test success__get_inner_root_element_info(
  args via update_fuzzer(UpdateInnerRootElement),
) {
  run_get_inner_root_element_info_case(args)
}

test fail__get_inner_root_element_info__root(
  args via update_fuzzer(UpdateRootElement),
) fail {
  let UpdateArgs { script_hash, element_input, .. } = args

  {
    let
      _address,
      _lovelace,
      _key,
      _data,
      _outer_link,
      _child_link,
      _ref_script,
    <- get_inner_root_element_info(element_input.output)
    True
  }
    |> eval_node(script_hash)
}

test fail__get_inner_root_element_info__node(
  args via update_fuzzer(UpdateNodeElement),
) fail {
  let UpdateArgs { script_hash, element_input, .. } = args

  {
    let
      _address,
      _lovelace,
      _key,
      _data,
      _outer_link,
      _child_link,
      _ref_script,
    <- get_inner_root_element_info(element_input.output)
    True
  }
    |> eval_node(script_hash)
}

test fail__get_inner_root_element_info__bad_node_prefix(
  args via update_fuzzer(UpdateInnerRootElement),
) fail {
  let UpdateArgs { script_hash, element_input, .. } = args

  {
    let
      _address,
      _lovelace,
      _key,
      _data,
      _outer_link,
      _child_link,
      _ref_script,
    <- get_inner_root_element_info(element_input.output)
    True
  }
    |> run_node_with(script_hash, #"ff", 1)
}

test success__get_node_element_info(args via update_fuzzer(UpdateNodeElement)) {
  run_get_node_element_info_case(args)
}

test fail__get_node_element_info__root(
  args via update_fuzzer(UpdateRootElement),
) fail {
  let UpdateArgs { script_hash, element_input, .. } = args

  {
    let
      _address,
      _lovelace,
      _key,
      _data,
      _link,
      _ref_script,
    <- get_node_element_info(element_input.output)
    True
  }
    |> eval_node(script_hash)
}

test fail__get_node_element_info__inner_root(
  args via update_fuzzer(UpdateInnerRootElement),
) fail {
  let UpdateArgs { script_hash, element_input, .. } = args

  {
    let
      _address,
      _lovelace,
      _key,
      _data,
      _link,
      _ref_script,
    <- get_node_element_info(element_input.output)
    True
  }
    |> eval_node(script_hash)
}

test fail__get_node_element_info__bad_node_prefix(
  args via update_fuzzer(UpdateNodeElement),
) fail {
  let UpdateArgs { script_hash, element_input, .. } = args

  {
    let
      _address,
      _lovelace,
      _key,
      _data,
      _link,
      _ref_script,
    <- get_node_element_info(element_input.output)
    True
  }
    |> run_node_with(script_hash, #"ff", 1)
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
    new_node_key,
    new_node_data,
    new_node_link,
    new_node_ref_script,
    ..
  } = args

  {
    let
      input,
      lovelace_change,
      anchor,
      new_node_lovelace,
      callback_new_node_key,
      callback_new_node_data,
      callback_new_node_link,
      callback_new_node_ref_script,
      other_list_assets,
    <-
      insert_into_inner_list(
        ordering_of_inner_node_keys: ordering,
        continued_anchor_element_output: continued_anchor_output,
        new_node_output: new_node_output,
        inputs: inputs,
        tx_mint: tx_mint,
      )

    and {
      input.output_reference == anchor_input.output_reference,
      lovelace_change == 0,
      anchor(
        fn(
          callback_anchor_key,
          callback_anchor_data,
          callback_cont_anchor_data,
          callback_child_link,
        ) {
          and {
            callback_anchor_key == anchor_key,
            callback_anchor_data == anchor_data,
            callback_cont_anchor_data == cont_anchor_data,
            callback_child_link == new_node_link,
          }
        },
        fn(_node_key, _node_data, _continued_node_data) { False },
      ),
      new_node_lovelace == min_lovelace,
      callback_new_node_key == new_node_key,
      callback_new_node_data == new_node_data,
      callback_new_node_link == new_node_link,
      callback_new_node_ref_script == new_node_ref_script,
      dict.get(other_list_assets, extra_asset_name) == Some(1),
    }
  }
    |> eval_element(script_hash)
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

  {
    let
      input,
      lovelace_change,
      anchor,
      new_node_lovelace,
      callback_new_node_key,
      callback_new_node_data,
      callback_new_node_link,
      callback_new_node_ref_script,
      other_list_assets,
    <-
      insert_into_inner_list(
        ordering_of_inner_node_keys: ordering,
        continued_anchor_element_output: continued_anchor_output,
        new_node_output: new_node_output,
        inputs: inputs,
        tx_mint: tx_mint,
      )
    and {
      input.output_reference == anchor_input.output_reference,
      lovelace_change == 0,
      anchor(
        fn(
          _inner_root_key,
          _inner_root_data,
          _continued_inner_root_data,
          _child_link,
        ) {
          False
        },
        fn(callback_anchor_key, callback_anchor_data, callback_cont_anchor_data) {
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
  }
    |> eval_element(script_hash)
}

test fail__insert_into_inner_list__changed_anchor_reference_script(
  args via insert_into_inner_list_fuzzer(NodeAnchor),
) fail {
  let InsertIntoInnerListArgs {
    script_hash,
    ordering,
    inputs,
    continued_anchor_output,
    new_node_output,
    tx_mint,
    ..
  } = args

  {
    let
      _input,
      _lovelace_change,
      _anchor,
      _new_node_lovelace,
      _new_node_key,
      _new_node_data,
      _new_node_link,
      _new_node_ref_script,
      _other_list_assets,
    <-
      insert_into_inner_list(
        ordering_of_inner_node_keys: ordering,
        continued_anchor_element_output: alter_reference_script(
          continued_anchor_output,
          script_hash,
        ),
        new_node_output: new_node_output,
        inputs: inputs,
        tx_mint: tx_mint,
      )
    True
  }
    |> eval_element(script_hash)
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

  {
    let
      _input,
      _lovelace_change,
      _anchor,
      _new_node_lovelace,
      _new_node_key,
      _new_node_data,
      _new_node_link,
      _new_node_ref_script,
      _other_list_assets,
    <-
      insert_into_inner_list(
        ordering_of_inner_node_keys: ordering,
        continued_anchor_element_output: continued_anchor_output,
        new_node_output: new_node_output,
        inputs: inputs,
        tx_mint: tx_mint,
      )
    True
  }
    |> eval_element(script_hash)
}

test fail__insert_into_inner_list__rejects_extra_root_key_change(
  args via insert_into_inner_list_fuzzer(InnerRootAnchor),
) fail {
  let InsertIntoInnerListArgs {
    script_hash,
    ordering,
    inputs,
    continued_anchor_output,
    new_node_output,
    tx_mint,
    ..
  } = args

  {
    let
      _input,
      _lovelace_change,
      _anchor,
      _new_node_lovelace,
      _new_node_key,
      _new_node_data,
      _new_node_link,
      _new_node_ref_script,
      _other_list_assets,
    <-
      insert_into_inner_list(
        ordering_of_inner_node_keys: ordering,
        continued_anchor_element_output: continued_anchor_output,
        new_node_output: new_node_output,
        inputs: inputs,
        tx_mint: tx_mint |> assets.merge(one_mint(script_hash, test_root_key)),
      )
    True
  }
    |> eval_element(script_hash)
}

test success__insert_inner_list_ascending__root_anchor_with_nodes(
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
    new_inner_root_child_link,
    new_inner_root_ref_script,
    expected_inner_nodes,
    expected_last_inner_node_key,
    expected_extra_asset_change,
  } = args

  {
    let
      input,
      lovelace_change,
      callback_anchor_key,
      callback_anchor_data,
      callback_cont_anchor_data,
      callback_anchor_link,
      final_state,
      other_list_assets,
    <-
      insert_inner_list_ascending(
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
              link == new_inner_root_child_link,
              reference_script == new_inner_root_ref_script,
            }
          None
        },
        node_validator: fn(
          _state,
          index,
          address,
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
          expect Some(expected_output) = list.at(inner_node_outputs, index)
          expect and {
              address == expected_output.address,
              lovelace == min_lovelace,
              key == expected_key,
              data == expected_data,
              link == expected_link,
              reference_script == expected_reference_script,
            }
          Some(key)
        },
      )
    and {
      input.output_reference == anchor_input.output_reference,
      lovelace_change == 0,
      callback_anchor_key == anchor_key,
      callback_anchor_data == anchor_data,
      callback_cont_anchor_data == cont_anchor_data,
      callback_anchor_link == anchor_link,
      final_state == expected_last_inner_node_key,
      when expected_extra_asset_change is {
        Some(Pair(asset_name, quantity)) ->
          dict.get(other_list_assets, asset_name) == Some(quantity)
        None -> dict.is_empty(other_list_assets)
      },
    }
  }
    |> eval_element(script_hash)
}

test success__insert_inner_list_descending__empty_inner_list(
  args via insert_of_inner_list_fuzzer(DescendingOuterAnchorWithEmptyInnerList),
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
    expected_extra_asset_change,
    ..
  } = args

  {
    let
      input,
      lovelace_change,
      callback_anchor_key,
      callback_anchor_data,
      callback_cont_anchor_data,
      callback_anchor_link,
      final_state,
      other_list_assets,
    <-
      insert_inner_list_descending(
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
          address,
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
          expect Some(expected_output) = list.at(inner_node_outputs, index)
          expect and {
              address == expected_output.address,
              lovelace == min_lovelace,
              key == expected_key,
              data == expected_data,
              link == expected_link,
              reference_script == expected_reference_script,
            }
          Some(key)
        },
      )
    and {
      input.output_reference == anchor_input.output_reference,
      lovelace_change == 0,
      callback_anchor_key == anchor_key,
      callback_anchor_data == anchor_data,
      callback_cont_anchor_data == cont_anchor_data,
      callback_anchor_link == anchor_link,
      final_state == expected_last_inner_node_key,
      when expected_extra_asset_change is {
        Some(Pair(asset_name, quantity)) ->
          dict.get(other_list_assets, asset_name) == Some(quantity)
        None -> dict.is_empty(other_list_assets)
      },
    }
  }
    |> eval_element(script_hash)
}

test fail__insert_inner_list_ascending__changed_anchor_reference_script(
  args via insert_of_inner_list_fuzzer(RootAnchorWithNodes),
) fail {
  let InsertOfInnerListArgs {
    script_hash,
    inner_ordering,
    inputs,
    continued_anchor_output,
    new_inner_root_output,
    inner_node_outputs,
    tx_mint,
    ..
  } = args

  {
    let
      _input,
      _lovelace_change,
      _anchor_key,
      _anchor_data,
      _continued_anchor_data,
      _anchor_link,
      _final_state,
      _other_list_assets,
    <-
      insert_inner_list_ascending(
        ordering_of_inner_node_keys: inner_ordering,
        continued_anchor_element_output: alter_reference_script(
          continued_anchor_output,
          script_hash,
        ),
        new_inner_root_output: new_inner_root_output,
        inputs: inputs,
        inner_node_outputs: inner_node_outputs,
        tx_mint: tx_mint,
        prepare_state: fn(_lovelace, _key, _data, _link, _reference_script) {
          True
        },
        node_validator: fn(
          state,
          _index,
          _address,
          _lovelace,
          _key,
          _data,
          _link,
          _reference_script,
        ) {
          state
        },
      )
    True
  }
    |> eval_element(script_hash)
}

test fail__insert_inner_list_ascending__rejects_extra_root_key_change(
  args via insert_of_inner_list_fuzzer(RootAnchorWithNodes),
) fail {
  let InsertOfInnerListArgs {
    script_hash,
    inner_ordering,
    inputs,
    continued_anchor_output,
    new_inner_root_output,
    inner_node_outputs,
    tx_mint,
    ..
  } = args

  {
    let
      _input,
      _lovelace_change,
      _anchor_key,
      _anchor_data,
      _continued_anchor_data,
      _anchor_link,
      _final_state,
      _other_list_assets,
    <-
      insert_inner_list_ascending(
        ordering_of_inner_node_keys: inner_ordering,
        continued_anchor_element_output: continued_anchor_output,
        new_inner_root_output: new_inner_root_output,
        inputs: inputs,
        inner_node_outputs: inner_node_outputs,
        tx_mint: tx_mint |> assets.merge(one_mint(script_hash, test_root_key)),
        prepare_state: fn(_lovelace, _key, _data, _link, _reference_script) {
          True
        },
        node_validator: fn(
          state,
          _index,
          _address,
          _lovelace,
          _key,
          _data,
          _link,
          _reference_script,
        ) {
          state
        },
      )
    True
  }
    |> eval_element(script_hash)
}

test fail__insert_inner_list_ascending__missing_inner_node_mint(
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

  {
    let
      _input,
      _lovelace_change,
      _anchor_key,
      _anchor_data,
      _continued_anchor_data,
      _anchor_link,
      _final_state,
      _other_list_assets,
    <-
      insert_inner_list_ascending(
        ordering_of_inner_node_keys: inner_ordering,
        continued_anchor_element_output: continued_anchor_output,
        new_inner_root_output: new_inner_root_output,
        inputs: inputs,
        inner_node_outputs: [first_node_output, second_node_output],
        tx_mint: tx_mint,
        prepare_state: fn(_lovelace, _key, _data, _link, _reference_script) {
          True
        },
        node_validator: fn(
          state,
          _index,
          _address,
          _lovelace,
          _key,
          _data,
          _link,
          _reference_script,
        ) {
          state
        },
      )
    True
  }
    |> eval_element(script_hash)
}

test fail__insert_inner_list_ascending__bad_inner_node_link(
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

  {
    let
      _input,
      _lovelace_change,
      _anchor_key,
      _anchor_data,
      _continued_anchor_data,
      _anchor_link,
      _final_state,
      _other_list_assets,
    <-
      insert_inner_list_ascending(
        ordering_of_inner_node_keys: inner_ordering,
        continued_anchor_element_output: continued_anchor_output,
        new_inner_root_output: new_inner_root_output,
        inputs: inputs,
        inner_node_outputs: [broken_first_node_output, second_node_output],
        tx_mint: tx_mint,
        prepare_state: fn(_lovelace, _key, _data, _link, _reference_script) {
          True
        },
        node_validator: fn(
          state,
          _index,
          _address,
          _lovelace,
          _key,
          _data,
          _link,
          _reference_script,
        ) {
          state
        },
      )
    True
  }
    |> eval_element(script_hash)
}
