use aiken/builtin
use aiken/crypto.{ScriptHash, blake2b_224, sha2_256}
use aiken/fuzz
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list.{
  Element, Head, Node, append_unordered, deinit, init, insert_ordered, remove,
  run_eval_with, run_head_with,
}
use aiken_design_patterns/utils
use cardano/address.{Address, Script, VerificationKey}
use cardano/assets.{Value}
use cardano/transaction.{InlineDatum, Input, Output, OutputReference}

// ## Tests

type GenericElement =
  Element<Data, Data>

const test_head_key = #""

const test_node_key = #"00"

const test_node_key_length = 1

const b_data = builtin.b_data(#"00")

fn change_tn_by(b: ByteArray, change: Int) -> ByteArray {
  let b_length = bytearray.length(b)
  b
    |> bytearray.to_int_big_endian
    |> fn(x: Int) -> Int { x + change }
    |> bytearray.from_int_big_endian(b_length)
}

fn two_elements_fuzzer(
  label: ByteArray,
  covering_is_head: Bool,
  node_has_link: Bool,
  consequtive: Bool,
) -> Fuzzer<(ScriptHash, Input, Input)> {
  let label_length = bytearray.length(label)
  let tn_length = 32 - label_length
  let script_hash <- fuzz.and_then(fuzz.bytearray_fixed(28))
  let no_label_tn_0 <- fuzz.and_then(fuzz.bytearray_fixed(tn_length))
  let additional_no_label_tn <- fuzz.and_then(fuzz.bytearray_fixed(tn_length))
  let no_label_tn_1 =
    if consequtive {
      no_label_tn_0 |> change_tn_by(1)
    } else {
      additional_no_label_tn
    }
  let tn_0 =
    if covering_is_head {
      test_head_key
    } else {
      label |> bytearray.concat(no_label_tn_0)
    }
  let tn_1 = label |> bytearray.concat(no_label_tn_1)
  let lovelace_value = assets.from_lovelace(2_000_000)
  let beacon_0 = assets.from_asset(script_hash, tn_0, 1)
  let beacon_1 = assets.from_asset(script_hash, tn_1, 1)
  let v_0 = assets.merge(lovelace_value, beacon_0)
  let v_1 = assets.merge(lovelace_value, beacon_1)
  let out_ref_0 <- fuzz.and_then(utils.output_reference_fuzzer())
  let out_ref_1 <- fuzz.and_then(utils.output_reference_fuzzer())
  fuzz.constant(
    (
      script_hash,
      Input {
        output_reference: out_ref_0,
        output: Output {
          address: Address {
            payment_credential: Script(script_hash),
            stake_credential: None,
          },
          value: v_0,
          datum: InlineDatum(
            Element {
              data: if covering_is_head {
                Head(b_data)
              } else {
                Node(b_data)
              },
              next_link: Some(tn_1),
            },
          ),
          reference_script: None,
        },
      },
      Input {
        output: Output {
          address: Address {
            payment_credential: Script(script_hash),
            stake_credential: None,
          },
          value: v_1,
          datum: InlineDatum(
            Element {
              data: Node(b_data),
              next_link: if node_has_link {
                Some(
                  label |> bytearray.concat(no_label_tn_1 |> change_tn_by(1)),
                )
              } else {
                None
              },
            },
          ),
          reference_script: None,
        },
        output_reference: out_ref_1,
      },
    ),
  )
}

fn alter_outputs_address(output: Output) -> Output {
  expect Script(script_hash) = output.address.payment_credential
  let altered_address: Address =
    Address {
      payment_credential: VerificationKey(script_hash),
      stake_credential: None,
    }
  Output { ..output, address: altered_address }
}

fn alter_outputs_link(output: Output) -> Output {
  expect InlineDatum(datum_data) = output.datum
  expect Element { data, next_link }: GenericElement = datum_data
  let altered_datum =
    InlineDatum(
      Element(
        data,
        when next_link is {
          None ->
            Some(#"00000000000000000000000000000000000000000000000000000000")
          Some(_) -> None
        },
      ),
    )
  Output { ..output, datum: altered_datum }
}

fn init_fuzzer(
  head_datum: Bool,
  next_link: Option<ByteArray>,
) -> Fuzzer<(List<Input>, OutputReference, ScriptHash, Output)> {
  let inputs <- fuzz.and_then(utils.user_inputs_fuzzer())
  let out_ref =
    builtin.head_list(inputs)
      |> fn(i: Input) -> OutputReference { i.output_reference }
  let (script_hash, script_output) <-
    fuzz.and_then(
      utils.authentic_script_output_with_given_asset_name_fuzzer(
        test_head_key,
        InlineDatum(
          Element {
            data: if head_datum {
              Head(b_data)
            } else {
              Node(b_data)
            },
            next_link,
          },
        ),
      ),
    )
  fuzz.constant((inputs, out_ref, script_hash, script_output))
}

test success__init(init_values via init_fuzzer(True, None)) {
  let (inputs, out_ref, script_hash, script_output) = init_values
  init(
    out_ref,
    script_output,
    script_hash,
    script_hash,
    fn(_) { True },
    inputs,
    assets.from_asset(script_hash, test_head_key, 1),
  )
    |> run_head_with(test_head_key)
}

test fail__init__bad_datum(init_values via init_fuzzer(False, None)) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  init(
    out_ref,
    script_output,
    script_hash,
    script_hash,
    fn(_) { True },
    inputs,
    assets.from_asset(script_hash, test_head_key, 1),
  )
    |> run_head_with(test_head_key)
}

test fail__init__bad_asset_name(init_values via init_fuzzer(True, None)) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  init(
    out_ref,
    script_output,
    script_hash,
    script_hash,
    fn(_) { True },
    inputs,
    assets.from_asset(script_hash, test_head_key, 1),
  )
    |> run_head_with("HEAD")
}

test fail__init__bad_nonce(init_values via init_fuzzer(True, None)) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  init(
    out_ref
      |> fn(o_ref: OutputReference) -> OutputReference {
          OutputReference {
            ..o_ref,
            transaction_id: sha2_256(o_ref.transaction_id),
          }
        },
    script_output,
    script_hash,
    script_hash,
    fn(_) { True },
    inputs,
    assets.from_asset(script_hash, test_head_key, 1),
  )
    |> run_head_with(test_head_key)
}

test fail__init__bad_first_link(
  init_values via init_fuzzer(True, Some(test_head_key)),
) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  init(
    out_ref,
    script_output,
    script_hash,
    script_hash,
    fn(_) { True },
    inputs,
    assets.from_asset(script_hash, test_head_key, 1),
  )
    |> run_head_with(test_head_key)
}

test fail__init__bad_nft_symbol(init_values via init_fuzzer(True, None)) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  init(
    out_ref,
    script_output,
    script_hash,
    blake2b_224(script_hash),
    fn(_) { True },
    inputs,
    assets.from_asset(script_hash, test_head_key, 1),
  )
    |> run_head_with(test_head_key)
}

test fail__init__bad_destination(init_values via init_fuzzer(True, None)) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  init(
    out_ref,
    script_output,
    blake2b_224(script_hash),
    script_hash,
    fn(_) { True },
    inputs,
    assets.from_asset(script_hash, test_head_key, 1),
  )
    |> run_head_with(test_head_key)
}

test fail__init__bad_head_data_validator(
  init_values via init_fuzzer(True, None),
) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  init(
    out_ref,
    script_output,
    script_hash,
    script_hash,
    fn(_) { False },
    inputs,
    assets.from_asset(script_hash, test_head_key, 1),
  )
    |> run_head_with(test_head_key)
}

test fail__init__bad_mint(init_values via init_fuzzer(True, None)) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  init(
    out_ref,
    script_output,
    script_hash,
    script_hash,
    fn(_) { True },
    inputs,
    assets.zero,
  )
    |> run_head_with(test_head_key)
}

test success__deinit(init_values via init_fuzzer(True, None)) {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let head_input = Input { output_reference: out_ref, output: script_output }
  deinit(
    head_input,
    script_hash,
    script_hash,
    fn(_) { True },
    assets.from_asset(script_hash, test_head_key, -1),
  )
    |> run_head_with(test_head_key)
}

test fail__deinit__bad_datum(init_values via init_fuzzer(False, None)) fail {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let head_input = Input { output_reference: out_ref, output: script_output }
  deinit(
    head_input,
    script_hash,
    script_hash,
    fn(_) { True },
    assets.from_asset(script_hash, test_head_key, -1),
  )
    |> run_head_with(test_head_key)
}

test fail__deinit__bad_link(
  init_values via init_fuzzer(
    True,
    Some(#"0000000000000000000000000000000000000000000000000000000000000000"),
  ),
) fail {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let head_input = Input { output_reference: out_ref, output: script_output }
  deinit(
    head_input,
    script_hash,
    script_hash,
    fn(_) { True },
    assets.from_asset(script_hash, test_head_key, -1),
  )
    |> run_head_with(test_head_key)
}

test fail__deinit__bad_origin(init_values via init_fuzzer(True, None)) fail {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let head_input = Input { output_reference: out_ref, output: script_output }
  deinit(
    head_input,
    blake2b_224(script_hash),
    script_hash,
    fn(_) { True },
    assets.from_asset(script_hash, test_head_key, -1),
  )
    |> run_head_with(test_head_key)
}

test fail__deinit__bad_nft_symbol(init_values via init_fuzzer(True, None)) fail {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let head_input = Input { output_reference: out_ref, output: script_output }
  deinit(
    head_input,
    script_hash,
    blake2b_224(script_hash),
    fn(_) { True },
    assets.from_asset(script_hash, test_head_key, -1),
  )
    |> run_head_with(test_head_key)
}

test fail__deinit__bad_head_data_validator(
  init_values via init_fuzzer(True, None),
) fail {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let head_input = Input { output_reference: out_ref, output: script_output }
  deinit(
    head_input,
    script_hash,
    script_hash,
    fn(_) { False },
    assets.from_asset(script_hash, test_head_key, -1),
  )
    |> run_head_with(test_head_key)
}

test fail__deinit__bad_mint(init_values via init_fuzzer(True, None)) fail {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let head_input = Input { output_reference: out_ref, output: script_output }
  deinit(head_input, script_hash, script_hash, fn(_) { True }, assets.zero)
    |> run_head_with(test_head_key)
}

fn addition_test_helper(
  covering_is_head: Bool,
  args: (ScriptHash, Input, Input),
) -> Fuzzer<(ScriptHash, Input, Output, Output, Value)> {
  let (script_hash, cont_head_input, node_input) = args
  expect InlineDatum(node_datum_data) = node_input.output.datum
  expect Element { next_link: nodes_next_link, .. }: GenericElement =
    node_datum_data
  let head_element: GenericElement =
    Element(
      if covering_is_head {
        Head(b_data)
      } else {
        Node(b_data)
      },
      nodes_next_link,
    )
  let head_output: Output =
    Output { ..cont_head_input.output, datum: InlineDatum(head_element) }
  let head_input: Input = Input { ..cont_head_input, output: head_output }
  fuzz.constant(
    (
      script_hash,
      head_input,
      cont_head_input.output,
      node_input.output,
      node_input.output.value |> assets.without_lovelace,
    ),
  )
}

fn insert_ordered_fuzzer() -> Fuzzer<(ScriptHash, Input, Output, Output, Value)> {
  let label = test_node_key
  let covering_is_head <- fuzz.and_then(fuzz.bool())
  let node_has_link <- fuzz.and_then(fuzz.bool())
  let args <-
    fuzz.and_then(
      two_elements_fuzzer(label, covering_is_head, node_has_link, True),
    )
  addition_test_helper(covering_is_head, args)
}

test success__insert(insert_ordered_args via insert_ordered_fuzzer()) {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    insert_ordered_args
  insert_ordered(
    script_hash,
    head_input,
    cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__insert__bad_nft_symbol(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    insert_ordered_args
  insert_ordered(
    blake2b_224(script_hash),
    head_input,
    cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__insert__bad_continued_head_destination(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    insert_ordered_args
  insert_ordered(
    script_hash,
    head_input,
    alter_outputs_address(cont_head_output),
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__insert__bad_node_destination(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    insert_ordered_args
  insert_ordered(
    script_hash,
    head_input,
    cont_head_output,
    alter_outputs_address(node_output),
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__insert__bad_continued_head_link(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    insert_ordered_args
  insert_ordered(
    script_hash,
    head_input,
    alter_outputs_link(cont_head_output),
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__insert__bad_node_link(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    insert_ordered_args
  insert_ordered(
    script_hash,
    head_input,
    cont_head_output,
    alter_outputs_link(node_output),
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__insert__bad_additional_validator(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    insert_ordered_args
  insert_ordered(
    script_hash,
    head_input,
    cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      False
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__insert__bad_mint(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, _mint_value) =
    insert_ordered_args
  insert_ordered(
    script_hash,
    head_input,
    cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    assets.zero,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

fn append_unordered_fuzzer(
  node_has_link: Bool,
) -> Fuzzer<(ScriptHash, Input, Output, Output, Value)> {
  let label = test_node_key
  let covering_is_head <- fuzz.and_then(fuzz.bool())
  let args <-
    fuzz.and_then(
      two_elements_fuzzer(label, covering_is_head, node_has_link, False),
    )
  addition_test_helper(covering_is_head, args)
}

test success__append(append_unordered_args via append_unordered_fuzzer(False)) {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  append_unordered(
    script_hash,
    head_input,
    cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__append__node_has_link(
  append_unordered_args via append_unordered_fuzzer(True),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  append_unordered(
    script_hash,
    head_input,
    cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__append__bad_nft_symbol(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  append_unordered(
    blake2b_224(script_hash),
    head_input,
    cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__append__bad_continued_head_destination(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  let altered_cont_head_output = alter_outputs_address(cont_head_output)
  append_unordered(
    script_hash,
    head_input,
    altered_cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__append__bad_node_destination(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  let altered_node_output = alter_outputs_address(node_output)
  append_unordered(
    script_hash,
    head_input,
    cont_head_output,
    altered_node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__append__bad_continued_head_link(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  let altered_cont_head_output = alter_outputs_link(cont_head_output)
  append_unordered(
    script_hash,
    head_input,
    altered_cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__append__bad_node_link(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, mint_value) =
    append_unordered_args
  let altered_node_output = alter_outputs_link(node_output)
  append_unordered(
    script_hash,
    head_input,
    cont_head_output,
    altered_node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__append__bad_mint(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  let (script_hash, head_input, cont_head_output, node_output, _mint_value) =
    append_unordered_args
  append_unordered(
    script_hash,
    head_input,
    cont_head_output,
    node_output,
    fn(_out_ref, _is_head, _head_key, _head_data, _new_key, _new_node_data) {
      True
    },
    assets.zero,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

fn remove_fuzzer() -> Fuzzer<(ScriptHash, Input, Input, Output, Value)> {
  let label = test_node_key
  let covering_is_head <- fuzz.and_then(fuzz.bool())
  let node_has_link <- fuzz.and_then(fuzz.bool())
  let (script_hash, head_input, node_input) <-
    fuzz.and_then(
      two_elements_fuzzer(label, covering_is_head, node_has_link, False),
    )
  expect InlineDatum(node_datum_data) = node_input.output.datum
  expect Element { next_link: nodes_next_link, .. }: GenericElement =
    node_datum_data
  let cont_head_element: GenericElement =
    Element(
      if covering_is_head {
        Head(b_data)
      } else {
        Node(b_data)
      },
      nodes_next_link,
    )
  let cont_head_output: Output =
    Output { ..head_input.output, datum: InlineDatum(cont_head_element) }
  fuzz.constant(
    (
      script_hash,
      head_input,
      node_input,
      cont_head_output,
      node_input.output.value |> assets.without_lovelace |> assets.negate,
    ),
  )
}

test success__remove(remove_args via remove_fuzzer()) {
  let (script_hash, head_input, node_input, cont_head_output, mint_value) =
    remove_args
  remove(
    script_hash,
    head_input,
    node_input,
    cont_head_output,
    fn(
      _out_ref,
      _is_head,
      _head_key,
      _head_data,
      _removing_key,
      _removing_node_data,
    ) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__remove__bad_nft_symbol(remove_args via remove_fuzzer()) fail {
  let (script_hash, head_input, node_input, cont_head_output, mint_value) =
    remove_args
  remove(
    blake2b_224(script_hash),
    head_input,
    node_input,
    cont_head_output,
    fn(
      _out_ref,
      _is_head,
      _head_key,
      _head_data,
      _removing_key,
      _removing_node_data,
    ) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__remove__bad_continued_head_destination(
  remove_args via remove_fuzzer(),
) fail {
  let (script_hash, head_input, node_input, cont_head_output, mint_value) =
    remove_args
  remove(
    script_hash,
    head_input,
    node_input,
    alter_outputs_address(cont_head_output),
    fn(
      _out_ref,
      _is_head,
      _head_key,
      _head_data,
      _removing_key,
      _removing_node_data,
    ) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__remove__bad_continued_head_link(remove_args via remove_fuzzer()) fail {
  let (script_hash, head_input, node_input, cont_head_output, mint_value) =
    remove_args
  remove(
    script_hash,
    head_input,
    node_input,
    alter_outputs_link(cont_head_output),
    fn(
      _out_ref,
      _is_head,
      _head_key,
      _head_data,
      _removing_key,
      _removing_node_data,
    ) {
      True
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__remove__bad_additional_validator(
  remove_args via remove_fuzzer(),
) fail {
  let (script_hash, head_input, node_input, cont_head_output, mint_value) =
    remove_args
  remove(
    script_hash,
    head_input,
    node_input,
    cont_head_output,
    fn(
      _out_ref,
      _is_head,
      _head_key,
      _head_data,
      _removing_key,
      _removing_node_data,
    ) {
      False
    },
    mint_value,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__remove__bad_mint(remove_args via remove_fuzzer()) fail {
  let (script_hash, head_input, node_input, cont_head_output, _mint_value) =
    remove_args
  remove(
    script_hash,
    head_input,
    node_input,
    cont_head_output,
    fn(
      _out_ref,
      _is_head,
      _head_key,
      _head_data,
      _removing_key,
      _removing_node_data,
    ) {
      True
    },
    assets.zero,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}

test fail__remove__covering_burnt(remove_args via remove_fuzzer()) fail {
  let (script_hash, head_input, node_input, cont_head_output, _mint_value) =
    remove_args
  remove(
    script_hash,
    head_input,
    node_input,
    node_input.output,
    fn(
      _out_ref,
      _is_head,
      _head_key,
      _head_data,
      _removing_key,
      _removing_node_data,
    ) {
      True
    },
    cont_head_output.value |> assets.without_lovelace |> assets.negate,
  )
    |> run_eval_with(test_head_key, test_node_key, test_node_key_length)
}
