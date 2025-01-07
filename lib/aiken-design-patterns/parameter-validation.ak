//// In some cases, validators need to be aware of instances of a parameterized
//// script in order to have a more robust control over the flow of assets.
//// 
//// As a simple example, consider a minting script that needs to ensure the
//// destination of its tokens can only be instances of a specific spending
//// script, e.g. parameterized by users' wallets.
//// 
//// Since each different wallet leads to a different script address, without
//// verifying instances, instances can only be seen as arbitrary scripts from
//// the minting script's point of view.
//// 
//// This can be resolved by validating an instance is the result of applying
//// specific parameters to a given parameterized script.
//// 
//// To allow this validation on-chain, some restrictions are needed:
//// 1. Parameters of the script must have constant lengths, which can be
////    achieved by having them hashed
//// 2. Consequently, for each transaction, the resolved value of those
////    parameters must be provided through the redeemer
//// 3. The dependent script must be provided with CBOR bytes of instances
////    before and after the parameter(s)
//// 4. Wrapping of instances' logics in an outer function so that there'll be
////    single occurances of each parameter
//// 
//// This pattern provides two sets of functions. One for applying parameter(s)
//// in the dependent script (i.e. the minting script in the example above), and
//// one for wrapping your parameterized scripts with.
//// 
//// After defining your parameterized scripts, you'll need to generate
//// instances of them with dummy data in order to obtain the required `prefix`
//// and `postfix` values for your target script to utilize.

use aiken/builtin
use aiken/crypto.{Blake2b_224, Hash, ScriptHash, blake2b_224}
use aiken/primitive/bytearray
use cardano/transaction.{OutputReference, Transaction}

const param_header_28_bytes = #"004c011e581c"

const postfix: ByteArray = #"0001"

fn append_first_param_to_prefix(
  version: Int,
  prefix: ByteArray,
  param: ByteArray,
) -> ByteArray {
  builtin.integer_to_bytearray(True, 1, version)
    |> bytearray.concat(prefix)
    |> bytearray.concat(blake2b_224(param))
}

fn append_param(prefix: ByteArray, param: ByteArray) -> ByteArray {
  prefix
    |> bytearray.concat(blake2b_224(param))
}

fn append_first_prehashed_param_to_prefix(
  version: Int,
  prefix: ByteArray,
  param: ByteArray,
) -> ByteArray {
  builtin.integer_to_bytearray(True, 1, version)
    |> bytearray.concat(prefix)
    |> bytearray.concat(param)
}

/// Use this inside your dependent script for single parameter scripts. The
/// parameter must be serialised before getting passed here. It'll be hashed
/// with `blake2b_224` before placement after `prefix`.
///
/// Note that your prefix should be from a single CBOR encoded result. And also,
/// the version should either be 1, 2, or 3 depending on your script.
pub fn apply_param(
  version: Int,
  prefix: ByteArray,
  param: ByteArray,
) -> ScriptHash {
  append_first_param_to_prefix(version, prefix, param)
    |> bytearray.concat(postfix)
    |> blake2b_224
}

/// Similar to [`apply_param`](#apply_param), but for scripts that their
/// parameters don't need to be resolved (e.g. have a script hash as their
/// parameter).
///
/// Note that `blake2b_224` is the presumed hashing algorithm, i.e. the
/// parameter is expected to be 28 bytes long.
pub fn apply_prehashed_param(
  version: Int,
  prefix: ByteArray,
  param: ByteArray,
) -> ScriptHash {
  append_first_prehashed_param_to_prefix(version, prefix, param)
    |> bytearray.concat(postfix)
    |> blake2b_224
}

/// Similar to [`apply_param`](#apply_param), but for scripts with 2 parameters.
pub fn apply_param_2(
  version: Int,
  prefix: ByteArray,
  param_0: ByteArray,
  param_1: ByteArray,
) -> ScriptHash {
  append_first_param_to_prefix(version, prefix, param_0)
    |> bytearray.concat(param_header_28_bytes)
    |> append_param(param_1)
    |> bytearray.concat(postfix)
    |> blake2b_224
}

/// Similar to [`apply_prehashed_param`](#apply_prehashed_param), but for
/// scripts with 2 parameters.
pub fn apply_prehashed_param_2(
  version: Int,
  prefix: ByteArray,
  param_0: ByteArray,
  param_1: ByteArray,
) -> ScriptHash {
  append_first_prehashed_param_to_prefix(version, prefix, param_0)
    |> bytearray.concat(param_header_28_bytes)
    |> bytearray.concat(param_1)
    |> bytearray.concat(postfix)
    |> blake2b_224
}

/// Similar to [`apply_param`](#apply_param), but for scripts with 3 parameters.
pub fn apply_param_3(
  version: Int,
  prefix: ByteArray,
  param_0: ByteArray,
  param_1: ByteArray,
  param_2: ByteArray,
) -> ScriptHash {
  append_first_param_to_prefix(version, prefix, param_0)
    |> bytearray.concat(param_header_28_bytes)
    |> append_param(param_1)
    |> bytearray.concat(param_header_28_bytes)
    |> append_param(param_2)
    |> bytearray.concat(postfix)
    |> blake2b_224
}

/// Similar to [`apply_prehashed_param`](#apply_prehashed_param), but for
/// scripts with 3 parameters.
pub fn apply_prehashed_param_3(
  version: Int,
  prefix: ByteArray,
  param_0: ByteArray,
  param_1: ByteArray,
  param_2: ByteArray,
) -> ScriptHash {
  append_first_prehashed_param_to_prefix(version, prefix, param_0)
    |> bytearray.concat(param_header_28_bytes)
    |> bytearray.concat(param_1)
    |> bytearray.concat(param_header_28_bytes)
    |> bytearray.concat(param_2)
    |> bytearray.concat(postfix)
    |> blake2b_224
}

/// Datatype for redeemer of your single parameterized scripts.
pub type ParameterizedRedeemer<p, r> {
  param: p,
  redeemer: r,
}

/// Helper function for parameterized spending scripts, which takes care of
/// validating resolved parameter hashes, provides you with both the parameter,
/// and your custom redeemer.
pub fn spend_wrapper(
  hashed_parameter: Hash<Blake2b_224, p>,
  parameter_serialiser: fn(p) -> ByteArray,
  validator_function: fn(p, Option<d>, redeemer, OutputReference, Transaction) ->
    Bool,
  datum: Option<d>,
  outer_redeemer: ParameterizedRedeemer<p, redeemer>,
  output_reference: OutputReference,
  tx: Transaction,
) -> Bool {
  let ParameterizedRedeemer { param, redeemer } = outer_redeemer
  expect (blake2b_224(parameter_serialiser(param)) == hashed_parameter)?
  validator_function(param, datum, redeemer, output_reference, tx)
}

/// Similar to [`spend_wrapper`](#spend_wrapper), but for other endpoints that
/// are not provided with a datum (mint, withdraw, etc.).
pub fn no_datum_wrapper(
  hashed_parameter: Hash<Blake2b_224, p>,
  parameter_serialiser: fn(p) -> ByteArray,
  validator_function: fn(p, redeemer, endpoint_specific, Transaction) -> Bool,
  outer_redeemer: ParameterizedRedeemer<p, redeemer>,
  variable_arg: endpoint_specific,
  tx: Transaction,
) -> Bool {
  let ParameterizedRedeemer { param, redeemer } = outer_redeemer
  expect (blake2b_224(parameter_serialiser(param)) == hashed_parameter)?
  validator_function(param, redeemer, variable_arg, tx)
}

pub type ParameterizedRedeemer2<p, q, r> {
  param_0: p,
  param_1: q,
  redeemer: r,
}

pub fn spend_wrapper_2(
  hashed_parameter_0: Hash<Blake2b_224, p>,
  hashed_parameter_1: Hash<Blake2b_224, q>,
  parameter_serialiser_0: fn(p) -> ByteArray,
  parameter_serialiser_1: fn(q) -> ByteArray,
  validator_function: fn(p, q, Option<d>, r, OutputReference, Transaction) ->
    Bool,
  datum: Option<d>,
  outer_redeemer: ParameterizedRedeemer2<p, q, r>,
  output_reference: OutputReference,
  tx: Transaction,
) -> Bool {
  let ParameterizedRedeemer2 { param_0, param_1, redeemer } = outer_redeemer
  expect and {
      blake2b_224(parameter_serialiser_0(param_0)) == hashed_parameter_0,
      blake2b_224(parameter_serialiser_1(param_1)) == hashed_parameter_1,
    }?
  validator_function(param_0, param_1, datum, redeemer, output_reference, tx)
}

pub fn no_datum_wrapper_2(
  hashed_parameter_0: Hash<Blake2b_224, p>,
  hashed_parameter_1: Hash<Blake2b_224, q>,
  parameter_serialiser_0: fn(p) -> ByteArray,
  parameter_serialiser_1: fn(q) -> ByteArray,
  validator_function: fn(p, q, redeemer, endpoint_specific, Transaction) -> Bool,
  outer_redeemer: ParameterizedRedeemer2<p, q, redeemer>,
  variable_arg: endpoint_specific,
  tx: Transaction,
) -> Bool {
  let ParameterizedRedeemer2 { param_0, param_1, redeemer } = outer_redeemer
  expect and {
      blake2b_224(parameter_serialiser_0(param_0)) == hashed_parameter_0,
      blake2b_224(parameter_serialiser_1(param_1)) == hashed_parameter_1,
    }?
  validator_function(param_0, param_1, redeemer, variable_arg, tx)
}

pub type ParameterizedRedeemer3<p, q, s, r> {
  param_0: p,
  param_1: q,
  param_2: s,
  redeemer: r,
}

pub fn spend_wrapper_3(
  hashed_parameter_0: Hash<Blake2b_224, p>,
  hashed_parameter_1: Hash<Blake2b_224, q>,
  hashed_parameter_2: Hash<Blake2b_224, s>,
  parameter_serialiser_0: fn(p) -> ByteArray,
  parameter_serialiser_1: fn(q) -> ByteArray,
  parameter_serialiser_2: fn(s) -> ByteArray,
  validator_function: fn(p, q, s, Option<d>, r, OutputReference, Transaction) ->
    Bool,
  datum: Option<d>,
  outer_redeemer: ParameterizedRedeemer3<p, q, s, r>,
  output_reference: OutputReference,
  tx: Transaction,
) -> Bool {
  let ParameterizedRedeemer3 { param_0, param_1, param_2, redeemer } =
    outer_redeemer
  expect and {
      blake2b_224(parameter_serialiser_0(param_0)) == hashed_parameter_0,
      blake2b_224(parameter_serialiser_1(param_1)) == hashed_parameter_1,
      blake2b_224(parameter_serialiser_2(param_2)) == hashed_parameter_2,
    }?
  validator_function(
    param_0,
    param_1,
    param_2,
    datum,
    redeemer,
    output_reference,
    tx,
  )
}

pub fn no_datum_wrapper_3(
  hashed_parameter_0: Hash<Blake2b_224, p>,
  hashed_parameter_1: Hash<Blake2b_224, q>,
  hashed_parameter_2: Hash<Blake2b_224, s>,
  parameter_serialiser_0: fn(p) -> ByteArray,
  parameter_serialiser_1: fn(q) -> ByteArray,
  parameter_serialiser_2: fn(s) -> ByteArray,
  validator_function: fn(p, q, s, redeemer, endpoint_specific, Transaction) ->
    Bool,
  outer_redeemer: ParameterizedRedeemer3<p, q, s, redeemer>,
  variable_arg: endpoint_specific,
  tx: Transaction,
) -> Bool {
  let ParameterizedRedeemer3 { param_0, param_1, param_2, redeemer } =
    outer_redeemer
  expect and {
      blake2b_224(parameter_serialiser_0(param_0)) == hashed_parameter_0,
      blake2b_224(parameter_serialiser_1(param_1)) == hashed_parameter_1,
      blake2b_224(parameter_serialiser_2(param_2)) == hashed_parameter_2,
    }?
  validator_function(param_0, param_1, param_2, redeemer, variable_arg, tx)
}

/// Datatype for parameterized scripts that don't need a redeemer.
pub type Parameter<p> {
  param: p,
}

/// Wrapper function for spending scripts with one parameter that don't need a
/// redeemer.
pub fn spend_wrapper_no_redeemer(
  hashed_parameter: Hash<Blake2b_224, p>,
  parameter_serialiser: fn(p) -> ByteArray,
  validator_function: fn(p, Option<d>, OutputReference, Transaction) -> Bool,
  datum: Option<d>,
  outer_redeemer: Parameter<p>,
  output_reference: OutputReference,
  tx: Transaction,
) -> Bool {
  let Parameter { param } = outer_redeemer
  expect (blake2b_224(parameter_serialiser(param)) == hashed_parameter)?
  validator_function(param, datum, output_reference, tx)
}

/// Wrapper function for datumless scripts with one parameters that don't need a
/// redeemer.
pub fn no_datum_wrapper_no_redeemer(
  hashed_parameter: Hash<Blake2b_224, p>,
  parameter_serialiser: fn(p) -> ByteArray,
  validator_function: fn(p, endpoint_specific, Transaction) -> Bool,
  outer_redeemer: Parameter<p>,
  variable_arg: endpoint_specific,
  tx: Transaction,
) -> Bool {
  let Parameter { param } = outer_redeemer
  expect (blake2b_224(parameter_serialiser(param)) == hashed_parameter)?
  validator_function(param, variable_arg, tx)
}

pub type Parameter2<p, q> {
  param_0: p,
  param_1: q,
}

pub fn spend_wrapper_no_redeemer_2(
  hashed_parameter_0: Hash<Blake2b_224, p>,
  hashed_parameter_1: Hash<Blake2b_224, q>,
  parameter_serialiser_0: fn(p) -> ByteArray,
  parameter_serialiser_1: fn(q) -> ByteArray,
  validator_function: fn(p, q, Option<d>, OutputReference, Transaction) -> Bool,
  datum: Option<d>,
  outer_redeemer: Parameter2<p, q>,
  output_reference: OutputReference,
  tx: Transaction,
) -> Bool {
  let Parameter2 { param_0, param_1 } = outer_redeemer
  expect and {
      blake2b_224(parameter_serialiser_0(param_0)) == hashed_parameter_0,
      blake2b_224(parameter_serialiser_1(param_1)) == hashed_parameter_1,
    }?
  validator_function(param_0, param_1, datum, output_reference, tx)
}

pub fn no_datum_wrapper_no_redeemer_2(
  hashed_parameter_0: Hash<Blake2b_224, p>,
  hashed_parameter_1: Hash<Blake2b_224, q>,
  parameter_serialiser_0: fn(p) -> ByteArray,
  parameter_serialiser_1: fn(q) -> ByteArray,
  validator_function: fn(p, q, endpoint_specific, Transaction) -> Bool,
  outer_redeemer: Parameter2<p, q>,
  variable_arg: endpoint_specific,
  tx: Transaction,
) -> Bool {
  let Parameter2 { param_0, param_1 } = outer_redeemer
  expect and {
      blake2b_224(parameter_serialiser_0(param_0)) == hashed_parameter_0,
      blake2b_224(parameter_serialiser_1(param_1)) == hashed_parameter_1,
    }?
  validator_function(param_0, param_1, variable_arg, tx)
}

pub type Parameter3<p, q, s> {
  param_0: p,
  param_1: q,
  param_2: s,
}

pub fn spend_wrapper_no_redeemer_3(
  hashed_parameter_0: Hash<Blake2b_224, p>,
  hashed_parameter_1: Hash<Blake2b_224, q>,
  hashed_parameter_2: Hash<Blake2b_224, q>,
  parameter_serialiser_0: fn(p) -> ByteArray,
  parameter_serialiser_1: fn(q) -> ByteArray,
  parameter_serialiser_2: fn(s) -> ByteArray,
  validator_function: fn(p, q, s, Option<d>, OutputReference, Transaction) ->
    Bool,
  datum: Option<d>,
  outer_redeemer: Parameter3<p, q, s>,
  output_reference: OutputReference,
  tx: Transaction,
) -> Bool {
  let Parameter3 { param_0, param_1, param_2 } = outer_redeemer
  expect and {
      blake2b_224(parameter_serialiser_0(param_0)) == hashed_parameter_0,
      blake2b_224(parameter_serialiser_1(param_1)) == hashed_parameter_1,
      blake2b_224(parameter_serialiser_2(param_2)) == hashed_parameter_2,
    }?
  validator_function(param_0, param_1, param_2, datum, output_reference, tx)
}

pub fn no_datum_wrapper_no_redeemer_3(
  hashed_parameter_0: Hash<Blake2b_224, p>,
  hashed_parameter_1: Hash<Blake2b_224, q>,
  hashed_parameter_2: Hash<Blake2b_224, q>,
  parameter_serialiser_0: fn(p) -> ByteArray,
  parameter_serialiser_1: fn(q) -> ByteArray,
  parameter_serialiser_2: fn(s) -> ByteArray,
  validator_function: fn(p, q, s, endpoint_specific, Transaction) -> Bool,
  outer_redeemer: Parameter3<p, q, s>,
  variable_arg: endpoint_specific,
  tx: Transaction,
) -> Bool {
  let Parameter3 { param_0, param_1, param_2 } = outer_redeemer
  expect and {
      blake2b_224(parameter_serialiser_0(param_0)) == hashed_parameter_0,
      blake2b_224(parameter_serialiser_1(param_1)) == hashed_parameter_1,
      blake2b_224(parameter_serialiser_2(param_2)) == hashed_parameter_2,
    }?
  validator_function(param_0, param_1, param_2, variable_arg, tx)
}

/// Helper function for spending scripts that are parameterized by a single hash
/// value which is not needed to be resolved.
///
/// The purpose of theses wrappers is to make the parameters appear only once in
/// the resulting CBORs.
pub fn prehashed_param_spend_wrapper(
  validator_function: fn(
    Hash<Blake2b_224, a>,
    Option<d>,
    redeemer,
    OutputReference,
    Transaction,
  ) ->
    Bool,
  parameter: Hash<Blake2b_224, a>,
  datum: Option<d>,
  redeemer: redeemer,
  output_reference: OutputReference,
  tx: Transaction,
) -> Bool {
  validator_function(parameter, datum, redeemer, output_reference, tx)
}

/// Similar to [`prehashed_param_spend_wrapper`](#prehashed_param_spend_wrapper), but
/// for other endpoints that are not provided with a datum (mint, withdraw,
/// etc.).
pub fn prehashed_param_no_datum_wrapper(
  validator_function: fn(
    Hash<Blake2b_224, a>,
    redeemer,
    endpoint_specific,
    Transaction,
  ) ->
    Bool,
  param: Hash<Blake2b_224, a>,
  redeemer: redeemer,
  variable_arg: endpoint_specific,
  tx: Transaction,
) -> Bool {
  validator_function(param, redeemer, variable_arg, tx)
}

pub fn prehashed_param_spend_wrapper_2(
  validator_function: fn(
    Hash<Blake2b_224, a>,
    Hash<Blake2b_224, b>,
    Option<d>,
    redeemer,
    OutputReference,
    Transaction,
  ) ->
    Bool,
  parameter_0: Hash<Blake2b_224, a>,
  parameter_1: Hash<Blake2b_224, b>,
  datum: Option<d>,
  redeemer: redeemer,
  output_reference: OutputReference,
  tx: Transaction,
) -> Bool {
  validator_function(
    parameter_0,
    parameter_1,
    datum,
    redeemer,
    output_reference,
    tx,
  )
}

pub fn prehashed_param_no_datum_wrapper_2(
  validator_function: fn(
    Hash<Blake2b_224, a>,
    Hash<Blake2b_224, b>,
    redeemer,
    endpoint_specific,
    Transaction,
  ) ->
    Bool,
  parameter_0: Hash<Blake2b_224, a>,
  parameter_1: Hash<Blake2b_224, b>,
  redeemer: redeemer,
  variable_arg: endpoint_specific,
  tx: Transaction,
) -> Bool {
  validator_function(parameter_0, parameter_1, redeemer, variable_arg, tx)
}

pub fn prehashed_param_spend_wrapper_3(
  validator_function: fn(
    Hash<Blake2b_224, a>,
    Hash<Blake2b_224, b>,
    Hash<Blake2b_224, c>,
    Option<d>,
    redeemer,
    OutputReference,
    Transaction,
  ) ->
    Bool,
  parameter_0: Hash<Blake2b_224, a>,
  parameter_1: Hash<Blake2b_224, b>,
  parameter_2: Hash<Blake2b_224, c>,
  datum: Option<d>,
  redeemer: redeemer,
  output_reference: OutputReference,
  tx: Transaction,
) -> Bool {
  validator_function(
    parameter_0,
    parameter_1,
    parameter_2,
    datum,
    redeemer,
    output_reference,
    tx,
  )
}

pub fn prehashed_param_no_datum_wrapper_3(
  validator_function: fn(
    Hash<Blake2b_224, a>,
    Hash<Blake2b_224, b>,
    Hash<Blake2b_224, c>,
    redeemer,
    endpoint_specific,
    Transaction,
  ) ->
    Bool,
  parameter_0: Hash<Blake2b_224, a>,
  parameter_1: Hash<Blake2b_224, b>,
  parameter_2: Hash<Blake2b_224, c>,
  redeemer: redeemer,
  variable_arg: endpoint_specific,
  tx: Transaction,
) -> Bool {
  validator_function(
    parameter_0,
    parameter_1,
    parameter_2,
    redeemer,
    variable_arg,
    tx,
  )
}
