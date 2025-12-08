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
//// value for your target script to utilize. Note that your prefix should be
//// from a single CBOR encoded result.

use aiken/builtin
use aiken/crypto.{Blake2b_224, Hash, ScriptHash, blake2b_224}
use aiken/primitive/bytearray

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

/// Use this inside your contracts that depend on scripts with single
/// parameters. The parameter must be serialised before getting passed here.
/// It'll be hashed with `blake2b_224` before placement after `prefix`.
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
/// Can be used for any hashing algorithms, i.e. the length of the provided hash
/// does not matter (`prefix` covers it).
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
///
/// Note that while the first parameter (`param_0`) can still be of any length,
/// `blake2b_224` is the presumed hashing algorithm for the second parameter,
/// i.e. the parameter is expected to be 28 bytes long.
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
///
/// Here again the first parameter can be of arbitrary length, while the other
/// two must be 28 bytes long.
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

/// Helper function for parameterized scripts, which takes care of validating
/// resolved parameter hashes, provides you with both the parameter, and your
/// custom redeemer.
pub fn wrapper(
  hashed_parameter: Hash<Blake2b_224, p>,
  parameter_serialiser: fn(p) -> ByteArray,
  outer_redeemer: ParameterizedRedeemer<p, redeemer>,
  validator_function: fn(p, redeemer) -> Bool,
) -> Bool {
  let ParameterizedRedeemer { param, redeemer } = outer_redeemer
  expect blake2b_224(parameter_serialiser(param)) == hashed_parameter
  validator_function(param, redeemer)
}

pub type ParameterizedRedeemer2<p, q, r> {
  param_0: p,
  param_1: q,
  redeemer: r,
}

pub fn wrapper_2(
  hashed_parameter_0: Hash<Blake2b_224, p>,
  hashed_parameter_1: Hash<Blake2b_224, q>,
  parameter_serialiser_0: fn(p) -> ByteArray,
  parameter_serialiser_1: fn(q) -> ByteArray,
  outer_redeemer: ParameterizedRedeemer2<p, q, r>,
  validator_function: fn(p, q, r) -> Bool,
) -> Bool {
  let ParameterizedRedeemer2 { param_0, param_1, redeemer } = outer_redeemer
  expect and {
      blake2b_224(parameter_serialiser_0(param_0)) == hashed_parameter_0,
      blake2b_224(parameter_serialiser_1(param_1)) == hashed_parameter_1,
    }
  validator_function(param_0, param_1, redeemer)
}

pub type ParameterizedRedeemer3<p, q, s, r> {
  param_0: p,
  param_1: q,
  param_2: s,
  redeemer: r,
}

pub fn wrapper_3(
  hashed_parameter_0: Hash<Blake2b_224, p>,
  hashed_parameter_1: Hash<Blake2b_224, q>,
  hashed_parameter_2: Hash<Blake2b_224, s>,
  parameter_serialiser_0: fn(p) -> ByteArray,
  parameter_serialiser_1: fn(q) -> ByteArray,
  parameter_serialiser_2: fn(s) -> ByteArray,
  outer_redeemer: ParameterizedRedeemer3<p, q, s, r>,
  validator_function: fn(p, q, s, r) -> Bool,
) -> Bool {
  let ParameterizedRedeemer3 { param_0, param_1, param_2, redeemer } =
    outer_redeemer
  expect and {
      blake2b_224(parameter_serialiser_0(param_0)) == hashed_parameter_0,
      blake2b_224(parameter_serialiser_1(param_1)) == hashed_parameter_1,
      blake2b_224(parameter_serialiser_2(param_2)) == hashed_parameter_2,
    }
  validator_function(param_0, param_1, param_2, redeemer)
}

/// Datatype for parameterized scripts that don't need a redeemer.
pub type Parameter<p> {
  param: p,
}

/// Wrapper function for scripts with one parameter that don't need a redeemer.
pub fn wrapper_no_redeemer(
  hashed_parameter: Hash<Blake2b_224, p>,
  parameter_serialiser: fn(p) -> ByteArray,
  outer_redeemer: Parameter<p>,
  validator_function: fn(p) -> Bool,
) -> Bool {
  let Parameter { param } = outer_redeemer
  expect blake2b_224(parameter_serialiser(param)) == hashed_parameter
  validator_function(param)
}

pub type Parameter2<p, q> {
  param_0: p,
  param_1: q,
}

pub fn wrapper_no_redeemer_2(
  hashed_parameter_0: Hash<Blake2b_224, p>,
  hashed_parameter_1: Hash<Blake2b_224, q>,
  parameter_serialiser_0: fn(p) -> ByteArray,
  parameter_serialiser_1: fn(q) -> ByteArray,
  outer_redeemer: Parameter2<p, q>,
  validator_function: fn(p, q) -> Bool,
) -> Bool {
  let Parameter2 { param_0, param_1 } = outer_redeemer
  expect and {
      blake2b_224(parameter_serialiser_0(param_0)) == hashed_parameter_0,
      blake2b_224(parameter_serialiser_1(param_1)) == hashed_parameter_1,
    }
  validator_function(param_0, param_1)
}

pub type Parameter3<p, q, s> {
  param_0: p,
  param_1: q,
  param_2: s,
}

pub fn wrapper_no_redeemer_3(
  hashed_parameter_0: Hash<Blake2b_224, p>,
  hashed_parameter_1: Hash<Blake2b_224, q>,
  hashed_parameter_2: Hash<Blake2b_224, q>,
  parameter_serialiser_0: fn(p) -> ByteArray,
  parameter_serialiser_1: fn(q) -> ByteArray,
  parameter_serialiser_2: fn(s) -> ByteArray,
  outer_redeemer: Parameter3<p, q, s>,
  validator_function: fn(p, q, s) -> Bool,
) -> Bool {
  let Parameter3 { param_0, param_1, param_2 } = outer_redeemer
  expect and {
      blake2b_224(parameter_serialiser_0(param_0)) == hashed_parameter_0,
      blake2b_224(parameter_serialiser_1(param_1)) == hashed_parameter_1,
      blake2b_224(parameter_serialiser_2(param_2)) == hashed_parameter_2,
    }
  validator_function(param_0, param_1, param_2)
}
