//// In some cases, validators need to be aware of instances of a parameterized
//// script in order to have a more robust control over the flow of assets.
//// 
//// As a simple example, consider a minting script that needs to ensure the
//// destination of its tokens can only be instances of a specific spending
//// script, e.g. parameterized by users' wallets.
//// 
//// Since each different wallet leads to a different script address, without
//// verifying instances, each script address is seen as an arbitrary script
//// address from the minting script.
//// 
//// To allow this validation on-chain, some restrictions are needed to be put
//// in place:
//// 1. Parameters of the target script must have constant lengths, which can be
////    achieved by having them hashed
//// 2. Consequently, for each transaction, the resolved value of those
////    parameters must be provided through the redeemer
//// 3. The dependent script must be provided with CBOR bytes of instances
////    before and after the parameter(s)
//// 4. Wrapping of instances' logics in an outer function so that there'll be
////    single occurances of each parameter

use aiken/collection/list
use aiken/crypto.{Hash, Sha2_256, sha2_256}
use aiken/primitive/bytearray
use cardano/transaction.{OutputReference, Transaction}

const param_header = #"a601225820"

const param_end = #"00"

/// Use this inside your dependent script for single parameter scripts. The
/// parameter must be serialised before getting passed here. It'll be hashed
/// with `sha2_256` before placement between `prefix` and `postfix`.
pub fn apply_param(
  prefix: ByteArray,
  param: ByteArray,
  postfix: ByteArray,
) -> ByteArray {
  prefix |> bytearray.concat(sha2_256(param)) |> bytearray.concat(postfix)
}

/// Similar to [`apply_param`](#apply_param), but for scripts with 2 or more
/// parameters. This is not modeled in the arguments to avoid extra overhead.
/// In other words, you can provide 0 or 1 parameters, but you shouldn't expect
/// to get correct results.
pub fn apply_params(
  prefix: ByteArray,
  params: List<ByteArray>,
  postfix: ByteArray,
) -> ByteArray {
  list.foldl(
    params,
    prefix,
    fn(param, prefix_so_far) {
      prefix_so_far
        |> bytearray.concat(param_header)
        |> bytearray.concat(sha2_256(param))
        |> bytearray.concat(param_end)
    },
  )
    |> bytearray.concat(postfix)
}

/// Datatype for redeemer of your single parameterized scripts.
pub type ParameterizedRedeemer<p, r> {
  param: p,
  redeemer: r,
}

/// Helper function for parameterized spending scripts, which takes care of
/// validating resolved parameter hashes, provides you with both the parameter,
/// and your custom redeemer.
pub fn spend_wrapper_validator(
  hashed_parameter: Hash<Sha2_256, p>,
  parameter_serialiser: fn(p) -> ByteArray,
  validator_function: fn(p, Option<d>, redeemer, OutputReference, Transaction) ->
    Bool,
  datum: Option<d>,
  outer_redeemer: ParameterizedRedeemer<p, redeemer>,
  output_reference: OutputReference,
  tx: Transaction,
) -> Bool {
  let ParameterizedRedeemer { param, redeemer } = outer_redeemer
  expect (sha2_256(parameter_serialiser(param)) == hashed_parameter)?
  validator_function(param, datum, redeemer, output_reference, tx)
}

/// Similar to [`spend_wrapper_validator`](#spend_wrapper_validator), but for
/// other endpoints that are not provided with a datum (mint, withdraw, etc.).
pub fn no_datum_wrapper_validator(
  hashed_parameter: Hash<Sha2_256, p>,
  parameter_serialiser: fn(p) -> ByteArray,
  validator_function: fn(p, redeemer, endpoint_specific, Transaction) -> Bool,
  outer_redeemer: ParameterizedRedeemer<p, redeemer>,
  variable_arg: endpoint_specific,
  tx: Transaction,
) -> Bool {
  let ParameterizedRedeemer { param, redeemer } = outer_redeemer
  expect (sha2_256(parameter_serialiser(param)) == hashed_parameter)?
  validator_function(param, redeemer, variable_arg, tx)
}

pub type ParameterizedRedeemer2<p, q, r> {
  param_0: p,
  param_1: q,
  redeemer: r,
}

pub fn spend_wrapper_validator_2(
  hashed_parameter_0: Hash<Sha2_256, p>,
  hashed_parameter_1: Hash<Sha2_256, q>,
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
      sha2_256(parameter_serialiser_0(param_0)) == hashed_parameter_0,
      sha2_256(parameter_serialiser_1(param_1)) == hashed_parameter_1,
    }?
  validator_function(param_0, param_1, datum, redeemer, output_reference, tx)
}

pub fn no_datum_wrapper_validator_2(
  hashed_parameter_0: Hash<Sha2_256, p>,
  hashed_parameter_1: Hash<Sha2_256, q>,
  parameter_serialiser_0: fn(p) -> ByteArray,
  parameter_serialiser_1: fn(q) -> ByteArray,
  validator_function: fn(p, q, redeemer, endpoint_specific, Transaction) -> Bool,
  outer_redeemer: ParameterizedRedeemer2<p, q, redeemer>,
  variable_arg: endpoint_specific,
  tx: Transaction,
) -> Bool {
  let ParameterizedRedeemer2 { param_0, param_1, redeemer } = outer_redeemer
  expect and {
      sha2_256(parameter_serialiser_0(param_0)) == hashed_parameter_0,
      sha2_256(parameter_serialiser_1(param_1)) == hashed_parameter_1,
    }?
  validator_function(param_0, param_1, redeemer, variable_arg, tx)
}

pub type ParameterizedRedeemer3<p, q, s, r> {
  param_0: p,
  param_1: q,
  param_2: s,
  redeemer: r,
}

pub fn spend_wrapper_validator_3(
  hashed_parameter_0: Hash<Sha2_256, p>,
  hashed_parameter_1: Hash<Sha2_256, q>,
  hashed_parameter_2: Hash<Sha2_256, s>,
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
      sha2_256(parameter_serialiser_0(param_0)) == hashed_parameter_0,
      sha2_256(parameter_serialiser_1(param_1)) == hashed_parameter_1,
      sha2_256(parameter_serialiser_2(param_2)) == hashed_parameter_2,
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

pub fn no_datum_wrapper_validator_3(
  hashed_parameter_0: Hash<Sha2_256, p>,
  hashed_parameter_1: Hash<Sha2_256, q>,
  hashed_parameter_2: Hash<Sha2_256, s>,
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
      sha2_256(parameter_serialiser_0(param_0)) == hashed_parameter_0,
      sha2_256(parameter_serialiser_1(param_1)) == hashed_parameter_1,
      sha2_256(parameter_serialiser_2(param_2)) == hashed_parameter_2,
    }?
  validator_function(param_0, param_1, param_2, redeemer, variable_arg, tx)
}
