//// Advanced parameter-application helpers for arbitrary `Data` parameters.
////
//// Unlike the base helpers, this reconstructs the final applied script from
//// the Flat prefix immediately before the parameter payload, and serialises
//// the parameter as Plutus `Data` on-chain.
////
//// The script instance must be parameterised off-chain with the canonical CBOR
//// emitted by `aiken/cbor.serialise`. A semantically equivalent, non-canonical
//// CBOR encoding produces different script bytes and therefore a different hash.

use aiken/builtin
use aiken/cbor
use aiken/crypto.{ScriptHash, blake2b_224}
use aiken/primitive/bytearray

const flat_bytestring_tail = #"01"

const max_flat_bytestring_chunk_size = 255

/// Apply a single `Data` parameter to a script Flat prefix and return the
/// resulting script hash.
///
/// `flat_prefix_without_parameter_header` must contain the Flat bytes of the
/// script up to, but not including, the Flat bytestring chunk-length byte for
/// the parameter payload. The outer CBOR bytestring header must not be included.
/// The script instance must use the canonical parameter CBOR produced by
/// `cbor.serialise`.
pub fn apply_param(
  version: Int,
  flat_prefix_without_parameter_header: ByteArray,
  parameter: Data,
) -> ScriptHash {
  let compiled_code = apply_param_to_compiled_code(
    flat_prefix_without_parameter_header,
    parameter,
  )

  builtin.integer_to_bytearray(True, 1, version)
    |> bytearray.concat(compiled_code)
    |> blake2b_224
}

fn apply_param_to_compiled_code(
  flat_prefix_without_parameter_header: ByteArray,
  parameter: Data,
) -> ByteArray {
  let parameter_cbor = cbor.serialise(parameter)

  let flat_script = bytearray.concat(
    flat_prefix_without_parameter_header,
    bytearray.concat(
      flat_encode_bytestring(parameter_cbor),
      flat_bytestring_tail,
    ),
  )

  bytearray.concat(
    definite_bytestring_header(bytearray.length(flat_script)),
    flat_script,
  )
}

fn flat_encode_bytestring(bytes: ByteArray) -> ByteArray {
  flat_encode_bytestring_chunks(bytes, bytearray.length(bytes))
}

fn flat_encode_bytestring_chunks(bytes: ByteArray, length: Int) -> ByteArray {
  if length == 0 {
    #"00"
  } else if length <= max_flat_bytestring_chunk_size {
    bytearray.concat(
      bytearray.from_int_big_endian(length, 1),
      bytearray.concat(bytes, #"00"),
    )
  } else {
    bytearray.concat(
      #"ff",
      bytearray.concat(
        bytearray.take(bytes, max_flat_bytestring_chunk_size),
        flat_encode_bytestring_chunks(
          bytearray.drop(bytes, max_flat_bytestring_chunk_size),
          length - max_flat_bytestring_chunk_size,
        ),
      ),
    )
  }
}

fn definite_bytestring_header(length: Int) -> ByteArray {
  if length < 24 {
    bytearray.from_int_big_endian(0x40 + length, 1)
  } else if length < 256 {
    bytearray.concat(#"58", bytearray.from_int_big_endian(length, 1))
  } else if length < 65536 {
    bytearray.concat(#"59", bytearray.from_int_big_endian(length, 2))
  } else if length < 4294967296 {
    bytearray.concat(#"5a", bytearray.from_int_big_endian(length, 4))
  } else {
    bytearray.concat(#"5b", bytearray.from_int_big_endian(length, 8))
  }
}
