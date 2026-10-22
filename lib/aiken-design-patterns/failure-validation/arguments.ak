//// Exact-arity decoding for builtin arguments stored as a Data list.
////
//// Each helper checks only the list shape and passes its raw arguments to the
//// continuation in order. The caller chooses the argument types and how to use
//// the builtin's result. Use backpassing for continuations with arguments.

/// Decode exactly 0 arguments and invoke the continuation.
pub fn with_arity_0(datum: Data, callback: fn() -> result) -> result {
  expect arguments: List<Data> = datum
  expect [] = arguments
  callback()
}

/// Decode exactly 1 argument and invoke the continuation.
pub fn with_arity_1(datum: Data, callback: fn(Data) -> result) -> result {
  expect arguments: List<Data> = datum
  expect [a] = arguments
  callback(a)
}

/// Decode exactly 2 arguments and invoke the continuation.
pub fn with_arity_2(datum: Data, callback: fn(Data, Data) -> result) -> result {
  expect arguments: List<Data> = datum
  expect [a, b] = arguments
  callback(a, b)
}

/// Decode exactly 3 arguments and invoke the continuation.
pub fn with_arity_3(
  datum: Data,
  callback: fn(Data, Data, Data) -> result,
) -> result {
  expect arguments: List<Data> = datum
  expect [a, b, c] = arguments
  callback(a, b, c)
}

/// Decode exactly 4 arguments and invoke the continuation.
pub fn with_arity_4(
  datum: Data,
  callback: fn(Data, Data, Data, Data) -> result,
) -> result {
  expect arguments: List<Data> = datum
  expect [a, b, c, d] = arguments
  callback(a, b, c, d)
}

/// Decode exactly 5 arguments and invoke the continuation.
pub fn with_arity_5(
  datum: Data,
  callback: fn(Data, Data, Data, Data, Data) -> result,
) -> result {
  expect arguments: List<Data> = datum
  expect [a, b, c, d, e] = arguments
  callback(a, b, c, d, e)
}

/// Decode exactly 6 arguments and invoke the continuation.
pub fn with_arity_6(
  datum: Data,
  callback: fn(Data, Data, Data, Data, Data, Data) -> result,
) -> result {
  expect arguments: List<Data> = datum
  expect [a, b, c, d, e, f] = arguments
  callback(a, b, c, d, e, f)
}
