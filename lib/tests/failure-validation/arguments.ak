use aiken/builtin
use aiken_design_patterns/failure_validation/arguments

const non_list = builtin.i_data(42)

const values_0: List<Data> = []

const datum_0 = builtin.list_data(values_0)

const values_1: List<Data> = [builtin.i_data(1)]

const datum_1 = builtin.list_data(values_1)

const values_2: List<Data> = [builtin.i_data(1), builtin.i_data(2)]

const datum_2 = builtin.list_data(values_2)

const values_3: List<Data> =
  [builtin.i_data(1), builtin.i_data(2), builtin.i_data(3)]

const datum_3 = builtin.list_data(values_3)

const values_4: List<Data> =
  [builtin.i_data(1), builtin.i_data(2), builtin.i_data(3), builtin.i_data(4)]

const datum_4 = builtin.list_data(values_4)

const values_5: List<Data> =
  [
    builtin.i_data(1),
    builtin.i_data(2),
    builtin.i_data(3),
    builtin.i_data(4),
    builtin.i_data(5),
  ]

const datum_5 = builtin.list_data(values_5)

const values_6: List<Data> =
  [
    builtin.i_data(1),
    builtin.i_data(2),
    builtin.i_data(3),
    builtin.i_data(4),
    builtin.i_data(5),
    builtin.i_data(6),
  ]

const datum_6 = builtin.list_data(values_6)

const values_7: List<Data> =
  [
    builtin.i_data(1),
    builtin.i_data(2),
    builtin.i_data(3),
    builtin.i_data(4),
    builtin.i_data(5),
    builtin.i_data(6),
    builtin.i_data(7),
  ]

const datum_7 = builtin.list_data(values_7)

test arity_0__preserves_arguments_and_return_value() {
  let actual = arguments.with_arity_0(datum_0, fn() { 42 })
  actual == 42
}

test arity_0__rejects_non_list() fail {
  arguments.with_arity_0(non_list, fn() { True })
}

test arity_0__rejects_extra_arguments() fail {
  arguments.with_arity_0(datum_1, fn() { True })
}

test arity_0__propagates_false() {
  let result = arguments.with_arity_0(datum_0, fn() { False })
  !result
}

test arity_0__propagates_failure() fail {
  arguments.with_arity_0(
    datum_0,
    fn() {
      expect False
      True
    },
  )
}

test arity_1__preserves_arguments_and_return_value() {
  let actual = {
    let a <- arguments.with_arity_1(datum_1)
    [a]
  }
  actual == values_1
}

test arity_1__rejects_non_list() fail {
  let _a <- arguments.with_arity_1(non_list)
  True
}

test arity_1__rejects_extra_arguments() fail {
  let _a <- arguments.with_arity_1(datum_2)
  True
}

test arity_1__rejects_missing_arguments() fail {
  let _a <- arguments.with_arity_1(datum_0)
  True
}

test arity_1__propagates_false() {
  let result = {
    let _a <- arguments.with_arity_1(datum_1)
    False
  }
  !result
}

test arity_1__propagates_failure() fail {
  let _a <- arguments.with_arity_1(datum_1)
  expect False
  True
}

test arity_2__preserves_arguments_and_return_value() {
  let actual = {
    let a, b <- arguments.with_arity_2(datum_2)
    [a, b]
  }
  actual == values_2
}

test arity_2__rejects_non_list() fail {
  let _a, _b <- arguments.with_arity_2(non_list)
  True
}

test arity_2__rejects_extra_arguments() fail {
  let _a, _b <- arguments.with_arity_2(datum_3)
  True
}

test arity_2__rejects_missing_arguments() fail {
  let _a, _b <- arguments.with_arity_2(datum_1)
  True
}

test arity_2__propagates_false() {
  let result = {
    let _a, _b <- arguments.with_arity_2(datum_2)
    False
  }
  !result
}

test arity_2__propagates_failure() fail {
  let _a, _b <- arguments.with_arity_2(datum_2)
  expect False
  True
}

test arity_3__preserves_arguments_and_return_value() {
  let actual = {
    let a, b, c <- arguments.with_arity_3(datum_3)
    [a, b, c]
  }
  actual == values_3
}

test arity_3__rejects_non_list() fail {
  let _a, _b, _c <- arguments.with_arity_3(non_list)
  True
}

test arity_3__rejects_extra_arguments() fail {
  let _a, _b, _c <- arguments.with_arity_3(datum_4)
  True
}

test arity_3__rejects_missing_arguments() fail {
  let _a, _b, _c <- arguments.with_arity_3(datum_2)
  True
}

test arity_3__propagates_false() {
  let result = {
    let _a, _b, _c <- arguments.with_arity_3(datum_3)
    False
  }
  !result
}

test arity_3__propagates_failure() fail {
  let _a, _b, _c <- arguments.with_arity_3(datum_3)
  expect False
  True
}

test arity_4__preserves_arguments_and_return_value() {
  let actual = {
    let a, b, c, d <- arguments.with_arity_4(datum_4)
    [a, b, c, d]
  }
  actual == values_4
}

test arity_4__rejects_non_list() fail {
  let _a, _b, _c, _d <- arguments.with_arity_4(non_list)
  True
}

test arity_4__rejects_extra_arguments() fail {
  let _a, _b, _c, _d <- arguments.with_arity_4(datum_5)
  True
}

test arity_4__rejects_missing_arguments() fail {
  let _a, _b, _c, _d <- arguments.with_arity_4(datum_3)
  True
}

test arity_4__propagates_false() {
  let result = {
    let _a, _b, _c, _d <- arguments.with_arity_4(datum_4)
    False
  }
  !result
}

test arity_4__propagates_failure() fail {
  let _a, _b, _c, _d <- arguments.with_arity_4(datum_4)
  expect False
  True
}

test arity_5__preserves_arguments_and_return_value() {
  let actual = {
    let a, b, c, d, e <- arguments.with_arity_5(datum_5)
    [a, b, c, d, e]
  }
  actual == values_5
}

test arity_5__rejects_non_list() fail {
  let _a, _b, _c, _d, _e <- arguments.with_arity_5(non_list)
  True
}

test arity_5__rejects_extra_arguments() fail {
  let _a, _b, _c, _d, _e <- arguments.with_arity_5(datum_6)
  True
}

test arity_5__rejects_missing_arguments() fail {
  let _a, _b, _c, _d, _e <- arguments.with_arity_5(datum_4)
  True
}

test arity_5__propagates_false() {
  let result = {
    let _a, _b, _c, _d, _e <- arguments.with_arity_5(datum_5)
    False
  }
  !result
}

test arity_5__propagates_failure() fail {
  let _a, _b, _c, _d, _e <- arguments.with_arity_5(datum_5)
  expect False
  True
}

test arity_6__preserves_arguments_and_return_value() {
  let actual = {
    let a, b, c, d, e, f <- arguments.with_arity_6(datum_6)
    [a, b, c, d, e, f]
  }
  actual == values_6
}

test arity_6__rejects_non_list() fail {
  let _a, _b, _c, _d, _e, _f <- arguments.with_arity_6(non_list)
  True
}

test arity_6__rejects_extra_arguments() fail {
  let _a, _b, _c, _d, _e, _f <- arguments.with_arity_6(datum_7)
  True
}

test arity_6__rejects_missing_arguments() fail {
  let _a, _b, _c, _d, _e, _f <- arguments.with_arity_6(datum_5)
  True
}

test arity_6__propagates_false() {
  let result = {
    let _a, _b, _c, _d, _e, _f <- arguments.with_arity_6(datum_6)
    False
  }
  !result
}

test arity_6__propagates_failure() fail {
  let _a, _b, _c, _d, _e, _f <- arguments.with_arity_6(datum_6)
  expect False
  True
}
