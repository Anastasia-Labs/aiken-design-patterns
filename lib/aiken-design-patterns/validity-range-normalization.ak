use aiken/interval.{Interval, IntervalBound}
use aiken/transaction.{ValidityRange}

pub type NormalizedTimeRange {
  ClosedRange { lower: Int, upper: Int }
  FromNegInf { upper: Int }
  ToPosInf { lower: Int }
  Always
}

pub fn normalize_time_range(
  validity_range: ValidityRange,
) -> NormalizedTimeRange {
  let Interval {
    lower_bound: IntervalBound {
      bound_type: lower_bound_type,
      is_inclusive: lower_is_inclusive,
    },
    upper_bound: IntervalBound {
      bound_type: upper_bound_type,
      is_inclusive: upper_is_inclusive,
    },
  } = validity_range
  when (lower_bound_type, upper_bound_type) is {
    (interval.NegativeInfinity, interval.PositiveInfinity) -> Always
    (interval.NegativeInfinity, interval.Finite(upper_int)) ->
      FromNegInf { upper: resolve_upper(upper_int, upper_is_inclusive) }
    (interval.Finite(init_lower_int), interval.Finite(init_upper_int)) ->
      ClosedRange {
        lower: resolve_lower(init_lower_int, lower_is_inclusive),
        upper: resolve_upper(init_upper_int, upper_is_inclusive),
      }
    (interval.Finite(init_lower_int), interval.PositiveInfinity) ->
      ToPosInf { lower: resolve_lower(init_lower_int, lower_is_inclusive) }
    _ -> fail @"Improper validity range encountered"
  }
}

fn resolve_lower(init_lower: Int, is_inclusive: Bool) -> Int {
  if is_inclusive {
    init_lower
  } else {
    init_lower + 1
  }
}

fn resolve_upper(init_upper: Int, is_inclusive: Bool) -> Int {
  if is_inclusive {
    init_upper
  } else {
    init_upper - 1
  }
}
