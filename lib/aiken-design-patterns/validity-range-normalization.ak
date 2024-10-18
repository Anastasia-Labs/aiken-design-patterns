//// The datatype that models validity range in Cardano currently allows for
//// values that are either meaningless, or can have more than one
//// representations. For example, since the values are integers, the inclusive
//// flag for each end is redundant and can be omitted in favor of a predefined
//// convention (e.g. a value should always be considered inclusive).
//// 
//// In this module we present a custom datatype that essentially reduces the
//// value domain of the original validity range to a smaller one that
//// eliminates meaningless instances and redundancies.

use aiken/interval.{Interval, IntervalBound}
use cardano/transaction.{ValidityRange}

/// Datatype for eliminating meaningless ranges, without the redundant
/// inclusiveness flag (instead all range values are inclusive).
pub type NormalizedTimeRange {
  ClosedRange { lower: Int, upper: Int }
  FromNegInf { upper: Int }
  ToPosInf { lower: Int }
  Always
}

/// Validates the given time range, and returns a normalized version.
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
