<!-- vim-markdown-toc GFM -->

* [Aiken Library for Common Design Patterns in Cardano Smart Contracts](#aiken-library-for-common-design-patterns-in-cardano-smart-contracts)
    * [How to Use](#how-to-use)
    * [Provided Patterns](#provided-patterns)
        * [Stake Validator](#stake-validator)
            * [Endpoints](#endpoints)
        * [UTxO Indexers](#utxo-indexers)
            * [Singular UTxO Indexer](#singular-utxo-indexer)
                * [One-to-One](#one-to-one)
                * [One-to-Many](#one-to-many)
            * [Multi UTxO Indexer](#multi-utxo-indexer)
        * [Transaction Level Validator Minting Policy](#transaction-level-validator-minting-policy)
        * [Validity Range Normalization](#validity-range-normalization)

<!-- vim-markdown-toc -->

# Aiken Library for Common Design Patterns in Cardano Smart Contracts

To help facilitate faster development of Cardano smart contracts, we present a
collection of tried and tested modules and functions for implementing common
design patterns.

## How to Use

Install the package with `aiken`:
```bash
aiken package add anastasia-labs/aiken-design-patterns --version main
```

And you'll be able to import functions of various patterns:
```rs
use aiken_design_patterns/multi_utxo_indexer as multi_utxo_indexer
use aiken_design_patterns/singular_utxo_indexer as singular_utxo_indexer
use aiken_design_patterns/stake_validator as stake_validator
use aiken_design_patterns/tx_level_minter as tx_level_minter
```

Check out `validators/` to see how the exposed functions can be used.

## Provided Patterns

### Stake Validator

This module offers two functions meant to be used within a multi-validator for
implementing a "coupled" stake validator logic.

The primary application for this is the so-called "withdraw zero trick," which
is most effective for validators that need to go over multiple inputs.

With a minimal spending logic (which is executed for each UTxO), and an
arbitrary withdrawal logic (which is executed only once), a much more optimized
script can be implemented.

#### Endpoints

`spend` merely looks for the presence of a withdrawal (with arbitrary amount)
from its own reward address.

`withdraw` takes a custom logic that requires 3 arguments:
  1. Redeemer (arbitrary `Data`)
  2. Script's validator hash (`Hash<Blake2b_224, Script>`)
  3. Transaction info (`Transaction`)

### UTxO Indexers

The primary purpose of this pattern is to offer a more optimized solution for
a unique mapping between one input UTxO to one output UTxO.

#### Singular UTxO Indexer

##### One-to-One

By specifying the redeemer type to be a pair of integers (`(Int, Int)`), the
validator can efficiently pick the input UTxO, match its output reference to
make sure it's the one that's getting spent, and similarly pick the
corresponding output UTxO in order to perform an arbitrary validation between
the two.

The provided example validates that the two are identical, and each carries a
single state token apart from Ada.

##### One-to-Many

Here the validator looks for a set of output for the given input, through a
redeemer of type `(Int, List<Int>)` (output indices are required to be in
ascending order to disallow duplicates). To make the abstraction as efficient
as possible, the provided higher-order function takes 3 validation functions:
1. A function that validates the spending `Input` (single invocation).
2. A function that validates the input UTxO against a corresponding output
   UTxO. Note that this is executed for each associated output.
3. A function that validates the collective outputs. This also runs only once.
   An example use-case could be checking for the number of outputs.

#### Multi UTxO Indexer

While the singular variant of this pattern is primarily meant for the spending
endpoint of a contract, a multi UTxO indexer utilizes the stake validator
provided by this package. And therefore the spending endpoint can be taken
directly from `stake_validator`.

Subsequently, spend redeemers are irrelevant here. The redeemer of the
withdrawal endpoint is expected to be a properly sorted list of pairs of
indices (for the one-to-one case), or a list of one-to-many mapping of indices.

The distinction between one-to-one and one-to-many variants here is very
similar to the singular case, so please refer to [its section above](#singular-utxo-indexer) for
more details.

### Transaction Level Validator Minting Policy

Very similar to the [stake validator](#stake-validator), this design pattern
utilizes a multi-validator comprising of a spend and a minting endpoint.

The role of the spendig input is to ensure the minting endpoint executes. It
does so by looking at the mint field and making sure a non-zero amount of its
asset (where its policy is the same as the multi-validator's hash, and its name
is specified as a parameter) are getting minted/burnt.

The arbitrary logic is passed to the minting policy so that it can be executed
a single time for a given transaction.

### Validity Range Normalization

The datatype that models validity range in Cardano currently allows for values
that are either meaningless, or can have more than one representations. For
example, since the values are integers, the inclusive flag for each end is
redundant and can be omitted in favor of a predefined convention (e.g. a value
should always be considered inclusive).

In this module we present a custom datatype that essentially reduces the value
domain of the original validity range to a smaller one that eliminates
meaningless instances and redundancies.

The datatype is defined as following:
```rs
pub type NormalizedTimeRange {
  ClosedRange { lower: Int, upper: Int }
  FromNegInf  {             upper: Int }
  ToPosInf    { lower: Int             }
  Always
}
```

The exposed function of the module (`normalize_time_range`), takes a
`ValidityRange` and returns this custom datatype.
