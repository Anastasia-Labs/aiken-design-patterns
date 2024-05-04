<!-- vim-markdown-toc GFM -->
# Table of Contents

* [Aiken Library for Common Design Patterns in Cardano Smart Contracts](#aiken-library-for-common-design-patterns-in-cardano-smart-contracts)
  * [How to Use](#how-to-use)
  * [How to Run Package Tests](#how-to-run-package-tests)
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
    * [Merkelized Validator](#merkelized-validator)

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
use aiken_design_patterns/merkelized_validator as merkelized_validator
use aiken_design_patterns/multi_utxo_indexer as multi_utxo_indexer
use aiken_design_patterns/singular_utxo_indexer as singular_utxo_indexer
use aiken_design_patterns/stake_validator as stake_validator
use aiken_design_patterns/tx_level_minter as tx_level_minter
```

Check out `validators/` to see how the exposed functions can be used.

## How to Run Package Tests

Here are the steps to compile and run the included tests:

1. Clone the repo and navigate inside:

```bash
git clone https://github.com/Anastasia-Labs/aiken-design-patterns
cd aiken-design-patterns
```

2. Run the build command, which both compiles all the functions/examples and
   also runs the included unit tests:

```sh
aiken build
```

3. Execute the test suite:

```sh
aiken check
```

![aiken-design-patterns.gif](/assets/images/aiken-design-patterns.gif)

Test results:

![test_report.png](/assets/images/test_report.png)

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
a unique mapping between one input UTxO to one or many output UTxOs.

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

Here the validator looks for a set of outputs for the given input, through a
redeemer of type `(Int, List<Int>)` (output indices are required to be in
ascending order to disallow duplicates). To make the abstraction as efficient
as possible, the provided higher-order function takes 3 validation logics:

1. A function that validates the spending `Input` (single invocation).
2. A function that validates the input UTxO against a corresponding output
   UTxO. Note that this is executed for each associated output.
3. A function that validates the collective outputs. This also runs only once.
   The number of outputs is also available for this function (its second
   argument).

#### Multi UTxO Indexer

While the singular variant of this pattern is primarily meant for the spending
endpoint of a contract, a multi UTxO indexer utilizes the stake validator
provided by this package. And therefore the spending endpoint can be taken
directly from `stake_validator`.

Subsequently, spend redeemers are irrelevant here. The redeemer of the
withdrawal endpoint is expected to be a properly sorted list of pairs of
indices (for the one-to-one case), or a list of one-to-many mappings of
indices.

It's worth emphasizing that it is necessary for this design to be a
multi-validator as the staking logic filters inputs that are coming from a
script address which its validator hash is identical to its own.

The distinction between one-to-one and one-to-many variants here is very
similar to the singular case, so please refer to [its section above](#singular-utxo-indexer) for
more details.

The primary difference is that here, input indices should be provided for the
_filtered_ list of inputs, i.e. only script inputs, unlike the singular variant
where the index applies to all the inputs of the transaction. This slight
inconvenience is for preventing extra overhead on-chain.

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

### Merkelized Validator

Since transaction size is limited in Cardano, some validators benefit from a
solution which allows them to delegate parts of their logics. This becomes more
prominent in cases where such logics can greatly benefit from optimization
solutions that trade computation resources for script sizes (e.g. table
lookups can take up more space so that costly computations can be averted).

This design pattern offers an interface for off-loading such logics into an
external withdrawal script, so that the size of the validator itself can stay
within the limits of Cardano.

> [!NOTE]
> While currently the sizes of reference scripts are essentially irrelevant,
> they'll soon impose additional fees.
> See [here](https://github.com/IntersectMBO/cardano-ledger/issues/3952) for
> more info.

The exposed `spend` function from `merkelized_validator` expects 3 arguments:

1. The hash of the withdrawal validator that performs the computation.
2. The list of arguments expected by the underlying logic.
3. The `Dict` of all redeemers within the current script context.

This function expects to find the given stake validator in the `redeemers` list,
such that its redeemer is of type `WithdrawRedeemer` (which carries the list of
input arguments and the list of expected outputs), makes sure provided inputs
match the ones given to the validator through its redeemer, and returns the
outputs (which are carried inside the withdrawal redeemer) so that you can
safely use them.

For defining a withdrawal logic that carries out the computation, use the
exposed `withdraw` function. It expects 3 arguments:

1. The computation itself. It has to take a list of generic inputs, and return
   a list of generic outputs.
2. A redeemer of type `WithdrawRedeemer<a, b>`. Note that `a` is the type of
   input arguments, and `b` is the type of output arguments.
3. The script context.

It validates that the puropse is withdrawal, and that given the list of inputs,
the provided function yields identical outputs as the ones provided via the
redeemer.
