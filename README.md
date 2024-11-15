# Table of Contents

<!-- vim-markdown-toc GFM -->

* [Aiken Library for Common Design Patterns in Cardano Smart Contracts](#aiken-library-for-common-design-patterns-in-cardano-smart-contracts)
    * [How to Use](#how-to-use)
    * [How to Run Package Tests](#how-to-run-package-tests)
    * [Provided Patterns](#provided-patterns)
        * [Stake Validator](#stake-validator)
            * [Endpoints](#endpoints)
        * [UTxO Indexers](#utxo-indexers)
        * [Transaction Level Validator Minting Policy](#transaction-level-validator-minting-policy)
        * [Validity Range Normalization](#validity-range-normalization)
        * [Merkelized Validator](#merkelized-validator)
        * [Parameter Application](#parameter-application)

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

This pattern allows for delegating some computations to a given staking script.

The primary application for this is the so-called "withdraw zero trick," which
is most effective for validators that need to go over multiple inputs.

With a minimal spending logic (which is executed for each UTxO), and an
arbitrary withdrawal logic (which is executed only once), a much more optimized
script can be implemented.

#### Endpoints

`spend` merely looks for the presence of a withdrawal (with arbitrary amount)
from its own reward address.

`withdraw` takes a custom logic that is provided with 3 values:

  1. Redeemer (arbitrary `Data`)
  2. Script's validator hash (`Hash<Blake2b_224, Script>`)
  3. Transaction info (`Transaction`)

### UTxO Indexers

The primary purpose of this pattern is to offer a more optimized and composable
solution for a unique mapping between one input UTxO to one or many output
UTxOs.

There are a total of 6 variations:
- Single, one-to-one indexer
- Single, one-to-many indexer
- Multiple, one-to-one indexer, with ignored redeemers
- Multiple, one-to-one indexer, with provided redeemers
- Multiple, one-to-many indexer, with ignored redeemers
- Multiple, one-to-many indexer, with provided redeemers

> [!NOTE]
> Neither of singular UTxO indexer patterns provide protection against the
> [double satisfaction](https://github.com/Plutonomicon/plutonomicon/blob/b6906173c3f98fb5d7b40fd206f9d6fe14d0b03b/vulnerabilities.md#double-satisfaction)
> vulnerability, as this can be done in multiple ways depending on the contract.
> [Datum tagging](https://github.com/Plutonomicon/plutonomicon/blob/b6906173c3f98fb5d7b40fd206f9d6fe14d0b03b/vulnerabilities.md#solution-2) is
> a simple technique that you can perform through your one-to-one validator
> functions.

Depending on the variation, the functions you can provide are:
- One-to-one validator for an input and its corresponding outputs – this is
  always the validation that executes the most times (i.e. for each output)
- One-to-many validator for an input and all of its corresponding outputs – this
  executes as many times as your specified inputs
- Many-to-many validator for all inputs against all the outputs – this executes
  only once

In the cases of the singular variants, and multi variants with provided
redeemers, your validators are also provided with their spending redeemers.

> [!NOTE]
> Non-redeemer multi variants can only validate UTxOs that are spent via their
> own contract's spending endpoint. In other words, they can only validate UTxOs
> that are spent from an address which its payment part is a `Script`, such that
> its included hash equals the wrapping staking validator (which you utilize
> this function within).

### Transaction Level Validator Minting Policy

Very similar to the [stake validator](#stake-validator), this design pattern
couples the spend and minting endpoints of a validator.

The role of the spending input is to ensure the minting endpoint executes. It
does so by looking at the mint field and making sure **only** a non-zero amount
of its asset (i.e. its policy is the same as the validator's hash, with its name
specified as a parameter) are getting minted/burnt.

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
> Be aware that total size of reference scripts is currently limited to 200KiB
> (204800 bytes), and they also impose additional fees in an exponential manner.
> See [here](https://github.com/IntersectMBO/cardano-ledger/issues/3952) and [here](https://github.com/CardanoSolutions/ogmios/releases/tag/v6.5.0) for
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

### Parameter Application

In some cases, validators need to be aware of instances of a parameterized
script in order to have a more robust control over the flow of assets.

As a simple example, consider a minting script that needs to ensure the
destination of its tokens can only be instances of a specific spending script,
e.g. parameterized by users' wallets.

Since each different wallet leads to a different script address, without
verifying instances, each script address is seen as an arbitrary script address
from the minting script.

To allow this validation on-chain, some restrictions are needed to be put in
place:
1. Parameters of the target script must have constant lengths, which can be
   achieved by having them hashed
2. Consequently, for each transaction, the resolved value of those parameters
   must be provided through the redeemer
3. The dependent script must be provided with CBOR bytes of instances before and
   after the parameter(s)
4. Wrapping of instances' logics in an outer function so that there'll be single
   occurances of each parameter

This pattern provides two sets of functions. One for applying parameter(s) in
the target script (i.e. the minting script in the example above), and one for
wrapping your parameterized scripts with.

After defining your parameterized scripts, you'll need to generate instances of
them with dummy data in order to obtain the required `prefix` and `postfix`
values for your target script to utilize.

Take a look at `validators/apply-params-example.ak` to see them in use.
