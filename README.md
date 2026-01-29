# Table of Contents

<!-- vim-markdown-toc GFM -->

* [Aiken Library for Common Design Patterns in Cardano Smart Contracts](#aiken-library-for-common-design-patterns-in-cardano-smart-contracts)
    * [How to Use](#how-to-use)
    * [How to Run Package Tests](#how-to-run-package-tests)
    * [Provided Patterns](#provided-patterns)
        * [Stake Validator](#stake-validator)
        * [UTxO Indexers](#utxo-indexers)
        * [Transaction Level Validator Minting Policy](#transaction-level-validator-minting-policy)
        * [Validity Range Normalization](#validity-range-normalization)
        * [Merkelized Validator](#merkelized-validator)
        * [Parameter Validation](#parameter-validation)
        * [Linked List](#linked-list)
    * [License](#license)

<!-- vim-markdown-toc -->

# Aiken Library for Common Design Patterns in Cardano Smart Contracts

To help facilitate faster development of Cardano smart contracts, we present a
collection of tried and tested modules and functions for implementing common
design patterns.

Based on our [`design-patterns`](https://github.com/Anastasia-Labs/design-patterns) repository.

## How to Use

Install the package with `aiken`:

```bash
aiken add anastasia-labs/aiken-design-patterns --version v1.3.0
```

And you'll be able to import functions of various patterns:

```rs
use aiken_design_patterns/merkelized_validator
use aiken_design_patterns/multi_utxo_indexer
use aiken_design_patterns/linked_list
use aiken_design_patterns/parameter_validation
use aiken_design_patterns/singular_utxo_indexer
use aiken_design_patterns/stake_validator
use aiken_design_patterns/tx_level_minter
```

Check out `validators/examples` to see how the exposed functions can be used.

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

## Provided Patterns

### Stake Validator

This pattern allows for delegating some computations to a given staking script.

The primary application for this is the so-called "withdraw zero trick," which
is most effective for validations against multiple script inputs in the
transaction.

With a minimal spending logic (which is executed for each UTxO), and an
arbitrary withdrawal logic (which is executed only once), a much more optimized
script can be implemented.

The module offers three functions, primarily meant to be implemented under
spending endpoints:
- `validate_withdraw`
- `validate_withdraw_with_amount`
- `validate_withdraw_minimal`

Use `validate_withdraw_minimal` if you don't need to perform any validations on
either the staking script's redeemer or withdrawal Lovelace quantity.

All three functions go over the `withdrawals` list in the transaction. However,
`validate_withdraw` and `validate_withdraw_with_amount` also traverse the
`redeemers` field in order to let you validate against the redeemer (and the
withdrawal quantity in case of the latter).

### UTxO Indexers

The primary purpose of this pattern is to offer a more optimized and composable
solution for a unique mapping between one input UTxO to one or many output
UTxOs.

There are a total of 4 variations available:
- Single, one-to-one indexer
- Single, one-to-many indexer
- Multiple, one-to-one indexer, with ignored redeemers
- Multiple, one-to-one indexer, with provided redeemers

> [!NOTE]
> Neither of singular UTxO indexer patterns provide protection against the
> [double satisfaction](https://github.com/Plutonomicon/plutonomicon/blob/b6906173c3f98fb5d7b40fd206f9d6fe14d0b03b/vulnerabilities.md#double-satisfaction)
> vulnerability, as this can be done in multiple ways depending on the contract.
> However, they require a dedicated argument as a reminder for the potential
> requirement of implementing a protection against this vulnerability.

Depending on the variation, the functions you can provide are:
- One-to-one validator for an input and its corresponding outputs – this is
  always the validation that executes the most times (i.e. for each output)
- One-to-many validator for an input and all of its corresponding outputs – this
  executes only once

### Transaction Level Validator Minting Policy

Very similar to the [stake validator](#stake-validator), this design pattern
couples the spend and minting endpoints of a validator.

In other words, spend logic only ensures the minting endpoint executes. It does
so by looking at the mint field and making sure a non-zero amount of its asset
(i.e. with a policy identical to the provided script hash) are getting
minted/burnt.

The arbitrary logic is passed to the minting policy so that it can be executed
a single time for a given transaction.

### Validity Range Normalization

The datatype that models validity range in Cardano currently allows for values
that are either meaningless, or can have more than one representations. For
example, since the values are integers, the inclusive flag for each end is
redundant for most cases and can be omitted in favor of a predefined convention
(e.g. a value should always be considered inclusive).

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
  InvalidRange
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

This design pattern offers an interface for off-loading such validations into an
external observer/withdrawal script, so that the sizes of the scripts themselves
can stay within the limits of Cardano.

> [!NOTE]
> Be aware that total size of reference scripts is currently limited to 200KiB
> (204800 bytes), and they also impose additional fees in an exponential manner.
> See [here](https://github.com/IntersectMBO/cardano-ledger/issues/3952) and [here](https://github.com/CardanoSolutions/ogmios/releases/tag/v6.5.0) for
> more info.

The exposed `delegated_compute` function from `merkelized_validator` expects 6
arguments:

1. The arbitrary input value for the underlying computation logic
2. The hash of the withdrawal validator that performs the computation
3. The `Pairs` of all redeemers within the current script context.
4. Positional index of the withdrawal redeemer inside the `redeemers` list
5. Validation function for coercing a `Data` to the format of the input expected
   by the staking script's computation
6. A similar validation function for coercing `Data` to the expected output of
   the computation

This function expects to find the given stake validator in the `redeemers` list,
such that its redeemer is of type `ComputationRedeemer` (which carries the
generic input argument(s) and the expected output(s)), makes sure provided
input(s) match the ones given to the validator through its redeemer, and returns
the output(s) (which are carried inside the withdrawal redeemer) so that you can
safely use them.

For defining a withdrawal logic that carries out the computation, use the
exposed `computation_withdrawal_wrapper` function. It expects 2 arguments:

1. A redeemer of type `ComputationRedeemer<a, b>`. Note that `a` is the type of
   input argument(s), and `b` is the type of output argument(s)
2. The computation itself. It has to take an argument of type `a`, and return
   a value of type `b`

It validates that the given input(s) and output(s) match correctly with the
provided computation logic.

There are also `ValidationRedeemer<a>`, `validation_withdrawal_wrapper` and
`delegated_validation` variants which can be used for validations that don't
return any outputs.

### Parameter Validation

In some cases, validators need to be aware of instances of a parameterized
script in order to have a more robust control over the flow of assets.

As a simple example, consider a minting script that needs to ensure the
destination of its tokens can only be instances of a specific spending script,
e.g. parameterized by users' wallets.

Since each different wallet leads to a different script address, without
verifying instances, instances can only be seen as arbitrary scripts from the
minting script's point of view.

This can be resolved by validating an instance is the result of applying
specific parameters to a given parameterized script.

To allow this validation on-chain, some restrictions are needed:
1. Parameters of the script must have constant lengths, which can be achieved by
   having them hashed
2. Consequently, for each transaction, the resolved value of those parameters
   must be provided through the redeemer
3. The dependent script must be provided with CBOR bytes of instances before and
   after the parameter(s)
4. Wrapping of instances' logics in an outer function so that there'll be single
   occurances of each parameter

This pattern provides two sets of functions. One for applying parameter(s) in
the dependent script (i.e. the minting script in the example above), and one for
wrapping your parameterized scripts with.

After defining your parameterized scripts, you'll need to generate instances of
them with dummy data in order to obtain the required `prefix` value for your
target script to utilize. Note that your prefix should be from a single CBOR
encoded result.

Take a look at `validators/examples/parameter-validation.ak` to see them in use.

### Linked List

Storing lists in datums is generally impractical, as its growth can lead to
unspendable UTxOs due to limited resources available on-chain.

A linked list is a construct for storing an infinitely large array of elements
on-chain, such that each element is represented with a UTxO that points to its
immediate successor.

Plutonomicon has [a nice write-up](https://github.com/Plutonomicon/plutonomicon/blob/main/assoc.md)
of how this can be implemented with eUTxOs.

To provide an API as user-friendly as possible, the implementation aims to
handle any validation related to the linked list logic, and provide the user
with any data that would help perform their custom validations.

This is why the API does not expose granular helper functions, and only provides
functions that perform primary linked list operations (e.g. `init`,
`insert_ordered`, etc.).

A good rule of thumb to keep in mind to know whether a validation is handled by
the library, is to ask whether said validation is related to the linked list
itself. If the answer is yes, the helper has already taken care of it.


## License

[MIT license](./LICENSE):

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
