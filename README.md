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
```

Checkout `validators/` to see how the exposed functions can be used.

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

By specifying the redeemer type to be a pair of integers (`(Int, Int)`), the
validator can efficiently pick the input UTxO, match its output reference to
make sure it's the one that's getting spent, and similarly pick the
corresponding output UTxO in order to perform an arbitrary validation between
the two.

The provided example validates that the two are identical, and each carries a
single state token apart from Ada.

#### Multi UTxO Indexer

While the singular variant of this pattern is primarily meant for the spending
endpoint of a contract, a multi UTxO indexer utilizes the stake validator
provided by this package. And therefore the spending endpoint can be taken
directly from `stake_validator`.

Subsequently, spend redeemers are irrelevant here. The redeemer of the
withdrawal endpoint is expected to be a properly sorted list of pairs of
indices.

The requirement for sorting here ensures that there are no duplicates in input
and output indices.

Both indexers can be implemented by providing a custom validation function
for an input UTxO and an output UTxO.
