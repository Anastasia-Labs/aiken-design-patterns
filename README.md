# Aiken Library for Common Design Patterns in Cardano Smart Contracts

To help facilitate faster development of Cardano smart contract, we present a
collection of tried and tested modules and functions for implementing common
design patterns.

## How to Use

Include this repository in your `aiken.toml` file:
```toml
[[dependencies]]
name = "anastasia-labs/aiken-design-patterns"
version = "0.0.1"
source = "github"
```

And you'll be able to import functions of various patterns:
```rs
use anastasia_labs/design_patterns/stake_validator as stake_validator
```

Checkout `validators/examples.ak` for how the exposed functions can be used.

## Provided Patterns

### Stake Validator: `design_patterns/stake_validator`

This module offers two functions meant to be used within a multi-validator for
implementing a "coupled" stake validator logic.

The primary application for this is the so-called "withdraw zero trick," which
is most effective for validators that need to go over multiple inputs.

With a minimal spending logic (which is executed for each UTxO), and an
arbitrary withdrawal logic (which is executed only once), a much more optimized
script can be implemented.

#### Endpoints

`spend` merely looks for the presence of a withdrawal (with arbitrary amount)
from its own reward address. This minimal logic enables a much more optimized
script execution, especially for validators that need to go over multiple
inputs.

`withdraw` takes a custom logic that requires 3 arguments:
  1. Redeemer (arbitrary `Data`)
  2. Script's validator hash (`Hash<Blake2b_224, Script>`)
  3. Transaction info (`Transaction`)
