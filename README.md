# Abstract Coupled Stake Validator in Aiken

A Cardano multi-validator for incorporating a coupled staking validator in your
Cardano smart contracts.

## What is it?

This is a template multi-validator written in [Aiken](https://aiken-lang.org), with
a placeholder logic for withdrawals.

The spending endpoint of this validator only checks whether a withdrawal with
arbitrary amount is present in the script context, such that its credential
equates its own hash (i.e. a withdrawal from this script).

The primary application for this sort of coupled withdrawal is for the
so-called "withdraw zero trick," which is most effective for validators that
need to go over all the inputs.

With a minimal logic for the spending endpoint (which is executed for each
UTxO), the primary logic can be delegated to the staking validator (which is
executed only once) to achieve a much more optimized script execution.

## How to Customize

The `withdrawal_logic` function in `validators/aiken-stake-validator.ak` is the
placeholder, which takes a redeemer (an arbitrary `Data`), the hash of the
validator (`Hash<Blake2b_224, Script>`), and the transaction
info (`Transaction`). The `WithdrawFrom` purpose is already validated within
the defined `validator`.
