# Data Encoding

Goals: what are these encodings used for? What do they represent?

Validation selection context - pick which validation function should be used.

Per-hook data encoding

## User Operation Nonce

## User Operation Signature

## ERC-1271 Signature

## Runtime authorization



## Internal-only data representation

These details aren't needed for integrating with the account or using it, but provide some context for account-internal organization

### Validation Lookup Keys

- Can't store full 24 bytes for module + entity ID in user op nonce, because it would occupy the entire parallel nonce key and not leave space for user-set parallel nonce key.
- Solution: make validation entity ID globally unique for a given account.
- Caveat: still need to handle direct call validation.
- Solution: define a packed union type that represents either a given address's direct call validation (can only have 1, using an entity id of `type(uint32).max)` (`0xffffffff`)).

Layout: