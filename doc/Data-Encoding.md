# Data Encoding


Goals: what are these encodings used for? What do they represent?

Notably, ERC-4337 account abstraction only standardizes the interface for validating transaction how smart accounts validate transactions

- accounts must define their own signature encoding scheme.

- In the context of ERC-6900 modular accounts, each account must define a mechanism for the caller to select which validation function to use for a given call, and to optionally provide validation data to each hook function.

- Specific to Alchemy Modular account, we choose to use the user operation nonce to encode the validation function to use, and define a restriction that entity IDs for validation functions must be unique over the entire account.

### User Operation Nonce

ERC-4337 defines a multi-dimensional nonce system for smart accounts. In this system, each nonce is composed of two parts: a nonce key and a sequential nonce. The EntryPoint contract maintains nonce state for each account as a mapping of nonce sequence to nonce key, with each nonce sequence starting at zero. For a user operation to be valid under this system, it's nonce sequence must be the next number in the sequence associated with the nonce key used.

This system gives flexibility to accounts, allowing for transactions to be pending in the mempool in parallel if desired, or for a specific ordering to be enforced.


ERC-4337 defines this as a 256-bit nonce, with the upper 192 bits used as the parallel nonce key and the lower 64 bits used as the nonce sequence.

```
0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA________________ // Parallel Nonce Key
0x________________________________________________BBBBBBBBBBBBBBBB // Sequential Nonce
```

For Modular Account, we overload the contents of the parallel nonce key to also hold information about which validation function is being used to validate this user operation (which implies which key is expected to sign), and an optional flag to indicate that the signature includes a deferred action (TODO: link to DA section). Note that we still want to allow the end user define some portion of the parallel nonce key, to allow for user operation parallelism even when using a single validation function.

To fully identify a module function typically requires 24 bytes: 20 bytes for the module address, and 4 bytes for the entity ID. However, if we would use this for the validation selection, there would not be any space for a user-facing parallel nonce key, as 24 bytes = 192 bits and it would occupy the entire parallel nonce key. To address this, Modular Account places a restriction that the entity ID of validation functions must be unique over the entire account - this way, a 4-byte validation entity ID also uniquely identifies the module address.

However, this causes an issue with how direct-call validation functions are defined, where each of these uses the magic value `0xffffffff` to represent that the module address may call into the account. To address this, we define a union type of a `ValidationLocator`, which can contain either a 4-byte validation entity ID or a 20-byte address of a direct call validation. It also contains an options byte holding the union tag (indicating how to interpret the other data) and boolean flags for whether the user operation contains a deferred action and whether the validation is being used as a global validation.

Putting this all together, we get the following encoding scheme:

```
// With a regular validation function
0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA__________________________ // Parallel Nonce Key
0x______________________________________BBBBBBBB__________________ // Validation Entity ID
0x______________________________________________CC________________ // Options byte
0x________________________________________________DDDDDDDDDDDDDDDD // Sequential Nonce Key

// With a direct call validation used as a user op validation function
0xAAAAAA__________________________________________________________ // Parallel Nonce Key
0x______BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB__________________ // Caller address of direct-call validation
0x______________________________________________CC________________ // Options byte
0x________________________________________________BBBBBBBBBBBBBBBB // Sequential Nonce Key

// Validation Options layout:
0b00000___ // Unused
0b_____A__ // is direct call validation (union tag)
0b______B_ // has deferred action
0b_______C // is global validation
```

ERC-6900 validation modules and validation hook modules may define additional restrictions on the parallel nonce key, including data to pack. Currently, none of the modules in this contract suite implement this behavior.

### User Operation Signature



### ERC-1271 Signature

### Runtime authorization



## Internal-only data representation

These details aren't needed for integrating with the account or using it, but provide some context for account-internal organization

### Validation Lookup Keys

- Can't store full 24 bytes for module + entity ID in user op nonce, because it would occupy the entire parallel nonce key and not leave space for user-set parallel nonce key.
- Solution: make validation entity ID globally unique for a given account.
- Caveat: still need to handle direct call validation.
- Solution: define a packed union type that represents either a given address's direct call validation (can only have 1, using an entity id of `type(uint32).max)` (`0xffffffff`)).

Layout: