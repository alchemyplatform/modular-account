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

ERC-4337 user operations include a `signature` field that accounts use to authorize transactions. For Modular Account, the validation function to use is already specified in the user operation nonce (see above), so the signature field only needs to contain:
1. Optional per-validation-hook data for any validation hooks associated with the validation function
2. The actual signature data for the validation function itself

The signature uses the ERC-6900 sparse calldata segment format, which allows passing data to specific validation hooks by index, while omitting data for hooks that don't require it.

#### Signature Structure (Without Deferred Actions)

The signature follows the sparse calldata segment encoding:

```
// Sparse Calldata Segments (per-hook data + validation data)
// For each validation hook (in same order as installation), if data is provided:
0xAA_____________ // Hook index (0 to 254 / 0x00 to 0xfe)
0x__BBBBBBBB_____ // Length of hook data (4 bytes, uint32)
0x________CCC.... // Hook data (variable length)

// Final segment (always present):
0xFF______ // Reserved index (255 = type(uint8).max)
0x__CCC... // Validation function signature data (variable length, no length prefix)
```

Note: The sparse calldata segment format allows all validation hooks to be called while providing data onlh for hooks that need it. Hooks are identified by their index (0-254), and the final validation data is marked with the reserved index 255 (`type(uint8).max`).

#### Validation Signature Data Format

The content of the final segment (validation function signature data) depends on the validation module being used. For the Semi-Modular Account fallback validation and for `SingleSignerValidationModule`, it includes a signature type prefix:

```
// Semi-Modular Account fallback validation signature format:
0xAA_______ // Signature type (0 = EOA, 1 = CONTRACT_OWNER)
0x__BBBB... // Actual signature data (65 bytes for EOA ECDSA, variable for contract)

// For EOA signatures (SignatureType = 0):
0x00__________________________________________________________________________________________________________________________________ // Type byte
0x__RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR__________________________________________________________________ // r value (32 bytes)
0x__________________________________________________________________SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS__ // s value (32 bytes)
0x__________________________________________________________________________________________________________________________________VV // v value (1 byte)

// For contract owner signatures (SignatureType = 1):
0x01______ // Type byte
0x__BBBB.. // ERC-1271 signature data (variable length)
```

Other validation modules, like `WebAuthnValidationModule`, define their own signature data formats.

```
// WebAuthnValidationModule signature format:
// The signature is ABI-encoded as a WebAuthn.WebAuthnAuth struct containing:

struct WebAuthnAuth {
    bytes authenticatorData;  // WebAuthn authenticator data
    string clientDataJSON;    // WebAuthn client data JSON
    uint256 challengeIndex;   // Index of "challenge" in clientDataJSON
    uint256 typeIndex;        // Index of "type" in clientDataJSON
    uint256 r;                // r value of secp256r1 signature
    uint256 s;                // s value of secp256r1 signature
}

// The signature uses the secp256r1 (P-256) elliptic curve, as used by WebAuthn/passkeys.
// The r and s values form the signature over sha256(authenticatorData || sha256(clientDataJSON)).
```

#### Complete Examples

##### Example 1: Simple signature with no validation hooks

```
// Validation function specified in nonce, no pre-validation hooks
0xFF____ // Reserved index for validation data
0x__[validation signature data]...
```

For Semi-Modular Account fallback validation with an EOA signature:
```
concat([
    0xFF, // Final Signature Segment
    0x00, // Signature type = EOA
    r,    // 32-byte signature R value
    s,    // 32-byte signature S value
    v     // 1-byte signature V value
])
```

Total: 1 + 1 + 65 = 67 bytes

##### Example 2: Signature with two validation hooks

```
// Validation function specified in nonce, with 2 pre-validation hooks
concat([
  0x00,       // Hook index 0
  0x00000020, // Length: 32 bytes
  0x.... ,    // Hook index 0 data (length 32 bytes)
  0x01,       // Hook index 1
  0x00000010, // Length: 16 bytes
  0x... ,     // Hook index 1 data (length 16 bytes)
  0xFF,       // Reserved index for validation data
  0x...       // Validation signature data
])
```

#### Signature Structure With Deferred Actions

When a user operation includes a deferred action (indicated by bit 1 in the options byte of the nonce), the signature encoding becomes more complex. The deferred action allows taking an arbitrary action during the user operation validation phase itself. This allows atomically installing a new validation function and using it to authorize the user operation, useful for installing session keys. See [deferred actions](./Architecture.md#deferred-actions) for more information.

The signature structure with deferred actions follows this layout (from [ModularAccountBase.sol:411-456](../src/account/ModularAccountBase.sol#L411-L456)):

```
// Complete signature with deferred action:
concat([
  encodedDataLength,       // uint32: length of the encodedData field
  encodedData,             // bytes: contains ValidationLocator + deadline + selfCall
  deferredActionSigLength, // uint32: length of the deferredActionSig field
  deferredActionSig,       // bytes: signature for the deferred action (validated by ERC-1271 signature validation)
  userOpSignature          // bytes: standard sparse calldata segment format (see above)
])
```

The `encodedData` field is structured as:

```
concat([
  innerValidationLocator,  // ValidationLocator (21 bytes): which validation to use for the deferred action signature
  deadline,                // uint48 (6 bytes): expiry time for the deferred action (0 = no expiry)
  selfCall                 // bytes: calldata for the self-call to execute (typically `installValidation`)
])
```

##### ValidationLocator Type

The `ValidationLocator` is a 21-byte packed type used to identify a validation function and specify flags used in deferred actions.

When encoded in bytes (as in signatures or deferred action data), the format depends on whether it's a regular validation or a direct call validation:

```
// ValidationLocator with regular validation function (5 bytes used, 16 bytes padding):
0x00000000000000000000000000000000__________ // Unused padding (16 bytes)
0x________________________________AAAAAAAA__ // Validation entity ID (4 bytes, uint32)
0x________________________________________BB // Options byte (1 byte)

// ValidationLocator with direct call validation (21 bytes used):
0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA__ // Direct call validation address (20 bytes)
0x________________________________________BB // Options byte (1 byte)

// Options byte layout:
0b00000___ // Unused
0b_____A__ // is direct call validation (union tag)
0b______B_ // has deferred action (should be 0 for inner validation)
0b_______C // is global validation
```

Note: For the inner validation locator in deferred actions, the "has deferred action" bit (bit 1) should be 0, as nested deferred actions are not supported.

##### Deferred Action Mechanism

The deferred action mechanism works as follows:
1. The inner validation (specified as a `ValidationLocator`) validates the deferred action signature against a typed EIP-712 hash
2. The deferred action (typically an `installValidation` call) is executed during the validation phase
3. The outer validation (specified in the nonce) then validates the user operation signature using the sparse calldata segment format
4. The result of user op validation are coalesced with the deferred action deadline using time bounds intersection rules

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