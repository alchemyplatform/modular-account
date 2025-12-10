# Data Encoding

ERC-4337 account abstraction only standardizes the interface for how smart accounts must validate transactions to the EntryPoint contract. Each account implementation is free to decide how to encode calldata and signatures, and how to interpret other user operation fields. The user operation signature field typically holds a cryptographic signature over the user operation, and is used for validation that the user operation is authorized by the user.

In the context of ERC-6900 modular accounts, each account must also define a mechanism for the caller to select which validation function to use for a given call, and to optionally provide validation data to each hook function.

Specific to Alchemy Modular account, we choose to use the user operation nonce to encode the validation function to use, and define a restriction that entity IDs for validation functions must be unique over the entire account.

### User Operation Nonce

ERC-4337 defines a multi-dimensional nonce system for smart accounts. In this system, each nonce is composed of two parts: a nonce key and a sequential nonce. The EntryPoint contract maintains nonce state for each account as a mapping of nonce sequence to nonce key, with each nonce sequence starting at zero. For a user operation to be valid under this system, its nonce sequence must be the next number in the sequence associated with the nonce key used.

This system gives flexibility to accounts, allowing for transactions to be pending in the mempool in parallel if desired, or for a specific ordering to be enforced.


ERC-4337 defines this as a 256-bit nonce, with the upper 192 bits used as the parallel nonce key and the lower 64 bits used as the nonce sequence.

```
0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA________________ // Parallel Nonce Key
0x________________________________________________BBBBBBBBBBBBBBBB // Sequential Nonce
```

For Modular Account, we overload the contents of the parallel nonce key to also hold information about which validation function is being used to validate this user operation (which implies which key is expected to sign), and an optional flag to indicate that the signature includes a [deferred action](./Architecture.md#deferred-actions).

Note that we still want to allow the end user to define some portion of the parallel nonce key, to allow for user operation parallelism even when using a single validation function.

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

Note: The sparse calldata segment format allows all validation hooks to be called while providing data only for hooks that need it. Hooks are identified by their index (0-254), and the final validation data is marked with the reserved index 255 (`type(uint8).max`).

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

When a user operation includes a deferred action (indicated by bit 2 in the options byte of the nonce), the signature encoding becomes more complex. The deferred action allows taking an arbitrary action during the user operation validation phase itself. This allows atomically installing a new validation function and using it to authorize the user operation, useful for installing session keys. See [deferred actions](./Architecture.md#deferred-actions) for more information.

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

The `ValidationLocator` is a 21-byte packed type used to identify a validation function and specify flags used in deferred actions. It is right-aligned (options byte at the end) because it is stored as a `uint168` and used in EIP-712 hashing for deferred actions.

When encoded in bytes (as in signatures or deferred action data), the format depends on whether it is a regular validation or a direct call validation:

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

ERC-1271 is a standard for smart contract signature validation, commonly used by applications like Permit2, Seaport, and others, to verify that a smart contract account has approved a given message or action. The standard defines an `isValidSignature(bytes32 hash, bytes signature)` function that returns a magic value if the signature is valid.

For Modular Account, the ERC-1271 signature encoding is very similar to user operation signatures, but with one key difference: the validation function to use must be specified in the signature itself, unlike user operations where it is specified in the nonce.

#### Signature Structure

The complete ERC-1271 signature structure is:

```
concat([
  packedValidationLocator, // PackedValidationLocator (5 or 21 bytes): which validation to use
  perHookData,             // bytes: sparse calldata segments for validation hooks (optional)
  validationSignatureData  // bytes: signature data for the validation function
])
```

The `packedValidationLocator` is the same concept as the `ValidationLocator` described in deferred actions, but encoded differently. While `ValidationLocator` is always 21 bytes (right-aligned as a `uint168`), the packed version is variable-length (5 or 21 bytes) and left-aligned (options byte first) in calldata for efficient parsing.

```
// Layout:
// [1-byte options][4-byte validation id OR 20-byte address of direct call validation][remainder]

// With non-direct call validation
0xAA______________ // Validation Type
0x__BBBBBBBB______ // Validation Entity ID
0x__________CCC... // Remainder

// With direct call validation
0xAA______________________________________________ // Validation Type
0x__BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB______ // Caller address of direct-call validation
0x__________________________________________CCC... // Remainder

// Validation Options layout:
0b00000___ // Unused
0b_____A__ // is direct call validation (union tag)
0b______B_ // has deferred action (should be zero, not implemented for signature validation)
0b_______C // is global validation
```

This format is shared between ERC-1271 signatures and runtime validation.

The remaining data uses the same sparse calldata segment format as user operation signatures:

```
// Sparse calldata segments (same as user op signature format):
concat([
  // For each validation hook (in same order as installation), if data is provided:
  hookIndex,     // uint8: hook index (0 to 254)
  hookDataLen,   // uint32: length of hook data
  hookData,      // bytes: hook data
  // ... more hooks ...
  0xFF,          // uint8: reserved index for validation data
  signatureData  // bytes: validation function signature data (no length prefix)
])
```

#### Validation-Specific Signature Formats

The format of the final validation signature data depends on the validation module being used:

##### Semi-Modular Account Fallback Validation

For SMA fallback validation, the signature data includes the same signature type prefix as user operations, but the hash being signed is wrapped in a replay-safe EIP-712 structure:

```
concat([
  signatureType,  // uint8: 0 = EOA, 1 = CONTRACT_OWNER
  signatureData   // bytes: 65 bytes for EOA (r, s, v), variable for contract
])
```

**Important**: The hash signed is NOT the raw hash passed to `isValidSignature`. Instead, the raw hash is wrapped in a EIP-712 structure to prevent against signature replay:
```
{
  domain: {
    chainId: chainId,
    verifyingContract: accountAddress
  },
  types: {
    ReplaySafeHash: [{ name: "hash", type: "bytes32" }]
  },
  message: {
    hash
  },
  primaryType: "ReplaySafeHash"
}
```

This prevents replay attacks when the same signer address may own multiple accounts, either on the same chain or cross-chain.

##### SingleSignerValidationModule

`SingleSignerValidationModule` uses the same format as SMA fallback validation, including the signature type prefix and replay-safe hash wrapping:

```
concat([
  signatureType,  // uint8: 0 = EOA, 1 = CONTRACT_OWNER
  signatureData   // bytes: 65 bytes for EOA (r, s, v), variable for contract
])
```

The replay-safe hash uses a module-specific domain separator:
```
{
  domain: {
    chainId: chainId,
    verifyingContract: singleSignerValidationModuleAddress,
    salt: concat([0x000000000000, accountAddress]) // Use account address in salt
  },
  types: {
    ReplaySafeHash: [{ name: "hash", type: "bytes32" }]
  },
  message: {
    hash
  },
  primaryType: "ReplaySafeHash"
}      
```

##### WebAuthnValidationModule

`WebAuthnValidationModule` uses the same ABI-encoded `WebAuthnAuth` struct format as in user operations, with replay-safe hash wrapping:

```
// ABI-encoded WebAuthnAuth struct (same as user op format)
abi.encode(WebAuthnAuth({
  authenticatorData: ...,
  clientDataJSON: ...,
  challengeIndex: ...,
  typeIndex: ...,
  r: ...,
  s: ...
}))
```

The replay-safe hash mechanism is the same as `SingleSignerValidationModule`.

#### Considerations

1. **Replay Protection**: Both SMA fallback validation and validation modules wrap the hash in a replay-safe EIP-712 structure. This prevents signatures from being replayed across different accounts or chains.

2. **isSignatureValidation Flag**: A validation function must have the `isSignatureValidation` flag set to be used for ERC-1271 validation. This is configured when the validation is installed.

3. **Deferred Actions**: During deferred action validation (when installing a new validation atomically with a user operation), the hash is already replay-safe from the EIP-712 wrapper, so the additional replay-safe wrapping is skipped.

4. **Module-Specific Domain Separators**: Validation modules like `SingleSignerValidationModule` and `WebAuthnValidationModule` use their own domain separators that include the module address, providing additional isolation between different validation implementations.

### Runtime authorization

Runtime validation allows external callers (not the EntryPoint) to execute functions on a modular account by providing authorization data. This is used for direct calls from EOAs, other smart contracts, or session keys that have been granted specific permissions.

The `executeWithRuntimeValidation(bytes calldata data, bytes calldata authorization)` function is the entry point for runtime-validated execution.

#### Authorization Structure

The complete runtime validation authorization structure is:

```
concat([
  packedValidationLocator, // PackedValidationLocator (5 or 21 bytes): which validation to use
  perHookData,             // bytes: sparse calldata segments for validation hooks (optional)
  validationAuthData       // bytes: authorization data for the validation function
])
```

This structure is identical to the ERC-1271 signature encoding. The `packedValidationLocator` uses the same left-aligned, variable-length format:

```
// Layout:
// [1-byte options][4-byte validation id OR 20-byte address of direct call validation][remainder]

// With non-direct call validation (5 bytes)
0xAA______________ // Validation Type
0x__BBBBBBBB______ // Validation Entity ID
0x__________CCC... // Remainder

// With direct call validation (21 bytes)
0xAA______________________________________________ // Validation Type
0x__BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB______ // Caller address of direct-call validation
0x__________________________________________CCC... // Remainder

// Validation Options layout:
0b00000___ // Unused
0b_____A__ // is direct call validation (union tag)
0b______B_ // has deferred action (unused for runtime validation)
0b_______C // is global validation
```

The remaining data uses the same sparse calldata segment format:

```
// Sparse calldata segments (same as user op and ERC-1271 signature format):
concat([
  // For each validation hook (in same order as installation), if data is provided:
  hookIndex,     // uint8: hook index (0 to 254)
  hookDataLen,   // uint32: length of hook data
  hookData,      // bytes: hook data
  // ... more hooks ...
  0xFF,          // uint8: reserved index for validation data
  authData       // bytes: validation function authorization data (no length prefix)
])
```

#### Validation-Specific Authorization Formats

Unlike user operation and ERC-1271 validation which typically require cryptographic signatures, runtime validation often uses simpler authorization schemes based on the caller's identity.

##### SingleSignerValidationModule and Semi-Modular Account Fallback Validation

For `SingleSignerValidationModule` and SMA fallback validation, runtime validation does not require signature data, instead, it validates that `msg.sender` matches the configured signer address.

```
// No authorization data needed - validation checks msg.sender
concat([
  packedValidationLocator,  // Identifies the validation to use
  // Optionally: validation hook data segments
  0xFF                      // Reserved index (no additional auth data needed)
])
```

##### WebAuthnValidationModule

`WebAuthnValidationModule` does not support runtime validation. The `validateRuntime` function always reverts with `NotAuthorized()`.

#### Considerations

1. **isRuntimeValidation Flag**: A validation function must have the `isRuntimeValidation` flag set to be used for runtime validation. This is configured when the validation is installed.

2. **Direct Call Validation**: When using direct call validation, the validation module address itself must be the caller (`msg.sender`), and the call should not be wrapped in the `executeWithRuntimeValidation` function. This allows the module to directly call into the account without additional authorization.


## Internal-only data representation

These details aren't needed for integrating with the account or using it, but provide some context for account-internal organization.

### Validation Lookup Keys

The `ValidationLookupKey` is an internal type used as a mapping key to store and retrieve validation configuration data in the account's storage. It solves a key design constraint: fully identifying a validation function normally requires 24 bytes (20-byte module address + 4-byte entity ID), but encoding this in the user operation nonce would consume the entire parallel nonce key, leaving no space for user-defined parallel nonces.

Modular Account requires that validation entity IDs be globally unique within an account. This means a 4-byte entity ID alone can uniquely identify both the module address and the entity ID, reducing the lookup key size from 24 bytes to just 5 bytes for most validations. However, direct call validations all use the magic entity ID `0xFFFFFFFF` (`type(uint32).max`), so they cannot rely on entity ID uniqueness. Instead, they are identified by the module's address (20 bytes), requiring a different encoding.

The `ValidationLookupKey` is a tagged union that can represent either a regular validation (4-byte entity ID), or a direct call validation (20-byte module address). It is implemented very similarly to a `ValidationLocator` (defined above), except the last options byte is maked out to just the union tag.

#### Type Definition and Layout

`ValidationLookupKey` is defined as a `uint168` (21 bytes) with the following layout:

```
// ValidationLookupKey with regular validation function (5 bytes used, 16 bytes padding):
0x00000000000000000000000000000000__________ // Unused padding (16 bytes)
0x________________________________AAAAAAAA__ // Validation entity ID (4 bytes, uint32)
0x________________________________________BB // Options byte (1 byte)

// ValidationLookupKey with direct call validation (21 bytes used):
0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA__ // Direct call validation address (20 bytes)
0x________________________________________BB // Options byte (1 byte)

// Options byte layout:
0b00000___ // Unused
0b_____A__ // is direct call validation (union tag)
0b______0_ // Masked out (hasDeferredAction flag in ValidationLocator)
0b_______0 // Masked out (isGlobal flag in ValidationLocator)
```

#### Computing the Lookup Key

A `ValidationLookupKey` is derived from a `ValidationLocator` by masking out transient flags. The `isGlobal` and `hasDeferredAction` flags are masked out because they describe how a validation is being used in a specific context, not the identity of the validation itself. The lookup key must be context-independent so the same validation always maps to the same storage location, regardless of whether it's used as a global validation or with a deferred action. 