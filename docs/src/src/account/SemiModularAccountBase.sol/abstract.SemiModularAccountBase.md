# SemiModularAccountBase
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/2824291b17c11e6f41963e8c13505f2476b92ee6/src/account/SemiModularAccountBase.sol)

**Inherits:**
[ModularAccountBase](/src/account/ModularAccountBase.sol/abstract.ModularAccountBase.md)

**Author:**
Alchemy

Abstract base contract for the Alchemy Semi-Modular Account variants. Includes fallback signer
functionality.

*Inherits ModularAccountBase. Overrides certain functionality from ModularAccountBase, and exposes an
internal virtual getter for the fallback signer.*


## State Variables
### _REPLAY_SAFE_HASH_TYPEHASH

```solidity
bytes32 private constant _REPLAY_SAFE_HASH_TYPEHASH =
    0x294a8735843d4afb4f017c76faf3b7731def145ed0025fc9b1d5ce30adf113ff;
```


### _SEMI_MODULAR_ACCOUNT_STORAGE_SLOT

```solidity
uint256 internal constant _SEMI_MODULAR_ACCOUNT_STORAGE_SLOT =
    0x5b9dc9aa943f8fa2653ceceda5e3798f0686455280432166ba472eca0bc17a32;
```


### _SIG_VALIDATION_PASSED

```solidity
uint256 internal constant _SIG_VALIDATION_PASSED = 0;
```


### _SIG_VALIDATION_FAILED

```solidity
uint256 internal constant _SIG_VALIDATION_FAILED = 1;
```


## Functions
### constructor


```solidity
constructor(IEntryPoint entryPoint, ExecutionInstallDelegate executionInstallDelegate)
    ModularAccountBase(entryPoint, executionInstallDelegate);
```

### updateFallbackSignerData

Updates the fallback signer data in storage.


```solidity
function updateFallbackSignerData(address fallbackSigner, bool isDisabled) external wrapNativeFunction;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`fallbackSigner`|`address`|The new signer to set.|
|`isDisabled`|`bool`|Whether to disable fallback signing entirely.|


### installValidation


```solidity
function installValidation(
    ValidationConfig validationConfig,
    bytes4[] calldata selectors,
    bytes calldata installData,
    bytes[] calldata hooks
) external override wrapNativeFunction;
```

### getFallbackSignerData

Returns the fallback signer data in storage.


```solidity
function getFallbackSignerData() external view returns (address, bool);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`address`|The fallback signer and a boolean, true if the fallback signer validation is disabled, false if it is enabled.|
|`<none>`|`bool`||


### _execUserOpValidation


```solidity
function _execUserOpValidation(
    ValidationLookupKey validationLookupKey,
    bytes32 userOpHash,
    bytes calldata signatureSegment,
    UOCallBuffer callBuffer
) internal override returns (uint256);
```

### _execRuntimeValidation


```solidity
function _execRuntimeValidation(
    ValidationLookupKey validationLookupKey,
    RTCallBuffer callBuffer,
    bytes calldata authorization
) internal override;
```

### _exec1271Validation


```solidity
function _exec1271Validation(
    SigCallBuffer buffer,
    bytes32 hash,
    ValidationLookupKey validationLookupKey,
    bytes calldata signature
) internal view override returns (bytes4);
```

### _checkSignature


```solidity
function _checkSignature(address owner, bytes32 digest, bytes calldata sig) internal view returns (bool);
```

### _isValidationGlobal


```solidity
function _isValidationGlobal(ValidationLookupKey validationFunction) internal view override returns (bool);
```

### _getFallbackSigner


```solidity
function _getFallbackSigner() internal view returns (address);
```

### _retrieveFallbackSignerUnchecked

*SMA implementations must implement their own fallback signer getter.
NOTE: The passed storage pointer may point to a struct with a zero address signer. It's up
to inheritors to determine what to do with that information. No assumptions about storage
state are safe to make besides layout.*


```solidity
function _retrieveFallbackSignerUnchecked(SemiModularAccountStorage storage _storage)
    internal
    view
    virtual
    returns (address);
```

### _replaySafeHash

Returns the replay-safe hash generated from the passed typed data hash for 1271 validation.

*Generates a replay-safe hash to wrap a standard typed data hash. This prevents replay attacks by
enforcing the domain separator, which includes this contract's address and the chainId. This is only
relevant for 1271 validation because UserOp validation relies on the UO hash and the Entrypoint has
safeguards.
NOTE: Like in signature-based validation modules, the returned hash should be used to generate signatures,
but the original hash should be passed to the external-facing function for 1271 validation.*


```solidity
function _replaySafeHash(bytes32 hash) internal view returns (bytes32);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`hash`|`bytes32`|The typed data hash to wrap in a replay-safe hash.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bytes32`|The replay-safe hash, to be used for 1271 signature generation.|


### _getSemiModularAccountStorage


```solidity
function _getSemiModularAccountStorage() internal pure returns (SemiModularAccountStorage storage);
```

### _validationIsNative


```solidity
function _validationIsNative(ValidationLookupKey validationLookupKey)
    internal
    pure
    virtual
    override
    returns (bool);
```

### _hashStructReplaySafeHash

Adds a EIP-712 replay safe hash wrapper to the digest


```solidity
function _hashStructReplaySafeHash(bytes32 hash) internal pure virtual returns (bytes32);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`hash`|`bytes32`|The hash to wrap in a replay-safe hash|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bytes32`|The replay-safe hash|


### _isNativeFunction

*Overrides ModularAccountView.*


```solidity
function _isNativeFunction(uint32 selector) internal pure virtual override returns (bool);
```

### _isWrappedNativeFunction

*Overrides ModularAccountView.*


```solidity
function _isWrappedNativeFunction(uint32 selector) internal pure virtual override returns (bool);
```

## Events
### FallbackSignerUpdated

```solidity
event FallbackSignerUpdated(address indexed newFallbackSigner, bool isDisabled);
```

## Errors
### FallbackSignerMismatch

```solidity
error FallbackSignerMismatch();
```

### FallbackValidationInstallationNotAllowed

```solidity
error FallbackValidationInstallationNotAllowed();
```

### FallbackSignerDisabled

```solidity
error FallbackSignerDisabled();
```

### InvalidSignatureType

```solidity
error InvalidSignatureType();
```

## Structs
### SemiModularAccountStorage

```solidity
struct SemiModularAccountStorage {
    address fallbackSigner;
    bool fallbackSignerDisabled;
}
```

