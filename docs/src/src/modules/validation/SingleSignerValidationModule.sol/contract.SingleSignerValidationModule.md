# SingleSignerValidationModule
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/22a036bde57711d56f967db6e1ecc2ae54755e1a/src/modules/validation/SingleSignerValidationModule.sol)

**Inherits:**
IValidationModule, ReplaySafeWrapper, [ModuleBase](/src/modules/ModuleBase.sol/abstract.ModuleBase.md)

**Author:**
Alchemy

This validation enables any ECDSA (secp256k1 curve) signature validation or Contract Owner signature
validation. It handles installation by each entity (entityId).
NOTE:
- The first byte of the to be checked Signature is the SignatureType, indicating EOA or Contract Owner.
- Uninstallation will NOT disable all installed entity IDs of an account. It only uninstalls the
entity ID that is passed in. Account must remove access for each entity ID if want to disable all.
- None of the functions are installed on the account. Account states are to be retrieved from this global
singleton directly.
- This validation supports ERC-1271. The signature is valid if it is signed by the owner's private key.
- This validation supports composition that other validation can relay on entities in this validation to
validate partially or fully.


## State Variables
### _SIG_VALIDATION_PASSED

```solidity
uint256 internal constant _SIG_VALIDATION_PASSED = 0;
```


### _SIG_VALIDATION_FAILED

```solidity
uint256 internal constant _SIG_VALIDATION_FAILED = 1;
```


### _1271_MAGIC_VALUE

```solidity
bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
```


### _1271_INVALID

```solidity
bytes4 internal constant _1271_INVALID = 0xffffffff;
```


### signers

```solidity
mapping(uint32 entityId => mapping(address account => address)) public signers;
```


## Functions
### transferSigner

Transfer Signer of the account's validation to `newSigner`.


```solidity
function transferSigner(uint32 entityId, address newSigner) external;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`entityId`|`uint32`|The entityId for the account and the signer.|
|`newSigner`|`address`|The address of the new signer.|


### onInstall

Initialize module data for the modular account.

*Called by the modular account during `installExecution`.*


```solidity
function onInstall(bytes calldata data) external override;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`data`|`bytes`|Optional bytes array to be decoded and used by the module to setup initial module data for the modular account.|


### onUninstall

Clear module data for the modular account.

*Called by the modular account during `uninstallExecution`.*


```solidity
function onUninstall(bytes calldata data) external override;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`data`|`bytes`|Optional bytes array to be decoded and used by the module to clear module data for the modular account.|


### validateUserOp

Run the user operation validation function specified by the `entityId`.


```solidity
function validateUserOp(uint32 entityId, PackedUserOperation calldata userOp, bytes32 userOpHash)
    external
    view
    override
    returns (uint256);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`entityId`|`uint32`|An identifier that routes the call to different internal implementations, should there be more than one.|
|`userOp`|`PackedUserOperation`|The user operation.|
|`userOpHash`|`bytes32`|The user operation hash.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint256`|Packed validation data for validAfter (6 bytes), validUntil (6 bytes), and authorizer (20 bytes).|


### validateRuntime

Run the runtime validation function specified by the `entityId`.

*To indicate the entire call should revert, the function MUST revert.*


```solidity
function validateRuntime(address account, uint32 entityId, address sender, uint256, bytes calldata, bytes calldata)
    external
    view
    override;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|the account to validate for.|
|`entityId`|`uint32`|An identifier that routes the call to different internal implementations, should there be more than one.|
|`sender`|`address`|The caller address.|
|`<none>`|`uint256`||
|`<none>`|`bytes`||
|`<none>`|`bytes`||


### validateSignature

Validates a signature using ERC-1271.

*The signature is valid if it is signed by the owner's private key
(if the owner is an EOA) or if it is a valid ERC-1271 signature from the
owner (if the owner is a contract).
Note that the digest is wrapped in an EIP-712 struct to prevent cross-account replay attacks. The
replay-safe hash may be retrieved by calling the public function `replaySafeHash`.*


```solidity
function validateSignature(address account, uint32 entityId, address, bytes32 digest, bytes calldata signature)
    external
    view
    override
    returns (bytes4);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|the account to validate for.|
|`entityId`|`uint32`|An identifier that routes the call to different internal implementations, should there be more than one.|
|`<none>`|`address`||
|`digest`|`bytes32`||
|`signature`|`bytes`|the signature of the ERC-1271 request|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bytes4`|The ERC-1271 `MAGIC_VALUE` if the signature is valid, or 0xFFFFFFFF if invalid.|


### moduleId

Return a unique identifier for the module.

*This function MUST return a string in the format "vendor.module.semver". The vendor and module
names MUST NOT contain a period character.*


```solidity
function moduleId() external pure returns (string memory);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`string`|The module ID.|


### supportsInterface


```solidity
function supportsInterface(bytes4 interfaceId) public view virtual override(ModuleBase, IERC165) returns (bool);
```

### _transferSigner


```solidity
function _transferSigner(uint32 entityId, address newSigner) internal;
```

### _checkSig


```solidity
function _checkSig(address owner, bytes32 digest, bytes calldata sig) internal view returns (bool);
```

## Events
### SignerTransferred
This event is emitted when Signer of the account's validation changes.


```solidity
event SignerTransferred(
    address indexed account, uint32 indexed entityId, address indexed newSigner, address previousSigner
) anonymous;
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account whose validation Signer changed.|
|`entityId`|`uint32`|The entityId for the account and the signer.|
|`newSigner`|`address`|The address of the new signer.|
|`previousSigner`|`address`|The address of the previous signer.|

## Errors
### InvalidSignatureType

```solidity
error InvalidSignatureType();
```

### NotAuthorized

```solidity
error NotAuthorized();
```

