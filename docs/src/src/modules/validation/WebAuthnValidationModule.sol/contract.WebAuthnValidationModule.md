# WebAuthnValidationModule
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/2824291b17c11e6f41963e8c13505f2476b92ee6/src/modules/validation/WebAuthnValidationModule.sol)

**Inherits:**
IValidationModule, ReplaySafeWrapper, [ModuleBase](/src/modules/ModuleBase.sol/abstract.ModuleBase.md)

**Author:**
Alchemy

This validation module enables WebAuthn (secp256r1 curve) signature validation.
NOTE:
- Uninstallation will NOT disable all installed entity IDs of an account. It only uninstalls the entity ID that
is passed in. Account must remove access for each entity ID if want to disable all.
- None of the functions are installed on the account. Account states are to be retrieved from this global
singleton directly.
- This validation supports ERC-1271. The signature is valid if it is signed by the owner's private key.
- This validation supports composition that other validation can relay on entities in this validation to
validate partially or fully.

*Implementation referenced from WebAuthn + Coinbase Smart Wallet developed by Base.*


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
mapping(uint32 entityId => mapping(address account => PubKey)) public signers;
```


## Functions
### transferSigner

Updates the signer for an entityId.

*Used for key rotation or deleting a key*


```solidity
function transferSigner(uint32 entityId, uint256 x, uint256 y) external;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`entityId`|`uint32`|The entityId to update the signer for.|
|`x`|`uint256`|The x coordinate of the new signer.|
|`y`|`uint256`|The y coordinate of the new signer.|


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


### validateRuntime

Run the runtime validation function specified by the `entityId`.

*To indicate the entire call should revert, the function MUST revert.*


```solidity
function validateRuntime(address, uint32, address, uint256, bytes calldata, bytes calldata)
    external
    pure
    override;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`address`||
|`<none>`|`uint32`||
|`<none>`|`address`||
|`<none>`|`uint256`||
|`<none>`|`bytes`||
|`<none>`|`bytes`||


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
function _transferSigner(uint32 entityId, uint256 newX, uint256 newY) internal;
```

### _validateSignature


```solidity
function _validateSignature(uint32 entityId, address account, bytes32 hash, bytes calldata signature)
    internal
    view
    returns (bool);
```

## Events
### SignerTransferred
This event is emitted when signer of the account's validation changes.


```solidity
event SignerTransferred(
    address indexed account,
    uint32 indexed entityId,
    uint256 indexed newX,
    uint256 indexed newY,
    uint256 oldX,
    uint256 oldY
) anonymous;
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account whose validation signer changed.|
|`entityId`|`uint32`|The entityId for the account and the signer.|
|`newX`|`uint256`|X coordinate of the new signer.|
|`newY`|`uint256`|Y coordinate of the new signer.|
|`oldX`|`uint256`|X coordinate of the old signer.|
|`oldY`|`uint256`|Y coordinate of the old signer.|

## Errors
### NotAuthorized

```solidity
error NotAuthorized();
```

## Structs
### PubKey

```solidity
struct PubKey {
    uint256 x;
    uint256 y;
}
```

