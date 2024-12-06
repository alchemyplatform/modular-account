# TimeRangeModule
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/30301ded6ae1a71c760933b7a75d6ac5437c1ae3/src/modules/permissions/TimeRangeModule.sol)

**Inherits:**
IValidationHookModule, [ModuleBase](/src/modules/ModuleBase.sol/abstract.ModuleBase.md)

**Author:**
Alchemy

This module allows for the setting and enforcement of time ranges for an entity ID.
- Enforcement relies on `block.timestamp`, either within this module for runtime validation, or by the
EntryPoint for user op validation.
- Time ranges are inclusive of both the beginning and ending timestamps.
- None of the functions are installed on the account. Account states are to be retrieved from this global
singleton directly.
- Uninstallation will NOT disable all installed hooks for an account. It only uninstalls hooks for the entity
ID that is passed in. Account must remove access for each entity ID if want to disable all hooks.


## State Variables
### timeRanges

```solidity
mapping(uint32 entityId => mapping(address account => TimeRange)) public timeRanges;
```


## Functions
### onInstall

Initializes the module with the given time range for `msg.sender` with a given entity id.

*data is abi-encoded as (uint32 entityId, uint48 validUntil, uint48 validAfter)*


```solidity
function onInstall(bytes calldata data) external override;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`data`|`bytes`|Optional bytes array to be decoded and used by the module to setup initial module data for the modular account.|


### onUninstall

Resets module state for `msg.sender` with the given entity id.

*data is abi-encoded as (uint32 entityId)*


```solidity
function onUninstall(bytes calldata data) external override;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`data`|`bytes`|Optional bytes array to be decoded and used by the module to clear module data for the modular account.|


### preUserOpValidationHook

Enforces the time range for a user op by returning the range in the ERC-4337 validation data.

*Pre user operation validation hooks MUST NOT return an authorizer value other than 0 or 1.*


```solidity
function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata userOp, bytes32)
    external
    view
    override
    assertNoData(userOp.signature)
    returns (uint256);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`entityId`|`uint32`|An identifier that routes the call to different internal implementations, should there be more than one.|
|`userOp`|`PackedUserOperation`|The user operation.|
|`<none>`|`bytes32`||

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint256`|Packed validation data for validAfter (6 bytes), validUntil (6 bytes), and authorizer (20 bytes).|


### preRuntimeValidationHook

Enforces the time range for a runtime validation by reverting if `block.timestamp` is not within
the range.

*To indicate the entire call should revert, the function MUST revert.*


```solidity
function preRuntimeValidationHook(uint32 entityId, address, uint256, bytes calldata, bytes calldata)
    external
    view
    override;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`entityId`|`uint32`|An identifier that routes the call to different internal implementations, should there be more than one.|
|`<none>`|`address`||
|`<none>`|`uint256`||
|`<none>`|`bytes`||
|`<none>`|`bytes`||


### preSignatureValidationHook

Run the pre signature validation hook specified by the `entityId`.

*No-op, signature checking is not enforced to be within a time range,  due to uncertainty about whether
the `timestamp` opcode is allowed during this operation. If the validation should not be allowed to
generate 1271 signatures, the flag `isSignatureValidation` should be set to false when calling
`installValidation`.*


```solidity
function preSignatureValidationHook(uint32, address, bytes32, bytes calldata) external pure override;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint32`||
|`<none>`|`address`||
|`<none>`|`bytes32`||
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


### setTimeRange

Sets the time range for the sending account (`msg.sender`) and a given entity id.


```solidity
function setTimeRange(uint32 entityId, uint48 validUntil, uint48 validAfter) public;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`entityId`|`uint32`|The entity id to set the time range for.|
|`validUntil`|`uint48`|The timestamp until which the time range is valid, inclusive.|
|`validAfter`|`uint48`|The timestamp after which the time range is valid, inclusive.|


### supportsInterface

Query if a contract implements an interface

*Interface identification is specified in ERC-165. This function
uses less than 30,000 gas.*


```solidity
function supportsInterface(bytes4 interfaceId) public view virtual override(ModuleBase, IERC165) returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`interfaceId`|`bytes4`||

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|`true` if the contract implements `interfaceID` and `interfaceID` is not 0xffffffff, `false` otherwise|


## Events
### TimeRangeSet

```solidity
event TimeRangeSet(uint32 indexed entityId, address indexed account, uint48 validUntil, uint48 validAfter);
```

## Errors
### TimeRangeNotValid

```solidity
error TimeRangeNotValid();
```

## Structs
### TimeRange

```solidity
struct TimeRange {
    uint48 validUntil;
    uint48 validAfter;
}
```

