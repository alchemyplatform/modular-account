# MemManagementLib
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/30301ded6ae1a71c760933b7a75d6ac5437c1ae3/src/libraries/MemManagementLib.sol)

**Author:**
Alchemy

A library for managing memory in ModularAccount. Handles loading data from storage into memory, and
manipulating the free memory pointer.


## Functions
### loadExecHooks

Load execution hooks associated both with a validation function and an execution selector.


```solidity
function loadExecHooks(ExecutionStorage storage execData, ValidationStorage storage valData)
    internal
    view
    returns (HookConfig[] memory hooks);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`execData`|`ExecutionStorage`|The execution storage struct to load from.|
|`valData`|`ValidationStorage`|The validation storage struct to load from.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`hooks`|`HookConfig[]`|An array of `HookConfig` items, representing the execution hooks.|


### loadExecHooks

Load execution hooks associated with an execution selector.


```solidity
function loadExecHooks(ExecutionStorage storage execData) internal view returns (HookConfig[] memory);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`execData`|`ExecutionStorage`|The execution storage struct to load from.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`HookConfig[]`|hooks An array of `HookConfig` items, representing the execution hooks.|


### loadExecHooks

Load execution hooks associated with a validation function.


```solidity
function loadExecHooks(ValidationStorage storage valData) internal view returns (HookConfig[] memory);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`valData`|`ValidationStorage`|The validation storage struct to load from.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`HookConfig[]`|hooks An array of `HookConfig` items, representing the execution hooks.|


### loadValidationHooks

Load validation hooks associated with a validation function.


```solidity
function loadValidationHooks(ValidationStorage storage valData) internal view returns (HookConfig[] memory);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`valData`|`ValidationStorage`|The validation storage struct to load from.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`HookConfig[]`|hooks An array of `HookConfig` items, representing the validation hooks.|


### loadSelectors

Load all selectors that have been added to a validation function.


```solidity
function loadSelectors(ValidationStorage storage valData) internal view returns (bytes4[] memory selectors);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`valData`|`ValidationStorage`|The validation storage struct to load from.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`selectors`|`bytes4[]`|An array of the selectors the validation function is allowed to validate.|


### reverseArr

Reverses an array of `HookConfig` items in place.


```solidity
function reverseArr(HookConfig[] memory hooks) internal pure;
```

### reverseArr

Reverses an array of `bytes4` items in place.


```solidity
function reverseArr(bytes4[] memory selectors) internal pure;
```

### getExecuteTarget

If the callData is an encoded function call to IModularAccount.execute, retrieves the target of the
call.


```solidity
function getExecuteTarget(bytes calldata callData) internal pure returns (address);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`callData`|`bytes`|The calldata to check.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`address`|target The target of the call.|


### freezeFMP

Captures a snapshot of the free memory pointer.


```solidity
function freezeFMP() internal pure returns (MemSnapshot);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`MemSnapshot`|The snapshot of the free memory pointer.|


### restoreFMP

Restores the free memory pointer to a previous snapshot.

*This invalidates any memory allocated since the snapshot was taken.*


```solidity
function restoreFMP(MemSnapshot snapshot) internal pure;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`snapshot`|`MemSnapshot`|The snapshot to restore to.|


### _loadValidationAssociatedHooks

Used to load both pre validation hooks and pre execution hooks, associated with a validation
function. The caller must first get the length of the hooks from the ValidationStorage struct.


```solidity
function _loadValidationAssociatedHooks(uint256 hookCount, LinkedListSet storage hooks)
    private
    view
    returns (HookConfig[] memory);
```

### _reverseArr


```solidity
function _reverseArr(bytes32[] memory hooks) private pure;
```

