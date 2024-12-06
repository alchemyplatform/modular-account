# LinkedListSetLib
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/2824291b17c11e6f41963e8c13505f2476b92ee6/src/libraries/LinkedListSetLib.sol)

**Author:**
Alchemy

This library provides a set of functions for managing enumerable sets of bytes31 values. It is a fork
of the LinkedListSet library in modular-account-libs, with the following changes:
- The flags feature has been removed, so the library no longer supports both the "has next" flag, and the
user-defined flags.
- The library has been modified to work with bytes31 values instead of bytes30 values.


## Functions
### tryAdd

Add a value to a set.


```solidity
function tryAdd(LinkedListSet storage set, SetValue value) internal returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`set`|`LinkedListSet`|The set to add the value to.|
|`value`|`SetValue`|The value to add.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|True if the value was added, false if the value cannot be added (already exists or is zero).|


### tryRemove

Remove a value from a set.

*This is an O(n) operation, where n is the number of elements in the set.*


```solidity
function tryRemove(LinkedListSet storage set, SetValue value) internal returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`set`|`LinkedListSet`|The set to remove the value from.|
|`value`|`SetValue`|The value to remove.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|True if the value was removed, false if the value does not exist.|


### tryRemoveKnown

Remove a value from a set, given the previous value in the set.

*This is an O(1) operation but requires additional knowledge.*


```solidity
function tryRemoveKnown(LinkedListSet storage set, SetValue value, bytes32 prev) internal returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`set`|`LinkedListSet`|The set to remove the value from.|
|`value`|`SetValue`|The value to remove.|
|`prev`|`bytes32`|The previous value in the set.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|True if the value was removed, false if the value does not exist, or if the wrong prev was specified.|


### clear

Remove all values from a set.

*This is an O(n) operation, where n is the number of elements in the set.*


```solidity
function clear(LinkedListSet storage set) internal;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`set`|`LinkedListSet`|The set to remove the values from.|


### contains

Check if a set contains a value.

*This method does not clear the upper bits of `value`, that is expected to be done as part of casting
to the correct type. If this function is provided the sentinel value by using the upper bits, this function
may returns `true`.*


```solidity
function contains(LinkedListSet storage set, SetValue value) internal view returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`set`|`LinkedListSet`|The set to check.|
|`value`|`SetValue`|The value to check for.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|True if the set contains the value, false otherwise.|


### isEmpty

Check if a set is empty.


```solidity
function isEmpty(LinkedListSet storage set) internal view returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`set`|`LinkedListSet`|The set to check.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|True if the set is empty, false otherwise.|


### getAll

Get all elements in a set.

*This is an O(n) operation, where n is the number of elements in the set.*


```solidity
function getAll(LinkedListSet storage set) internal view returns (SetValue[] memory ret);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`set`|`LinkedListSet`|The set to get the elements of.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ret`|`SetValue[]`|An array of all elements in the set.|


### isSentinel


```solidity
function isSentinel(bytes32 value) internal pure returns (bool ret);
```

