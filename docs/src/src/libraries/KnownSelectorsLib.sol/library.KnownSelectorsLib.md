# KnownSelectorsLib
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/2824291b17c11e6f41963e8c13505f2476b92ee6/src/libraries/KnownSelectorsLib.sol)

**Author:**
Alchemy

Library to help to check if a selector is an ERC-6900 module function or a an ERC-4337 contract
function.


## Functions
### isERC4337Function

Check if a selector is an ERC-4337 function.


```solidity
function isERC4337Function(uint32 selector) internal pure returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`selector`|`uint32`|The selector to check.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|True if the selector is an ERC-4337 function, false otherwise.|


### isIModuleFunction

Check if a selector is an ERC-6900 module function.


```solidity
function isIModuleFunction(uint32 selector) internal pure returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`selector`|`uint32`|The selector to check.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|True if the selector is an ERC-6900 module function, false otherwise.|


