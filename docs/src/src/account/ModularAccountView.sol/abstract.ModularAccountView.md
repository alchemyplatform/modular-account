# ModularAccountView
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/22a036bde57711d56f967db6e1ecc2ae54755e1a/src/account/ModularAccountView.sol)

**Inherits:**
IModularAccountView

**Author:**
Alchemy

This abstract contract implements the two view functions to get validation and execution data for an
account.


## Functions
### getExecutionData

Get the execution data for a selector.

*If the selector is a native function, the module address will be the address of the account.*


```solidity
function getExecutionData(bytes4 selector) external view override returns (ExecutionDataView memory data);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`selector`|`bytes4`|The selector to get the data for.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`data`|`ExecutionDataView`|The execution data for this selector.|


### getValidationData

Get the validation data for a validation function.

*If the selector is a native function, the module address will be the address of the account.*


```solidity
function getValidationData(ModuleEntity validationFunction)
    external
    view
    override
    returns (ValidationDataView memory data);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`validationFunction`|`ModuleEntity`|The validation function to get the data for.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`data`|`ValidationDataView`|The validation data for this validation function.|


### _isNativeFunction


```solidity
function _isNativeFunction(uint32 selector) internal pure virtual returns (bool);
```

### _isGlobalValidationAllowedNativeFunction

*Check whether a function is a native function that allows global validation.*


```solidity
function _isGlobalValidationAllowedNativeFunction(uint32 selector) internal pure virtual returns (bool);
```

### _isWrappedNativeFunction

*Check whether a function is a native function that has the `wrapNativeFunction` modifier applied,
which means it runs execution hooks associated with its selector.*


```solidity
function _isWrappedNativeFunction(uint32 selector) internal pure virtual returns (bool);
```

