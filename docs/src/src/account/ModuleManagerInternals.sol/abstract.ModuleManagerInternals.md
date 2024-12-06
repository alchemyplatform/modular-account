# ModuleManagerInternals
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/22a036bde57711d56f967db6e1ecc2ae54755e1a/src/account/ModuleManagerInternals.sol)

**Inherits:**
IModularAccount

**Author:**
Alchemy

This abstract contract hosts the internal installation and uninstallation methods of execution and
validation functions. Methods here update the account storage.


## Functions
### _setValidationFunction


```solidity
function _setValidationFunction(
    ValidationStorage storage validationStorage,
    ValidationConfig validationConfig,
    bytes4[] calldata selectors
) internal;
```

### _removeValidationFunction


```solidity
function _removeValidationFunction(ValidationStorage storage validationStorage) internal;
```

### _installValidation


```solidity
function _installValidation(
    ValidationConfig validationConfig,
    bytes4[] calldata selectors,
    bytes calldata installData,
    bytes[] calldata hooks
) internal;
```

### _uninstallValidation


```solidity
function _uninstallValidation(
    ModuleEntity validationFunction,
    bytes calldata uninstallData,
    bytes[] calldata hookUninstallDatas
) internal;
```

## Errors
### ArrayLengthMismatch

```solidity
error ArrayLengthMismatch();
```

### PreValidationHookDuplicate

```solidity
error PreValidationHookDuplicate();
```

### ValidationEntityIdInUse

```solidity
error ValidationEntityIdInUse();
```

### ValidationAlreadySet

```solidity
error ValidationAlreadySet(bytes4 selector, ModuleEntity validationFunction);
```

### ValidationAssocHookLimitExceeded

```solidity
error ValidationAssocHookLimitExceeded();
```

