# ModularAccount
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/2824291b17c11e6f41963e8c13505f2476b92ee6/src/account/ModularAccount.sol)

**Inherits:**
[ModularAccountBase](/src/account/ModularAccountBase.sol/abstract.ModularAccountBase.md)

**Author:**
Alchemy

This contract allows initializing with a validation config (of a validation module) to be installed on
the account.


## Functions
### constructor


```solidity
constructor(IEntryPoint entryPoint, ExecutionInstallDelegate executionInstallDelegate)
    ModularAccountBase(entryPoint, executionInstallDelegate);
```

### initializeWithValidation

Initializes the account with a validation function.

*This function is only callable once.*


```solidity
function initializeWithValidation(
    ValidationConfig validationConfig,
    bytes4[] calldata selectors,
    bytes calldata installData,
    bytes[] calldata hooks
) external virtual initializer;
```

### accountId

Return a unique identifier for the account implementation.

*This function MUST return a string in the format "vendor.account.semver". The vendor and account
names MUST NOT contain a period character.*


```solidity
function accountId() external pure override returns (string memory);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`string`|The account ID.|


### _isNativeFunction

*Overrides ModularAccountView.*


```solidity
function _isNativeFunction(uint32 selector) internal pure override returns (bool);
```

