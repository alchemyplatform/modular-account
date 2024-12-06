# SemiModularAccountStorageOnly
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/a15fd11665cc3bcdef40d456208c0f7907b5a3eb/src/account/SemiModularAccountStorageOnly.sol)

**Inherits:**
[SemiModularAccountBase](/src/account/SemiModularAccountBase.sol/abstract.SemiModularAccountBase.md)

**Author:**
Alchemy

An implementation of a semi-modular account which includes an initializer to set the fallback signer in
storage upon initialization.

*Inherits SemiModularAccountBase. Note that the initializer has no access control and should be called via
`upgradeToAndCall()`. Use the `SemiModularAccountBytecode` instead for new accounts, this implementation should
only be used for account upgrades.*


## Functions
### constructor


```solidity
constructor(IEntryPoint entryPoint, ExecutionInstallDelegate executionInstallDelegate)
    SemiModularAccountBase(entryPoint, executionInstallDelegate);
```

### initialize


```solidity
function initialize(address initialSigner) external initializer;
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

*Overrides SemiModularAccountBase.*


```solidity
function _isNativeFunction(uint32 selector) internal pure override returns (bool);
```

