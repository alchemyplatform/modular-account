# SemiModularAccount7702
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/2824291b17c11e6f41963e8c13505f2476b92ee6/src/account/SemiModularAccount7702.sol)

**Inherits:**
[SemiModularAccountBase](/src/account/SemiModularAccountBase.sol/abstract.SemiModularAccountBase.md)

**Author:**
Alchemy

An implementation of a semi-modular account which reads the signer as the address(this).

*Inherits SemiModularAccountBase. This account can be used as the delegate contract of an EOA with
EIP-7702, where address(this) (aka the EOA address) is the default fallback signer.*


## Functions
### constructor


```solidity
constructor(IEntryPoint entryPoint, ExecutionInstallDelegate executionInstallDelegate)
    SemiModularAccountBase(entryPoint, executionInstallDelegate);
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


### upgradeToAndCall


```solidity
function upgradeToAndCall(address, bytes calldata) public payable override;
```

### _retrieveFallbackSignerUnchecked

*If the fallback signer is set in storage, means the fallback signer has been updated. We ignore the
address(this) EOA signer.*


```solidity
function _retrieveFallbackSignerUnchecked(SemiModularAccountStorage storage _storage)
    internal
    view
    override
    returns (address);
```

## Errors
### UpgradeNotAllowed

```solidity
error UpgradeNotAllowed();
```

