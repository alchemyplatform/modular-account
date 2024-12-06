# SemiModularAccountBytecode
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/22a036bde57711d56f967db6e1ecc2ae54755e1a/src/account/SemiModularAccountBytecode.sol)

**Inherits:**
[SemiModularAccountBase](/src/account/SemiModularAccountBase.sol/abstract.SemiModularAccountBase.md)

**Author:**
Alchemy

An implementation of a semi-modular account which reads the signer from proxy bytecode if it is not
disabled and zero in storage.

*Inherits SemiModularAccountBase. This account requires that its proxy is compliant with Solady's LibClone
ERC1967WithImmutableArgs bytecode with a bytecode-appended address (should be encodePacked) to be used as the
fallback signer.*


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


### _retrieveFallbackSignerUnchecked

*If the fallback signer is set in storage, we ignore the bytecode signer.*


```solidity
function _retrieveFallbackSignerUnchecked(SemiModularAccountStorage storage _storage)
    internal
    view
    override
    returns (address);
```

