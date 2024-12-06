# ModuleBase
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/22a036bde57711d56f967db6e1ecc2ae54755e1a/src/modules/ModuleBase.sol)

**Inherits:**
ERC165, IModule

**Author:**
Alchemy

*Implements ERC-165 to support IModule's interface, which is a requirement for module installation.*


## Functions
### assertNoData


```solidity
modifier assertNoData(bytes calldata data);
```

### supportsInterface

*Returns true if this contract implements the interface defined by
`interfaceId`. See the corresponding
https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
to learn more about how these ids are created.
This function call must use less than 30 000 gas.
Supporting the IModule interface is a requirement for module installation. This is also used
by the modular account to prevent standard execution functions `execute` and `executeBatch` from
making calls to modules.*


```solidity
function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`interfaceId`|`bytes4`|The interface ID to check for support.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|True if the contract supports `interfaceId`.|


### _getSelectorAndCalldata

*help method that returns extracted selector and calldata. If selector is executeUserOp, return the
selector and calldata of the inner call.*


```solidity
function _getSelectorAndCalldata(bytes calldata data) internal pure returns (bytes4, bytes memory);
```

## Errors
### NotImplemented

```solidity
error NotImplemented();
```

### UnexpectedDataPassed

```solidity
error UnexpectedDataPassed();
```

