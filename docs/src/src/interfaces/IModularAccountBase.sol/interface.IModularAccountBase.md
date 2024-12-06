# IModularAccountBase
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/2824291b17c11e6f41963e8c13505f2476b92ee6/src/interfaces/IModularAccountBase.sol)


## Functions
### performCreate

Create a contract.


```solidity
function performCreate(uint256 value, bytes calldata initCode, bool isCreate2, bytes32 salt)
    external
    payable
    returns (address createdAddr);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`value`|`uint256`|The value to send to the new contract constructor|
|`initCode`|`bytes`|The initCode to deploy.|
|`isCreate2`|`bool`|The bool to indicate which method to use to deploy.|
|`salt`|`bytes32`|The salt for deployment.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`createdAddr`|`address`|The created contract address.|


