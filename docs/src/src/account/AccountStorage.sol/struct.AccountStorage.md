# AccountStorage
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/2824291b17c11e6f41963e8c13505f2476b92ee6/src/account/AccountStorage.sol)

**Note:**
erc7201:Alchemy.ModularAccount.Storage_V2


```solidity
struct AccountStorage {
    uint64 initialized;
    bool initializing;
    mapping(bytes4 selector => ExecutionStorage) executionStorage;
    mapping(ValidationLookupKey lookupKey => ValidationStorage) validationStorage;
    mapping(bytes4 => uint256) supportedIfaces;
}
```

