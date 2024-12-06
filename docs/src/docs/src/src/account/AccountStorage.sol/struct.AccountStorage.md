# AccountStorage
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/30301ded6ae1a71c760933b7a75d6ac5437c1ae3/src/account/AccountStorage.sol)

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

