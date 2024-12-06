# AccountStorage
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/a15fd11665cc3bcdef40d456208c0f7907b5a3eb/src/account/AccountStorage.sol)

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

