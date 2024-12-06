# AccountStorage
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/22a036bde57711d56f967db6e1ecc2ae54755e1a/src/account/AccountStorage.sol)

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

