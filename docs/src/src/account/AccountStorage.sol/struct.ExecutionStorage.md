# ExecutionStorage
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/22a036bde57711d56f967db6e1ecc2ae54755e1a/src/account/AccountStorage.sol)

Represents data associated with a specific function selector.


```solidity
struct ExecutionStorage {
    address module;
    bool skipRuntimeValidation;
    bool allowGlobalValidation;
    LinkedListSet executionHooks;
}
```

