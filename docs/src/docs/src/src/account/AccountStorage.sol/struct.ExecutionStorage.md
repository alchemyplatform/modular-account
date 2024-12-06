# ExecutionStorage
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/30301ded6ae1a71c760933b7a75d6ac5437c1ae3/src/account/AccountStorage.sol)

Represents data associated with a specific function selector.


```solidity
struct ExecutionStorage {
    address module;
    bool skipRuntimeValidation;
    bool allowGlobalValidation;
    LinkedListSet executionHooks;
}
```

