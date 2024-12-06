# ExecutionStorage
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/2824291b17c11e6f41963e8c13505f2476b92ee6/src/account/AccountStorage.sol)

Represents data associated with a specific function selector.


```solidity
struct ExecutionStorage {
    address module;
    bool skipRuntimeValidation;
    bool allowGlobalValidation;
    LinkedListSet executionHooks;
}
```

