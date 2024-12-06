# ExecutionStorage
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/a15fd11665cc3bcdef40d456208c0f7907b5a3eb/src/account/AccountStorage.sol)

Represents data associated with a specific function selector.


```solidity
struct ExecutionStorage {
    address module;
    bool skipRuntimeValidation;
    bool allowGlobalValidation;
    LinkedListSet executionHooks;
}
```

