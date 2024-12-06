# ValidationStorage
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/a15fd11665cc3bcdef40d456208c0f7907b5a3eb/src/account/AccountStorage.sol)

Represents data associated with a specific validation function.


```solidity
struct ValidationStorage {
    address module;
    ValidationFlags validationFlags;
    uint8 validationHookCount;
    uint8 executionHookCount;
    LinkedListSet validationHooks;
    LinkedListSet executionHooks;
    LinkedListSet selectors;
}
```

