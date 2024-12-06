# ValidationStorage
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/30301ded6ae1a71c760933b7a75d6ac5437c1ae3/src/account/AccountStorage.sol)

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

