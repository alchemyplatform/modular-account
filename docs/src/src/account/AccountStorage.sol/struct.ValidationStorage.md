# ValidationStorage
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/22a036bde57711d56f967db6e1ecc2ae54755e1a/src/account/AccountStorage.sol)

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

