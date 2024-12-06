# ValidationLocatorLib
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/a15fd11665cc3bcdef40d456208c0f7907b5a3eb/src/libraries/ValidationLocatorLib.sol)


## State Variables
### _VALIDATION_TYPE_GLOBAL

```solidity
uint8 internal constant _VALIDATION_TYPE_GLOBAL = 1;
```


### _HAS_DEFERRED_ACTION

```solidity
uint8 internal constant _HAS_DEFERRED_ACTION = 2;
```


### _IS_DIRECT_CALL_VALIDATION

```solidity
uint8 internal constant _IS_DIRECT_CALL_VALIDATION = 4;
```


## Functions
### moduleEntity


```solidity
function moduleEntity(ValidationLookupKey _lookupKey, ValidationStorage storage validationStorage)
    internal
    view
    returns (ModuleEntity result);
```

### loadFromNonce


```solidity
function loadFromNonce(uint256 nonce) internal pure returns (ValidationLocator result);
```

### loadFromSignature


```solidity
function loadFromSignature(bytes calldata signature)
    internal
    pure
    returns (ValidationLocator result, bytes calldata remainder);
```

### directCallAddress


```solidity
function directCallAddress(ValidationLookupKey _lookupKey) internal pure returns (address result);
```

### entityId


```solidity
function entityId(ValidationLookupKey _lookupKey) internal pure returns (uint32 result);
```

### isGlobal


```solidity
function isGlobal(ValidationLocator locator) internal pure returns (bool);
```

### hasDeferredAction


```solidity
function hasDeferredAction(ValidationLocator locator) internal pure returns (bool);
```

### isDirectCallValidation


```solidity
function isDirectCallValidation(ValidationLookupKey _lookupKey) internal pure returns (bool);
```

### configToLookupKey


```solidity
function configToLookupKey(ValidationConfig validationConfig) internal pure returns (ValidationLookupKey result);
```

### moduleEntityToLookupKey


```solidity
function moduleEntityToLookupKey(ModuleEntity _moduleEntity) internal pure returns (ValidationLookupKey result);
```

### directCallLookupKey


```solidity
function directCallLookupKey(address directCallValidation) internal pure returns (ValidationLookupKey result);
```

### lookupKey


```solidity
function lookupKey(ValidationLocator locator) internal pure returns (ValidationLookupKey result);
```

### pack


```solidity
function pack(uint32 _entityId, bool _isGlobal, bool _hasDeferredAction)
    internal
    pure
    returns (ValidationLocator);
```

### packDirectCall


```solidity
function packDirectCall(address directCallValidation, bool _isGlobal, bool _hasDeferredAction)
    internal
    pure
    returns (ValidationLocator);
```

### packNonce


```solidity
function packNonce(uint32 validationEntityId, bool _isGlobal, bool _hasDeferredAction)
    internal
    pure
    returns (uint256 result);
```

### packNonceDirectCall


```solidity
function packNonceDirectCall(address directCallValidation, bool _isGlobal, bool _hasDeferredAction)
    internal
    pure
    returns (uint256 result);
```

### packSignature


```solidity
function packSignature(uint32 validationEntityId, bool _isGlobal, bool _hasDeferredAction, bytes memory signature)
    internal
    pure
    returns (bytes memory result);
```

### packSignatureDirectCall


```solidity
function packSignatureDirectCall(
    address directCallValidation,
    bool _isGlobal,
    bool _hasDeferredAction,
    bytes memory signature
) internal pure returns (bytes memory result);
```

### packFromModuleEntity


```solidity
function packFromModuleEntity(ModuleEntity _moduleEntity, bool _isGlobal, bool _hasDeferredAction)
    internal
    pure
    returns (ValidationLocator);
```

### eq


```solidity
function eq(ValidationLookupKey a, ValidationLookupKey b) internal pure returns (bool);
```

