# AccountStorageInitializable
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/30301ded6ae1a71c760933b7a75d6ac5437c1ae3/src/account/AccountStorageInitializable.sol)

**Author:**
Alchemy

A contract mixin that provides the functionality of OpenZeppelin's Initializable contract, using the
custom storage layout defined by the AccountStorage struct.

*The implementation logic here is modified from OpenZeppelin's Initializable contract from v5.0.*


## Functions
### initializer

Modifier to put on function intended to be called only once per implementation

*Reverts if the contract has already been initialized*


```solidity
modifier initializer();
```

### _disableInitializers

Internal function to disable calls to initialization functions

*Reverts if the contract is currently initializing.*


```solidity
function _disableInitializers() internal virtual;
```

## Events
### Initialized
*Triggered when the contract has been initialized or reinitialized.*


```solidity
event Initialized(uint64 version);
```

## Errors
### InvalidInitialization
*The contract is already initialized.*


```solidity
error InvalidInitialization();
```

