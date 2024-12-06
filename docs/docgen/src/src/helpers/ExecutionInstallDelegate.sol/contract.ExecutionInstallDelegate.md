# ExecutionInstallDelegate
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/a15fd11665cc3bcdef40d456208c0f7907b5a3eb/src/helpers/ExecutionInstallDelegate.sol)

**Author:**
Alchemy

This contract acts as an external library which is meant to handle execution function installations and
uninstallations via delegatecall.


## State Variables
### _THIS_ADDRESS

```solidity
address internal immutable _THIS_ADDRESS;
```


## Functions
### onlyDelegateCall


```solidity
modifier onlyDelegateCall();
```

### constructor


```solidity
constructor();
```

### installExecution

Update components according to the manifest.


```solidity
function installExecution(address module, ExecutionManifest calldata manifest, bytes calldata moduleInstallData)
    external
    onlyDelegateCall;
```

### uninstallExecution

Remove components according to the manifest, in reverse order (by component type) of their
installation.


```solidity
function uninstallExecution(address module, ExecutionManifest calldata manifest, bytes calldata uninstallData)
    external
    onlyDelegateCall;
```

### _setExecutionFunction


```solidity
function _setExecutionFunction(
    bytes4 selector,
    bool skipRuntimeValidation,
    bool allowGlobalValidation,
    address module
) internal;
```

### _removeExecutionFunction


```solidity
function _removeExecutionFunction(bytes4 selector) internal;
```

### _removeExecHooks


```solidity
function _removeExecHooks(LinkedListSet storage hooks, HookConfig hookConfig) internal;
```

## Errors
### ERC4337FunctionNotAllowed

```solidity
error ERC4337FunctionNotAllowed(bytes4 selector);
```

### ExecutionFunctionAlreadySet

```solidity
error ExecutionFunctionAlreadySet(bytes4 selector);
```

### ExecutionFunctionNotSet

```solidity
error ExecutionFunctionNotSet(bytes4 selector);
```

### ExecutionHookNotSet

```solidity
error ExecutionHookNotSet(HookConfig hookConfig);
```

### IModuleFunctionNotAllowed

```solidity
error IModuleFunctionNotAllowed(bytes4 selector);
```

### NullModule

```solidity
error NullModule();
```

### OnlyDelegateCall

```solidity
error OnlyDelegateCall();
```

