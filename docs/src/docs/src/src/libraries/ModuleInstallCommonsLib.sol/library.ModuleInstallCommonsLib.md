# ModuleInstallCommonsLib
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/30301ded6ae1a71c760933b7a75d6ac5437c1ae3/src/libraries/ModuleInstallCommonsLib.sol)

**Author:**
Alchemy

This is an internal library which holds module installation-related functions relevant to both the
ExecutionInstallDelegate and the ModuleManagerInternals contracts.


## Functions
### addExecHooks

*adds an execution hook to a specific set of hooks.*


```solidity
function addExecHooks(LinkedListSet storage hooks, HookConfig hookConfig) internal;
```

### onInstall

*setup the module storage for the account, reverts are bubbled up into a custom
ModuleInstallCallbackFailed*


```solidity
function onInstall(address module, bytes calldata data, bytes4 interfaceId) internal;
```

### onUninstall

*clear the module storage for the account, reverts are IGNORED. Status is included in emitted event.*


```solidity
function onUninstall(address module, bytes calldata data) internal returns (bool onUninstallSuccess);
```

## Errors
### InterfaceNotSupported

```solidity
error InterfaceNotSupported(address module);
```

### ModuleInstallCallbackFailed

```solidity
error ModuleInstallCallbackFailed(address module, bytes revertReason);
```

### ExecutionHookAlreadySet

```solidity
error ExecutionHookAlreadySet(HookConfig hookConfig);
```

