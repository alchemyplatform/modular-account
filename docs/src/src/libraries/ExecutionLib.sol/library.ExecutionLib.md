# ExecutionLib
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/2824291b17c11e6f41963e8c13505f2476b92ee6/src/libraries/ExecutionLib.sol)

**Author:**
Alchemy

A library for performing external calls. This library is used for the external calls of `execute` and
`executeBatch`, for any account self-calls, and for any call to a module function.

*This library uses "call buffers", or reusable memory buffers that hold the abi-encoded data to be sent to
a module function. These buffers are used to avoid the overhead of encoding the same data multiple times.*


## Functions
### callBubbleOnRevert

Perform the following call, without capturing any return data.
If the call reverts, the revert message will be directly bubbled up.


```solidity
function callBubbleOnRevert(address target, uint256 value, bytes memory callData) internal;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`target`|`address`|The address to call.|
|`value`|`uint256`|The value to send with the call.|
|`callData`|`bytes`|The data to send with the call.|


### callBubbleOnRevertTransient

Transiently copy the call data to a memory, and perform a self-call.
If the call reverts, the revert message will be directly bubbled up.


```solidity
function callBubbleOnRevertTransient(address target, uint256 value, bytes calldata callData) internal;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`target`|`address`|The address to call.|
|`value`|`uint256`|The value to send with the call.|
|`callData`|`bytes`|The data to send with the call.|


### delegatecallBubbleOnRevertTransient


```solidity
function delegatecallBubbleOnRevertTransient(address target) internal;
```

### collectReturnData

Manually collect and store the return data from the most recent external call into a `bytes
memory`.


```solidity
function collectReturnData() internal pure returns (bytes memory returnData);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`returnData`|`bytes`|The return data from the most recent external call.|


### allocateUserOpValidationCallBuffer


```solidity
function allocateUserOpValidationCallBuffer(PackedUserOperation calldata userOp, bytes32 userOpHash)
    internal
    pure
    returns (UOCallBuffer result);
```

### convertToValidationBuffer


```solidity
function convertToValidationBuffer(UOCallBuffer buffer) internal pure;
```

### invokeUserOpCallBuffer


```solidity
function invokeUserOpCallBuffer(UOCallBuffer buffer, ModuleEntity moduleEntity, bytes calldata signatureSegment)
    internal
    returns (uint256 validationData);
```

### allocateRuntimeValidationCallBuffer


```solidity
function allocateRuntimeValidationCallBuffer(bytes calldata callData, bytes calldata authorization)
    internal
    returns (RTCallBuffer result);
```

### invokeRuntimeCallBufferPreValidationHook


```solidity
function invokeRuntimeCallBufferPreValidationHook(
    RTCallBuffer buffer,
    HookConfig hookEntity,
    bytes calldata authorizationSegment
) internal;
```

### invokeRuntimeCallBufferValidation


```solidity
function invokeRuntimeCallBufferValidation(
    RTCallBuffer buffer,
    ModuleEntity moduleEntity,
    bytes calldata authorizationSegment
) internal;
```

### executeRuntimeSelfCall


```solidity
function executeRuntimeSelfCall(RTCallBuffer buffer, bytes calldata data) internal;
```

### convertToPreHookCallBuffer


```solidity
function convertToPreHookCallBuffer(RTCallBuffer buffer, bytes calldata data)
    internal
    view
    returns (PHCallBuffer result);
```

### allocatePreExecHookCallBuffer


```solidity
function allocatePreExecHookCallBuffer(bytes calldata data) internal view returns (PHCallBuffer);
```

### invokePreExecHook


```solidity
function invokePreExecHook(PHCallBuffer buffer, HookConfig hookEntity)
    internal
    returns (uint256 returnedBytesSize);
```

### getExecuteUOCallData


```solidity
function getExecuteUOCallData(PHCallBuffer buffer, bytes calldata callData) internal pure returns (bytes memory);
```

### doPreHooks


```solidity
function doPreHooks(HookConfig[] memory hooks, PHCallBuffer callBuffer)
    internal
    returns (DensePostHookData result);
```

### doCachedPostHooks


```solidity
function doCachedPostHooks(DensePostHookData postHookData) internal;
```

### allocateSigCallBuffer


```solidity
function allocateSigCallBuffer(bytes32 hash, bytes calldata signature)
    internal
    view
    returns (SigCallBuffer result);
```

### invokePreSignatureValidationHook


```solidity
function invokePreSignatureValidationHook(
    SigCallBuffer buffer,
    HookConfig hookEntity,
    bytes calldata signatureSegment
) internal view;
```

### invokeSignatureValidation


```solidity
function invokeSignatureValidation(
    SigCallBuffer buffer,
    ModuleEntity validationFunction,
    bytes calldata signatureSegment
) internal view returns (bytes4 result);
```

### _appendPostHookToRun

Appends a post hook to run to the dense post hook data buffer.


```solidity
function _appendPostHookToRun(bytes32 workingMemPtr, HookConfig hookConfig, uint256 returnedBytesSize)
    private
    pure
    returns (bytes32);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`workingMemPtr`|`bytes32`|The current working memory pointer|
|`hookConfig`|`HookConfig`|The hook configuration|
|`returnedBytesSize`|`uint256`|The size of the returned bytes from the pre hook|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bytes32`|The new working memory pointer|


### _revertModuleFunction


```solidity
function _revertModuleFunction(uint32 errorSelector, address moduleAddress, uint32 entityId) private pure;
```

### _prepareRuntimeCallBufferPreValidationHooks


```solidity
function _prepareRuntimeCallBufferPreValidationHooks(RTCallBuffer buffer) private pure;
```

### _prepareSigValidationCallBufferPreSigValidationHooks


```solidity
function _prepareSigValidationCallBufferPreSigValidationHooks(SigCallBuffer buffer) private pure;
```

## Errors
### PostExecHookReverted

```solidity
error PostExecHookReverted(ModuleEntity moduleFunction, bytes revertReason);
```

### PreExecHookReverted

```solidity
error PreExecHookReverted(ModuleEntity moduleFunction, bytes revertReason);
```

### PreRuntimeValidationHookReverted

```solidity
error PreRuntimeValidationHookReverted(ModuleEntity moduleFunction, bytes revertReason);
```

### PreSignatureValidationHookReverted

```solidity
error PreSignatureValidationHookReverted(ModuleEntity moduleFunction, bytes revertReason);
```

### PreUserOpValidationHookReverted

```solidity
error PreUserOpValidationHookReverted(ModuleEntity moduleFunction, bytes revertReason);
```

### RuntimeValidationFunctionReverted

```solidity
error RuntimeValidationFunctionReverted(ModuleEntity moduleFunction, bytes revertReason);
```

### SignatureValidationFunctionReverted

```solidity
error SignatureValidationFunctionReverted(ModuleEntity moduleFunction, bytes revertReason);
```

### UserOpValidationFunctionReverted

```solidity
error UserOpValidationFunctionReverted(ModuleEntity moduleFunction, bytes revertReason);
```

