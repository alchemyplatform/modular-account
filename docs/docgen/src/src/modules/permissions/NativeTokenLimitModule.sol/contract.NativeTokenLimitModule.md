# NativeTokenLimitModule
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/a15fd11665cc3bcdef40d456208c0f7907b5a3eb/src/modules/permissions/NativeTokenLimitModule.sol)

**Inherits:**
[ModuleBase](/src/modules/ModuleBase.sol/abstract.ModuleBase.md), IExecutionHookModule, IValidationHookModule

**Author:**
Alchemy

This module supports a total native token spend limit across User Operation gas and native transfers.
- None of the functions are installed on the account. Account states are to be retrieved from this global
singleton directly.
- This module only tracks native transfers for the 3 functions `execute`, `executeBatch`, `performCreate`.
- By default, using a paymaster in a UO would cause the limit to not decrease. If an account uses a special
paymaster that converts non-native tokens in the account to pay for gas, this paymaster should be added to
the `specialPaymasters` list to enable the correct accounting of spend limits. When these paymasters are used
to pay for a UO, spend limits would be decremented.


## State Variables
### limits

```solidity
mapping(uint256 entityId => mapping(address account => uint256 limit)) public limits;
```


### specialPaymasters

```solidity
mapping(address paymaster => mapping(address account => bool allowed)) public specialPaymasters;
```


## Functions
### updateLimits

Update the native token limit for a specific entity


```solidity
function updateLimits(uint32 entityId, uint256 newLimit) external;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`entityId`|`uint32`|The entity id|
|`newLimit`|`uint256`|The new limit|


### updateSpecialPaymaster

Update special paymasters that should still decrease the limit of an account


```solidity
function updateSpecialPaymaster(address paymaster, bool allowed) external;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`paymaster`|`address`|The paymaster address|
|`allowed`|`bool`|Whether the paymaster is allowed to pull funds from the account|


### preUserOpValidationHook

Run the pre user operation validation hook specified by the `entityId`.

*Pre user operation validation hooks MUST NOT return an authorizer value other than 0 or 1.*


```solidity
function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata userOp, bytes32)
    external
    assertNoData(userOp.signature)
    returns (uint256);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`entityId`|`uint32`|An identifier that routes the call to different internal implementations, should there be more than one.|
|`userOp`|`PackedUserOperation`|The user operation.|
|`<none>`|`bytes32`||

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint256`|Packed validation data for validAfter (6 bytes), validUntil (6 bytes), and authorizer (20 bytes).|


### preExecutionHook

Run the pre execution hook specified by the `entityId`.

*To indicate the entire call should revert, the function MUST revert.*


```solidity
function preExecutionHook(uint32 entityId, address, uint256, bytes calldata data)
    external
    override
    returns (bytes memory);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`entityId`|`uint32`|An identifier that routes the call to different internal implementations, should there be more than one.|
|`<none>`|`address`||
|`<none>`|`uint256`||
|`data`|`bytes`|The calldata sent. For `executeUserOp` calls, hook modules should receive the full msg.data.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bytes`|Context to pass to a post execution hook, if present. An empty bytes array MAY be returned.|


### onInstall

Initialize module data for the modular account.

*Called by the modular account during `installExecution`.*


```solidity
function onInstall(bytes calldata data) external override;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`data`|`bytes`|Optional bytes array to be decoded and used by the module to setup initial module data for the modular account.|


### onUninstall

Clear module data for the modular account.

*Called by the modular account during `uninstallExecution`.*


```solidity
function onUninstall(bytes calldata data) external override;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`data`|`bytes`|Optional bytes array to be decoded and used by the module to clear module data for the modular account.|


### postExecutionHook

Run the post execution hook specified by the `entityId`.

*To indicate the entire call should revert, the function MUST revert.*


```solidity
function postExecutionHook(uint32, bytes calldata) external pure override;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint32`||
|`<none>`|`bytes`||


### preRuntimeValidationHook


```solidity
function preRuntimeValidationHook(uint32, address, uint256, bytes calldata, bytes calldata)
    external
    pure
    override;
```

### preSignatureValidationHook


```solidity
function preSignatureValidationHook(uint32, address, bytes32, bytes calldata) external pure override;
```

### moduleId

Return a unique identifier for the module.

*This function MUST return a string in the format "vendor.module.semver". The vendor and module
names MUST NOT contain a period character.*


```solidity
function moduleId() external pure returns (string memory);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`string`|The module ID.|


### supportsInterface

*Returns true if this contract implements the interface defined by
`interfaceId`. See the corresponding
https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
to learn more about how these ids are created.
This function call must use less than 30 000 gas.
Supporting the IModule interface is a requirement for module installation. This is also used
by the modular account to prevent standard execution functions `execute` and `executeBatch` from
making calls to modules.*


```solidity
function supportsInterface(bytes4 interfaceId) public view override(ModuleBase, IERC165) returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`interfaceId`|`bytes4`|The interface ID to check for support.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|True if the contract supports `interfaceId`.|


### _decreaseLimit


```solidity
function _decreaseLimit(uint32 entityId, PackedUserOperation calldata userOp, bool hasPaymaster) internal;
```

## Events
### NativeTokenSpendLimitUpdated

```solidity
event NativeTokenSpendLimitUpdated(uint32 indexed entityId, address indexed account, uint256 newLimit);
```

### SpecialPaymasterUpdated

```solidity
event SpecialPaymasterUpdated(address indexed account, address indexed paymaster, bool allowed);
```

## Errors
### ExceededNativeTokenLimit

```solidity
error ExceededNativeTokenLimit();
```

### InvalidPaymaster

```solidity
error InvalidPaymaster();
```

