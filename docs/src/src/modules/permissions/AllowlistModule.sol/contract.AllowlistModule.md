# AllowlistModule
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/2824291b17c11e6f41963e8c13505f2476b92ee6/src/modules/permissions/AllowlistModule.sol)

**Inherits:**
IExecutionHookModule, IValidationHookModule, [ModuleBase](/src/modules/ModuleBase.sol/abstract.ModuleBase.md)

**Author:**
Alchemy

This module allows for the setting and enforcement of allowlists with ERC-20 spend limit for an entity.
- Uninstallation will NOT disable all installed hooks for an account. It only uninstalls hooks for the
entity ID that is passed in. Account must remove access for each entity ID if want to disable all hooks.
- None of the functions are installed on the account. Account states are to be retrieved from this global
singleton directly.
- To enable allowlisting, the account must have this module installed as a validation hook.
- These allowlists can specify which addresses and or selectors can be called by the entity. It supports:
- Specific addresses + specific selectors
- Specific addresses + wildcard selectors
- Wildcard addresses + specific selectors
- These restrictions only apply to the `IModularAccount.execute` and `IModularAccount.executeBatch`
functions.
- The order of permission checks:
- If wildcard address (any selector allowed), pass
- If wildcard selector (any address allowed), pass
- If specific address + specific selector, pass
- Revert all other cases
- To enable ERC-20 spend limits, the account must also have this module installed as a validation associated
execution hook. The following features and restrictions apply:
- Only token contracts with a set limit will be checked, other allowed addresses will be allowed. To
protect the account's balance of non-tracked tokens, users are recommended to also install the allowlist
validation hook, to limit which addresses the validation may perform calls to.
- Spending requests are only supported through the following native execution functions:
IModularAccount.execute, IModularAccount.executeWithRuntimeValidation, IAccountExecute.executeUserOp,
IModularAccount.executeBatch. All other spending request will revert.
- This module is opinionated on what selectors can be called for token contracts: only `transfer` and
`approve` are allowed. This guards against edge cases, where token contracts like DAI have other
functions that result in ERC-20 transfers or allowance changes.


## State Variables
### addressAllowlist

```solidity
mapping(uint32 entityId => mapping(address target => mapping(address account => AddressAllowlistEntry))) public
    addressAllowlist;
```


### erc20SpendLimits
this is only for targets that are tokens, if hasERC20SpendLimit in AddressAllowlistEntry is false,
this value is ignored.


```solidity
mapping(uint32 entityId => mapping(address target => mapping(address account => uint256))) public erc20SpendLimits;
```


### selectorAllowlist
if target is address(0), any address is allowed with the selector


```solidity
mapping(uint32 entityId => mapping(bytes4 selector => mapping(address target => mapping(address account => bool))))
    public selectorAllowlist;
```


## Functions
### onInstall

Initialize module data for the modular account.

*The `data` parameter is expected to be encoded as `(uint32 entityId, AllowlistInput[] inputs)`.*


```solidity
function onInstall(bytes calldata data) external override;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`data`|`bytes`|Optional bytes array to be decoded and used by the module to setup initial module data for the modular account.|


### onUninstall

Clear module data for the modular account.

*The `data` parameter is expected to be encoded as `(uint32 entityId, AllowlistInput[] inputs)`.*


```solidity
function onUninstall(bytes calldata data) external override;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`data`|`bytes`|Optional bytes array to be decoded and used by the module to clear module data for the modular account.|


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


### preUserOpValidationHook

Run the pre user operation validation hook specified by the `entityId`.

*Pre user operation validation hooks MUST NOT return an authorizer value other than 0 or 1.*


```solidity
function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata userOp, bytes32)
    external
    view
    override
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


### preRuntimeValidationHook

Run the pre runtime validation hook specified by the `entityId`.

*To indicate the entire call should revert, the function MUST revert.*


```solidity
function preRuntimeValidationHook(uint32 entityId, address, uint256, bytes calldata data, bytes calldata)
    external
    view
    override;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`entityId`|`uint32`|An identifier that routes the call to different internal implementations, should there be more than one.|
|`<none>`|`address`||
|`<none>`|`uint256`||
|`data`|`bytes`|The calldata sent.|
|`<none>`|`bytes`||


### preSignatureValidationHook


```solidity
function preSignatureValidationHook(uint32, address, bytes32, bytes calldata) external pure override;
```

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


### updateLimits

Update the token limit of a validation


```solidity
function updateLimits(uint32 entityId, address token, bool hasERC20SpendLimit, uint256 newLimit) public;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`entityId`|`uint32`|The validation entityId to update|
|`token`|`address`|The token address whose limit will be updated|
|`hasERC20SpendLimit`|`bool`||
|`newLimit`|`uint256`|The new limit of the token for the validation|


### updateAllowlist

update the allowlists for a given entity ID. If the entry for an address or selector exist, it will
be overwritten.


```solidity
function updateAllowlist(uint32 entityId, AllowlistInput[] memory inputs) public;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`entityId`|`uint32`|The entity ID to initialize the allowlist for.|
|`inputs`|`AllowlistInput[]`|The allowlist inputs data to update.|


### deleteAllowlist

delete the allowlists for a given entity ID.


```solidity
function deleteAllowlist(uint32 entityId, AllowlistInput[] memory inputs) public;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`entityId`|`uint32`|The entity ID to initialize the allowlist for.|
|`inputs`|`AllowlistInput[]`|The allowlist inputs data to update. Note flag will be set to false despite passed different values.|


### setAddressAllowlist

Set the allowlist status for a target address, in the allowlist of the caller account and the
provided entity ID.


```solidity
function setAddressAllowlist(
    uint32 entityId,
    address target,
    bool allowed,
    bool hasSelectorAllowlist,
    bool hasERC20SpendLimit
) public;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`entityId`|`uint32`|The entity ID to set the allowlist status for.|
|`target`|`address`|The target address.|
|`allowed`|`bool`|The new allowlist status, indicating whether or not the target address can be called.|
|`hasSelectorAllowlist`|`bool`|Whether or not the target address has a selector allowlist. If true, the|
|`hasERC20SpendLimit`|`bool`|Whether or not the target address has a ERC20 spend limit. allowlist checking will validate that the selector is on the selector allowlist.|


### setSelectorAllowlist

Set the allowlist status for a selector, in the allowlist of the caller account and the provided
entity ID.
Note that if the target address does not have a selector allowlist, this update will not be
reflected on the usage of the allowlist hook.


```solidity
function setSelectorAllowlist(uint32 entityId, address target, bytes4 selector, bool allowed) public;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`entityId`|`uint32`|The entity ID to set the allowlist status for.|
|`target`|`address`|The target address.|
|`selector`|`bytes4`|The selector to set the allowlist status for.|
|`allowed`|`bool`|The new allowlist status, indicating whether or not the selector can be called.|


### checkAllowlistCalldata

Check the allowlist status for a call payload. If the call is not allowed, this function will
revert.


```solidity
function checkAllowlistCalldata(uint32 entityId, bytes calldata callData) public view;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`entityId`|`uint32`|The entity ID to check the allowlist status for.|
|`callData`|`bytes`|The call payload to check the allowlist status for. This should be a call to either `IModularAccount.execute`, or `IModularAccount.executeBatch`.|


### supportsInterface

Query if a contract implements an interface

*Interface identification is specified in ERC-165. This function
uses less than 30,000 gas.*


```solidity
function supportsInterface(bytes4 interfaceId) public view virtual override(ModuleBase, IERC165) returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`interfaceId`|`bytes4`||

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|`true` if the contract implements `interfaceID` and `interfaceID` is not 0xffffffff, `false` otherwise|


### _decrementLimitIfApplies


```solidity
function _decrementLimitIfApplies(uint32 entityId, address token, bytes memory innerCalldata) internal;
```

### _checkCallPermission


```solidity
function _checkCallPermission(uint32 entityId, address account, address target, bytes memory data) internal view;
```

### _isAllowedERC20Function


```solidity
function _isAllowedERC20Function(bytes4 selector) internal pure returns (bool);
```

## Events
### AddressAllowlistUpdated

```solidity
event AddressAllowlistUpdated(
    uint32 indexed entityId, address indexed account, address indexed target, AddressAllowlistEntry entry
);
```

### ERC20SpendLimitUpdated

```solidity
event ERC20SpendLimitUpdated(
    uint32 indexed entityId, address indexed account, address indexed token, uint256 newLimit
);
```

### SelectorAllowlistUpdated

```solidity
event SelectorAllowlistUpdated(
    uint32 indexed entityId, address indexed account, bytes24 indexed targetAndSelector, bool allowed
);
```

## Errors
### AddressNotAllowed

```solidity
error AddressNotAllowed();
```

### ERC20NotAllowed

```solidity
error ERC20NotAllowed(address);
```

### ExceededTokenLimit

```solidity
error ExceededTokenLimit();
```

### InvalidCalldataLength

```solidity
error InvalidCalldataLength();
```

### NoSelectorSpecified

```solidity
error NoSelectorSpecified();
```

### SelectorNotAllowed

```solidity
error SelectorNotAllowed();
```

### SpendingRequestNotAllowed

```solidity
error SpendingRequestNotAllowed(bytes4);
```

## Structs
### AllowlistInput

```solidity
struct AllowlistInput {
    address target;
    bool hasSelectorAllowlist;
    bool hasERC20SpendLimit;
    uint256 erc20SpendLimit;
    bytes4[] selectors;
}
```

### AddressAllowlistEntry

```solidity
struct AddressAllowlistEntry {
    bool allowed;
    bool hasSelectorAllowlist;
    bool hasERC20SpendLimit;
}
```

