# PaymasterGuardModule
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/22a036bde57711d56f967db6e1ecc2ae54755e1a/src/modules/permissions/PaymasterGuardModule.sol)

**Inherits:**
[ModuleBase](/src/modules/ModuleBase.sol/abstract.ModuleBase.md), IValidationHookModule

**Author:**
Alchemy

This module supports permission checks where an validation is allowed only if a certain paymaster is
used.
- If this hook is installed, and no paymaster is setup, all requests will revert.
- None of the functions are installed on the account. Account states are to be retrieved from this global
singleton directly.
- Uninstallation will NOT disable all installed hooks for an account. It only uninstalls hooks for the
entity ID that is passed in. Account must remove access for each entity ID if want to disable all hooks.


## State Variables
### paymasters

```solidity
mapping(uint32 entityId => mapping(address account => address paymaster)) public paymasters;
```


## Functions
### onInstall

Initialize module data for the modular account.

*Called by the modular account during `installExecution`.*


```solidity
function onInstall(bytes calldata data) external override;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`data`|`bytes`|should be encoded with the entityId of the validation and the paymaster address that guards the validation|


### onUninstall

Clear module data for the modular account.

*Called by the modular account during `uninstallExecution`.*


```solidity
function onUninstall(bytes calldata data) external override;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`data`|`bytes`|should be encoded with the entityId of the validation|


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
function preRuntimeValidationHook(uint32, address, uint256, bytes calldata, bytes calldata)
    external
    view
    override;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint32`||
|`<none>`|`address`||
|`<none>`|`uint256`||
|`<none>`|`bytes`||
|`<none>`|`bytes`||


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
function supportsInterface(bytes4 interfaceId) public view virtual override(ModuleBase, IERC165) returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`interfaceId`|`bytes4`|The interface ID to check for support.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|True if the contract supports `interfaceId`.|


## Errors
### BadPaymasterSpecified

```solidity
error BadPaymasterSpecified();
```

### InvalidPaymaster

```solidity
error InvalidPaymaster();
```

