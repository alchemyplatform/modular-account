# AccountFactory
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/2824291b17c11e6f41963e8c13505f2476b92ee6/src/factory/AccountFactory.sol)

**Inherits:**
Ownable2Step

**Author:**
Alchemy

Factory contract to deploy modular accounts. Allows creation of both modular and semi-modular accounts
(the bytecode variant).


## State Variables
### ACCOUNT_IMPL

```solidity
ModularAccount public immutable ACCOUNT_IMPL;
```


### SEMI_MODULAR_ACCOUNT_IMPL

```solidity
SemiModularAccountBytecode public immutable SEMI_MODULAR_ACCOUNT_IMPL;
```


### ENTRY_POINT

```solidity
IEntryPoint public immutable ENTRY_POINT;
```


### SINGLE_SIGNER_VALIDATION_MODULE

```solidity
address public immutable SINGLE_SIGNER_VALIDATION_MODULE;
```


### WEBAUTHN_VALIDATION_MODULE

```solidity
address public immutable WEBAUTHN_VALIDATION_MODULE;
```


## Functions
### constructor


```solidity
constructor(
    IEntryPoint _entryPoint,
    ModularAccount _accountImpl,
    SemiModularAccountBytecode _semiModularImpl,
    address _singleSignerValidationModule,
    address _webAuthnValidationModule,
    address owner
) Ownable(owner);
```

### createAccount

Create an account with the single singer validation module installed, and return its address.

*Returns the address even if the account is already deployed.
Note that during user operation execution, this method is called only if the account is not deployed.
This method returns an existing account address so that entryPoint.getSenderAddress() would work even after
account creation.*


```solidity
function createAccount(address owner, uint256 salt, uint32 entityId) external returns (ModularAccount);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`owner`|`address`|The owner of the account.|
|`salt`|`uint256`|The salt to use for the account creation.|
|`entityId`|`uint32`|The entity ID to use for the account creation.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`ModularAccount`|The address of the created account.|


### createSemiModularAccount

Create a semi-modular account and return its address.

*This only ever deploys semi-modular accounts with added bytecode since this is much less
expensive than the storage-only variant, which should only be used for upgrades.*


```solidity
function createSemiModularAccount(address owner, uint256 salt) external returns (SemiModularAccountBytecode);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`owner`|`address`|The owner of the account.|
|`salt`|`uint256`|The salt to use for the account creation.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`SemiModularAccountBytecode`|The address of the created account.|


### createWebAuthnAccount

Create an account with the WebAuthn module installed, and return its address.

*Returns the address even if the account is already deployed.
Note that during user operation execution, this method is called only if the account is not deployed.
This method returns an existing account address so that entryPoint.getSenderAddress() would work even after
account creation.*


```solidity
function createWebAuthnAccount(uint256 ownerX, uint256 ownerY, uint256 salt, uint32 entityId)
    external
    returns (ModularAccount);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`ownerX`|`uint256`|The x coordinate of the owner's public key.|
|`ownerY`|`uint256`|The y coordinate of the owner's public key.|
|`salt`|`uint256`|The salt to use for the account creation.|
|`entityId`|`uint32`|The entity ID to use for the account creation.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`ModularAccount`|The address of the created account.|


### addStake

Add stake to the entry point contract.


```solidity
function addStake(uint32 unstakeDelay) external payable onlyOwner;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`unstakeDelay`|`uint32`|The delay in seconds before the stake can be withdrawn.|


### unlockStake

Unlock the stake in the entry point contract.


```solidity
function unlockStake() external onlyOwner;
```

### withdrawStake

Withdraw the stake from the entry point contract.


```solidity
function withdrawStake(address payable withdrawAddress) external onlyOwner;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`withdrawAddress`|`address payable`|The address to withdraw the stake to.|


### withdraw

Withdraw funds from this contract.

*Can be used to withdraw native currency or ERC-20 tokens.*


```solidity
function withdraw(address payable to, address token, uint256 amount) external onlyOwner;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`to`|`address payable`|The address to withdraw the funds to.|
|`token`|`address`|The address of the token to withdraw, or the zero address for native currency.|
|`amount`|`uint256`|The amount to withdraw.|


### getAddress

Calculate the counterfactual address of this account as it would be returned by createAccount.


```solidity
function getAddress(address owner, uint256 salt, uint32 entityId) external view returns (address);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`owner`|`address`|The owner of the account.|
|`salt`|`uint256`|The salt to use for the account creation.|
|`entityId`|`uint32`|The entity ID to use for the account creation.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`address`|The address of the account.|


### getAddressSemiModular

Calculate the counterfactual address of a semi-modular account as it would be returned by
createSemiModularAccount.


```solidity
function getAddressSemiModular(address owner, uint256 salt) external view returns (address);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`owner`|`address`|The owner of the account.|
|`salt`|`uint256`|The salt to use for the account creation.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`address`|The address of the account.|


### getAddressWebAuthn

Calculate the counterfactual address of a webauthn account as it would be returned by
createWebAuthnAccount.


```solidity
function getAddressWebAuthn(uint256 ownerX, uint256 ownerY, uint256 salt, uint32 entityId)
    external
    view
    returns (address);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`ownerX`|`uint256`|The x coordinate of the owner's public key.|
|`ownerY`|`uint256`|The y coordinate of the owner's public key.|
|`salt`|`uint256`|The salt to use for the account creation.|
|`entityId`|`uint32`|The entity ID to use for the account creation.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`address`|The address of the account.|


### renounceOwnership

Disable renouncing ownership.


```solidity
function renounceOwnership() public view override onlyOwner;
```

### getSalt

Get the full salt used for account creation.

*To get the full salt used in createSemiModularAccount, use type(uint32).max for entityId.*


```solidity
function getSalt(address owner, uint256 salt, uint32 entityId) public pure returns (bytes32);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`owner`|`address`|The owner of the account.|
|`salt`|`uint256`|The salt to use for the account creation.|
|`entityId`|`uint32`|The entity ID to use for the account creation.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bytes32`|The full salt.|


### getSaltWebAuthn

Get the full salt used for account creation using WebAuthn.


```solidity
function getSaltWebAuthn(uint256 ownerX, uint256 ownerY, uint256 salt, uint32 entityId)
    public
    pure
    returns (bytes32);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`ownerX`|`uint256`|The x coordinate of the owner's public key.|
|`ownerY`|`uint256`|The y coordinate of the owner's public key.|
|`salt`|`uint256`|The salt to use for the account creation.|
|`entityId`|`uint32`|The entity ID to use for the account creation.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bytes32`|The full salt.|


### _getAddressSemiModular


```solidity
function _getAddressSemiModular(bytes memory immutables, bytes32 salt) internal view returns (address);
```

### _getImmutableArgs


```solidity
function _getImmutableArgs(address owner) private pure returns (bytes memory);
```

## Events
### ModularAccountDeployed

```solidity
event ModularAccountDeployed(address indexed account, address indexed owner, uint256 salt);
```

### SemiModularAccountDeployed

```solidity
event SemiModularAccountDeployed(address indexed account, address indexed owner, uint256 salt);
```

### WebAuthnModularAccountDeployed

```solidity
event WebAuthnModularAccountDeployed(
    address indexed account, uint256 indexed ownerX, uint256 indexed ownerY, uint256 salt
);
```

## Errors
### InvalidAction

```solidity
error InvalidAction();
```

### TransferFailed

```solidity
error TransferFailed();
```

