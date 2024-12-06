# ModularAccountBase
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/2824291b17c11e6f41963e8c13505f2476b92ee6/src/account/ModularAccountBase.sol)

**Inherits:**
IModularAccount, [IModularAccountBase](/src/interfaces/IModularAccountBase.sol/interface.IModularAccountBase.md), [ModularAccountView](/src/account/ModularAccountView.sol/abstract.ModularAccountView.md), [AccountStorageInitializable](/src/account/AccountStorageInitializable.sol/abstract.AccountStorageInitializable.md), [AccountBase](/src/account/AccountBase.sol/abstract.AccountBase.md), IERC1271, IERC165, IAccountExecute, [ModuleManagerInternals](/src/account/ModuleManagerInternals.sol/abstract.ModuleManagerInternals.md), UUPSUpgradeable, [TokenReceiver](/src/account/TokenReceiver.sol/abstract.TokenReceiver.md)

**Author:**
Alchemy

This abstract contract is a modular account that is compliant with ERC-6900 standard. It supports
deferred actions during validation.


## State Variables
### _DOMAIN_SEPARATOR_TYPEHASH

```solidity
bytes32 internal constant _DOMAIN_SEPARATOR_TYPEHASH =
    0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;
```


### _DEFERRED_ACTION_TYPEHASH

```solidity
bytes32 internal constant _DEFERRED_ACTION_TYPEHASH =
    0x9b23e06584efc6b65fc854cee55011d89f86485487b6db36aed7d23884711ea3;
```


### _INTERFACE_ID_INVALID

```solidity
bytes4 internal constant _INTERFACE_ID_INVALID = 0xffffffff;
```


### _1271_MAGIC_VALUE

```solidity
bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
```


### _1271_INVALID

```solidity
bytes4 internal constant _1271_INVALID = 0xffffffff;
```


### _EXECUTION_INSTALL_DELEGATE

```solidity
address internal immutable _EXECUTION_INSTALL_DELEGATE;
```


## Functions
### wrapNativeFunction


```solidity
modifier wrapNativeFunction();
```

### constructor


```solidity
constructor(IEntryPoint entryPoint, ExecutionInstallDelegate executionInstallDelegate) AccountBase(entryPoint);
```

### receive


```solidity
receive() external payable;
```

### fallback

Fallback function

*Routes calls to execution functions based on the incoming msg.sig. If there's no module associated
with this function selector, revert.*


```solidity
fallback(bytes calldata) external payable returns (bytes memory);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bytes`|The raw returned data from the invoked execution function.|


### performCreate

Create a contract.


```solidity
function performCreate(uint256 value, bytes calldata initCode, bool isCreate2, bytes32 salt)
    external
    payable
    virtual
    override
    wrapNativeFunction
    returns (address createdAddr);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`value`|`uint256`|The value to send to the new contract constructor|
|`initCode`|`bytes`|The initCode to deploy.|
|`isCreate2`|`bool`|The bool to indicate which method to use to deploy.|
|`salt`|`bytes32`|The salt for deployment.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`createdAddr`|`address`|The created contract address.|


### executeUserOp

Execution function that allows UO context to be passed to execution hooks

*This function is only callable by the EntryPoint*


```solidity
function executeUserOp(PackedUserOperation calldata userOp, bytes32) external override;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`userOp`|`PackedUserOperation`|             - The operation that was just validated.|
|`<none>`|`bytes32`||


### execute

May be validated by a global validation.


```solidity
function execute(address target, uint256 value, bytes calldata data)
    external
    payable
    override
    wrapNativeFunction
    returns (bytes memory result);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`target`|`address`|The target address for the account to call.|
|`value`|`uint256`|The value to send with the call.|
|`data`|`bytes`|The calldata for the call.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`result`|`bytes`|The return data from the call.|


### executeBatch

May be validated by a global validation function.

*If the target is a module, the call SHOULD revert. If any of the calls revert, the entire batch MUST
revert.*


```solidity
function executeBatch(Call[] calldata calls)
    external
    payable
    override
    wrapNativeFunction
    returns (bytes[] memory results);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`calls`|`Call[]`|The array of calls.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`results`|`bytes[]`|An array containing the return data from the calls.|


### executeWithRuntimeValidation

Execute a call using the specified runtime validation.


```solidity
function executeWithRuntimeValidation(bytes calldata data, bytes calldata authorization)
    external
    payable
    returns (bytes memory);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`data`|`bytes`|The calldata to send to the account.|
|`authorization`|`bytes`|The authorization data to use for the call. The first 24 bytes is a ModuleEntity which specifies which runtime validation to use, and the rest is sent as a parameter to runtime validation.|


### installExecution

May be validated by a global validation.


```solidity
function installExecution(address module, ExecutionManifest calldata manifest, bytes calldata moduleInstallData)
    external
    override
    wrapNativeFunction;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`module`|`address`|The module to install.|
|`manifest`|`ExecutionManifest`|the manifest describing functions to install.|
|`moduleInstallData`|`bytes`||


### uninstallExecution

May be validated by a global validation.


```solidity
function uninstallExecution(
    address module,
    ExecutionManifest calldata manifest,
    bytes calldata moduleUninstallData
) external override wrapNativeFunction;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`module`|`address`|The module to uninstall.|
|`manifest`|`ExecutionManifest`|the manifest describing functions to uninstall.|
|`moduleUninstallData`|`bytes`||


### installValidation

May be validated by a global validation.

*This function can be used to update (to a certain degree) previously installed validation functions.
- preValidationHook, executionHooks, and selectors can be added later. Though they won't be deleted.
- isGlobal and isSignatureValidation can also be updated later.*


```solidity
function installValidation(
    ValidationConfig validationConfig,
    bytes4[] calldata selectors,
    bytes calldata installData,
    bytes[] calldata hooks
) external virtual wrapNativeFunction;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`validationConfig`|`ValidationConfig`|The validation function to install, along with configuration flags.|
|`selectors`|`bytes4[]`|The selectors to install the validation function for.|
|`installData`|`bytes`|Optional data to be used by the account to handle the initial validation setup. Data encoding is implementation-specific.|
|`hooks`|`bytes[]`|Optional hooks to install and associate with the validation function. Data encoding is implementation-specific.|


### uninstallValidation

May be validated by a global validation.


```solidity
function uninstallValidation(
    ModuleEntity validationFunction,
    bytes calldata uninstallData,
    bytes[] calldata hookUninstallData
) external wrapNativeFunction;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`validationFunction`|`ModuleEntity`|The validation function to uninstall.|
|`uninstallData`|`bytes`|Optional data to be used by the account to handle the validation uninstallation. Data encoding is implementation-specific.|
|`hookUninstallData`|`bytes[]`|Optional data to be used by the account to handle hook uninstallation. Data encoding is implementation-specific.|


### isValidSignature

*Should return whether the signature provided is valid for the provided data*


```solidity
function isValidSignature(bytes32 hash, bytes calldata signature) external view override returns (bytes4);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`hash`|`bytes32`|     Hash of the data to be signed|
|`signature`|`bytes`|Signature byte array associated with _data|


### supportsInterface

ERC-165 introspection

*returns true for `IERC165.interfaceId` and false for `0xFFFFFFFF`*


```solidity
function supportsInterface(bytes4 interfaceId) external view override returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`interfaceId`|`bytes4`|interface id to check against|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|bool support for specific interface|


### accountId

Return a unique identifier for the account implementation.

*This function MUST return a string in the format "vendor.account.semver". The vendor and account
names MUST NOT contain a period character.*


```solidity
function accountId() external pure virtual returns (string memory);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`string`|The account ID.|


### upgradeToAndCall

May be validated by a global validation.

*Upgrades the proxy's implementation to `newImplementation`.
Emits a {Upgraded} event.
Note: Passing in empty `data` skips the delegatecall to `newImplementation`.*


```solidity
function upgradeToAndCall(address newImplementation, bytes calldata data)
    public
    payable
    virtual
    override
    onlyProxy
    wrapNativeFunction;
```

### _validateUserOp


```solidity
function _validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
    internal
    override
    returns (uint256 validationData);
```

### _handleDeferredAction

The calldata layout is unique for deferred validation installation.
Byte indices are [inclusive, exclusive] and relative to the start of the signature after the locator is
decoded and removed.
[0:4] : uint32, encodedDatalength.
[4:(4 + encodedDatalength)] : bytes, abi-encoded deferred action data.
[(4 + encodedDataLength):(8 + encodedDataLength)] : uint32, deferredActionSigLength.
[(8 + encodedDataLength):(8 + deferredActionSigLength + encodedDataLength)] : bytes,
deferred action sig. This is the signature passed to the outer validation decoded earlier.
[(8 + deferredActionSigLength + encodedDataLength):] : bytes, userOpSignature. This is the
signature passed to the inner validation.


```solidity
function _handleDeferredAction(uint256 userOpNonce, bytes calldata encodedData, bytes calldata sig)
    internal
    returns (uint48);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint48`|The deadline of the deferred action|


### _doUserOpValidation


```solidity
function _doUserOpValidation(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash,
    ValidationLookupKey validationLookupKey,
    bytes calldata signature
) internal returns (uint256);
```

### _doRuntimeValidation


```solidity
function _doRuntimeValidation(
    ValidationLookupKey validationLookupKey,
    bytes calldata callData,
    bytes calldata authorizationData
) internal returns (RTCallBuffer);
```

### _authorizeUpgrade


```solidity
function _authorizeUpgrade(address newImplementation) internal override;
```

### _checkPermittedCallerAndAssociatedHooks

Order of operations:
1. Check if the sender is the entry point, the account itself, or the selector called is public.
- Yes: Return an empty array, there are no post executionHooks.
- No: Continue
2. Check if the called selector (msg.sig) is included in the set of selectors the msg.sender can
directly call.
- Yes: Continue
- No: Revert, the caller is not allowed to call this selector
3. If there are runtime validation hooks associated with this caller-sig combination, run them.
4. Run the pre executionHooks associated with this caller-sig combination, and return the
post executionHooks to run later.


```solidity
function _checkPermittedCallerAndAssociatedHooks() internal returns (DensePostHookData);
```

### _execUserOpValidation


```solidity
function _execUserOpValidation(
    ValidationLookupKey validationLookupKey,
    bytes32 hash,
    bytes calldata signatureSegment,
    UOCallBuffer callBuffer
) internal virtual returns (uint256);
```

### _execRuntimeValidation


```solidity
function _execRuntimeValidation(
    ValidationLookupKey validationLookupKey,
    RTCallBuffer callBuffer,
    bytes calldata authorization
) internal virtual;
```

### _computeDeferredActionHash


```solidity
function _computeDeferredActionHash(uint256 userOpNonce, uint48 deadline, bytes calldata selfCall)
    internal
    view
    returns (bytes32);
```

### _validateDeferredActionSignature


```solidity
function _validateDeferredActionSignature(
    bytes32 defActionTypedDataHash,
    bytes calldata signature,
    ValidationLookupKey deferredSigValidationLookupKey
) internal view;
```

### _isValidSignature


```solidity
function _isValidSignature(ValidationLookupKey validationLookupKey, bytes32 hash, bytes calldata signature)
    internal
    view
    returns (bytes4);
```

### _exec1271Validation


```solidity
function _exec1271Validation(
    SigCallBuffer buffer,
    bytes32 hash,
    ValidationLookupKey validationLookupKey,
    bytes calldata signatureSegment
) internal view virtual returns (bytes4);
```

### _isValidationGlobal


```solidity
function _isValidationGlobal(ValidationLookupKey validationFunction) internal view virtual returns (bool);
```

### _checkIfValidationAppliesCallData


```solidity
function _checkIfValidationAppliesCallData(
    bytes calldata callData,
    ValidationLookupKey validationFunction,
    ValidationCheckingType checkingType
) internal view;
```

### _checkExecuteBatchValidationApplicability

Checks if the validation function is allowed to perform this call to `executeBatch`.


```solidity
function _checkExecuteBatchValidationApplicability(
    bytes calldata callData,
    ValidationLookupKey validationFunction,
    ValidationCheckingType checkingType
) internal view;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`callData`|`bytes`|The calldata to check, excluding the `executeBatch` selector.|
|`validationFunction`|`ValidationLookupKey`|The validation function to check against.|
|`checkingType`|`ValidationCheckingType`|The type of validation checking to perform.|


### _checkIfValidationAppliesSelector


```solidity
function _checkIfValidationAppliesSelector(
    bytes4 selector,
    ValidationLookupKey validationFunction,
    ValidationCheckingType checkingType
) internal view;
```

### _globalValidationApplies


```solidity
function _globalValidationApplies(bytes4 selector, ValidationLookupKey validationFunction)
    internal
    view
    returns (bool);
```

### _globalValidationAllowed


```solidity
function _globalValidationAllowed(bytes4 selector) internal view returns (bool);
```

### _selectorValidationApplies


```solidity
function _selectorValidationApplies(bytes4 selector, ValidationLookupKey validationFunction)
    internal
    view
    returns (bool);
```

### _domainSeparator


```solidity
function _domainSeparator() internal view returns (bytes32);
```

### _validationIsNative


```solidity
function _validationIsNative(ValidationLookupKey) internal pure virtual returns (bool);
```

## Errors
### CreateFailed

```solidity
error CreateFailed();
```

### DeferredActionSignatureInvalid

```solidity
error DeferredActionSignatureInvalid();
```

### RequireUserOperationContext

```solidity
error RequireUserOperationContext();
```

### SelfCallRecursionDepthExceeded

```solidity
error SelfCallRecursionDepthExceeded();
```

### SignatureValidationInvalid

```solidity
error SignatureValidationInvalid(ModuleEntity validationFunction);
```

### UserOpValidationInvalid

```solidity
error UserOpValidationInvalid(ModuleEntity validationFunction);
```

### UnexpectedAggregator

```solidity
error UnexpectedAggregator(ModuleEntity validationFunction, address aggregator);
```

### UnrecognizedFunction

```solidity
error UnrecognizedFunction(bytes4 selector);
```

### ValidationFunctionMissing

```solidity
error ValidationFunctionMissing(bytes4 selector);
```

### DeferredValidationHasValidationHooks

```solidity
error DeferredValidationHasValidationHooks();
```

## Enums
### ValidationCheckingType

```solidity
enum ValidationCheckingType {
    GLOBAL,
    SELECTOR,
    EITHER
}
```

