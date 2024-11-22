// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {
    HookConfig,
    IModularAccount,
    ModuleEntity
} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {
    ExecutionDataView,
    IModularAccountView,
    ValidationDataView
} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";
import {IAccountExecute} from "@eth-infinitism/account-abstraction/interfaces/IAccountExecute.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {NativeFunctionDelegate} from "../helpers/NativeFunctionDelegate.sol";
import {IModularAccountBase} from "../interfaces/IModularAccountBase.sol";
import {MemManagementLib} from "../libraries/MemManagementLib.sol";
import {ValidationLocatorLib} from "../libraries/ValidationLocatorLib.sol";
import {ExecutionStorage, ValidationStorage, getAccountStorage} from "./AccountStorage.sol";

/// @title Modular Account View
/// @author Alchemy
/// @notice This abstract contract implements the two view functions to get validation and execution data for an
/// account.
abstract contract ModularAccountView is IModularAccountView {
    NativeFunctionDelegate internal immutable _NATIVE_FUNCTION_DELEGATE;

    constructor() {
        _NATIVE_FUNCTION_DELEGATE = new NativeFunctionDelegate();
    }

    /// @inheritdoc IModularAccountView
    function getExecutionData(bytes4 selector) external view override returns (ExecutionDataView memory data) {
        ExecutionStorage storage executionStorage = getAccountStorage().executionStorage[selector];

        if (_isNativeFunction(uint32(selector))) {
            bool isGlobalValidationAllowed = _isGlobalValidationAllowedNativeFunction(uint32(selector));
            data.module = address(this);
            data.skipRuntimeValidation = !isGlobalValidationAllowed;
            data.allowGlobalValidation = isGlobalValidationAllowed;
            if (!_isWrappedNativeFunction(uint32(selector))) {
                // The native function does not run execution hooks associated with its selector, so
                // we can return early.
                return data;
            }
        } else {
            data.module = executionStorage.module;
            data.skipRuntimeValidation = executionStorage.skipRuntimeValidation;
            data.allowGlobalValidation = executionStorage.allowGlobalValidation;
        }

        HookConfig[] memory hooks = MemManagementLib.loadExecHooks(executionStorage);
        MemManagementLib.reverseArr(hooks);
        data.executionHooks = hooks;
    }

    /// @inheritdoc IModularAccountView
    function getValidationData(ModuleEntity validationFunction)
        external
        view
        override
        returns (ValidationDataView memory data)
    {
        ValidationStorage storage validationStorage =
            getAccountStorage().validationStorage[ValidationLocatorLib.moduleEntityToLookupKey(validationFunction)];
        data.isGlobal = validationStorage.isGlobal;
        data.isSignatureValidation = validationStorage.isSignatureValidation;
        data.isUserOpValidation = validationStorage.isUserOpValidation;
        data.validationHooks = MemManagementLib.loadValidationHooks(validationStorage);
        MemManagementLib.reverseArr(data.validationHooks);

        HookConfig[] memory hooks = MemManagementLib.loadExecHooks(validationStorage);
        MemManagementLib.reverseArr(hooks);
        data.executionHooks = hooks;

        bytes4[] memory selectors = MemManagementLib.loadSelectors(validationStorage);
        MemManagementLib.reverseArr(selectors);
        data.selectors = selectors;
    }

    function _isNativeFunction(uint32 selector) internal view virtual returns (bool) {
        return _NATIVE_FUNCTION_DELEGATE.isNativeFunction(selector);
    }

    /// @dev Check whether a function is a native function that has the `wrapNativeFunction` modifier applied,
    /// which means it runs execution hooks associated with its selector.
    function _isWrappedNativeFunction(uint32 selector) internal pure virtual returns (bool) {
        return (
            selector == uint32(IModularAccount.execute.selector)
                || selector == uint32(IModularAccount.executeBatch.selector)
                || selector == uint32(IModularAccount.installExecution.selector)
                || selector == uint32(IModularAccount.installValidation.selector)
                || selector == uint32(IModularAccount.uninstallExecution.selector)
                || selector == uint32(IModularAccount.uninstallValidation.selector)
                || selector == uint32(IModularAccountBase.performCreate.selector)
                || selector == uint32(UUPSUpgradeable.upgradeToAndCall.selector)
        );
    }

    /// @dev Check whether a function is a native function that allows global validation.
    function _isGlobalValidationAllowedNativeFunction(uint32 selector) internal pure virtual returns (bool) {
        return (
            _isWrappedNativeFunction(selector) || selector == uint32(IAccountExecute.executeUserOp.selector)
                || selector == uint32(IModularAccount.executeWithRuntimeValidation.selector)
        );
    }
}
