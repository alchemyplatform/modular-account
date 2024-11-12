// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {HookConfig, ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {
    ExecutionDataView,
    IModularAccountView,
    ValidationDataView
} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";

import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModularAccountView} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";
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
        // return ModularAccountViewLib.getExecutionData(selector, _isNativeFunction(selector));
        ExecutionStorage storage executionStorage = getAccountStorage().executionStorage[selector];

        if (_isGlobalValidationAllowedNativeFunction(selector)) {
            data.module = address(this);
            data.allowGlobalValidation = true;
        } else if (_isNativeFunction(uint32(selector))) {
            // native view functions
            data.module = address(this);
            data.skipRuntimeValidation = true;
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
            getAccountStorage().validationStorage[ValidationLocatorLib.moduleEntityToLookup(validationFunction)];
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

    function _isGlobalValidationAllowedNativeFunction(bytes4 selector) internal view virtual returns (bool) {
        if (
            selector == IModularAccount.execute.selector || selector == IModularAccount.executeBatch.selector
                || selector == IAccountExecute.executeUserOp.selector
                || selector == IModularAccount.executeWithRuntimeValidation.selector
                || selector == IModularAccount.installExecution.selector
                || selector == IModularAccount.uninstallExecution.selector
                || selector == IModularAccount.installValidation.selector
                || selector == IModularAccount.uninstallValidation.selector
                || selector == UUPSUpgradeable.upgradeToAndCall.selector
                || selector == IModularAccountBase.invalidateDeferredValidationInstallNonce.selector
                || selector == IModularAccountBase.performCreate.selector
        ) {
            return true;
        }
        return false;
    }
}
