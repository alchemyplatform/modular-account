// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {MAX_VALIDATION_ASSOC_HOOKS} from "@erc6900/reference-implementation/helpers/Constants.sol";
import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {
    ExecutionManifest,
    ManifestExecutionHook
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {
    HookConfig,
    IModularAccount,
    ModuleEntity,
    ValidationConfig
} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

import {ExecutionLib} from "../libraries/ExecutionLib.sol";
import {KnownSelectorsLib} from "../libraries/KnownSelectorsLib.sol";
import {LinkedListSet, LinkedListSetLib} from "../libraries/LinkedListSetLib.sol";
import {MemManagementLib} from "../libraries/MemManagementLib.sol";
import {AccountStorage, ExecutionData, ValidationData, getAccountStorage, toSetValue} from "./AccountStorage.sol";

abstract contract ModuleManagerInternals is IModularAccount {
    using LinkedListSetLib for LinkedListSet;
    using ModuleEntityLib for ModuleEntity;
    using ValidationConfigLib for ValidationConfig;
    using HookConfigLib for HookConfig;

    error ArrayLengthMismatch();
    error Erc4337FunctionNotAllowed(bytes4 selector);
    error ExecutionFunctionAlreadySet(bytes4 selector);
    error IModuleFunctionNotAllowed(bytes4 selector);
    error InterfaceNotSupported(address module);
    error NativeFunctionNotAllowed(bytes4 selector);
    error NullModule();
    error ExecutionHookAlreadySet(HookConfig hookConfig);
    error ModuleInstallCallbackFailed(address module, bytes revertReason);
    error ModuleNotInstalled(address module);
    error PreValidationHookDuplicate();
    error ValidationAlreadySet(bytes4 selector, ModuleEntity validationFunction);
    error ValidationAssocHookLimitExceeded();

    // Storage update operations

    function _setExecutionFunction(
        bytes4 selector,
        bool skipRuntimeValidation,
        bool allowGlobalValidation,
        address module
    ) internal {
        ExecutionData storage _executionData = getAccountStorage().executionData[selector];

        if (_executionData.module != address(0)) {
            revert ExecutionFunctionAlreadySet(selector);
        }

        // Make sure incoming execution function does not collide with any native functions (data are stored on the
        // account implementation contract)
        if (_isNativeFunction(selector)) {
            revert NativeFunctionNotAllowed(selector);
        }

        // Make sure incoming execution function is not a function in IModule
        if (KnownSelectorsLib.isIModuleFunction(selector)) {
            revert IModuleFunctionNotAllowed(selector);
        }

        // Also make sure it doesn't collide with functions defined by ERC-4337
        // and called by the entry point. This prevents a malicious module from
        // sneaking in a function with the same selector as e.g.
        // `validatePaymasterUserOp` and turning the account into their own
        // personal paymaster.
        if (KnownSelectorsLib.isErc4337Function(selector)) {
            revert Erc4337FunctionNotAllowed(selector);
        }

        _executionData.module = module;
        _executionData.skipRuntimeValidation = skipRuntimeValidation;
        _executionData.allowGlobalValidation = allowGlobalValidation;
    }

    function _removeExecutionFunction(bytes4 selector) internal {
        ExecutionData storage _executionData = getAccountStorage().executionData[selector];

        _executionData.module = address(0);
        _executionData.skipRuntimeValidation = false;
        _executionData.allowGlobalValidation = false;
    }

    function _removeValidationFunction(ModuleEntity validationFunction) internal {
        ValidationData storage _validationData = getAccountStorage().validationData[validationFunction];

        _validationData.isGlobal = false;
        _validationData.isSignatureValidation = false;
        _validationData.isUserOpValidation = false;
    }

    function _addExecHooks(LinkedListSet storage hooks, HookConfig hookConfig) internal {
        if (!hooks.tryAdd(toSetValue(hookConfig))) {
            revert ExecutionHookAlreadySet(hookConfig);
        }
    }

    function _removeExecHooks(LinkedListSet storage hooks, HookConfig hookConfig) internal {
        // Todo: use predecessor
        hooks.tryRemove(toSetValue(hookConfig));
    }

    function _installExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata moduleInstallData
    ) internal {
        AccountStorage storage _storage = getAccountStorage();

        if (module == address(0)) {
            revert NullModule();
        }

        // Update components according to the manifest.
        uint256 length = manifest.executionFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = manifest.executionFunctions[i].executionSelector;
            bool skipRuntimeValidation = manifest.executionFunctions[i].skipRuntimeValidation;
            bool allowGlobalValidation = manifest.executionFunctions[i].allowGlobalValidation;
            _setExecutionFunction(selector, skipRuntimeValidation, allowGlobalValidation, module);
        }

        length = manifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestExecutionHook memory mh = manifest.executionHooks[i];
            ExecutionData storage executionData = _storage.executionData[mh.executionSelector];
            HookConfig hookConfig = HookConfigLib.packExecHook({
                _module: module,
                _entityId: mh.entityId,
                _hasPre: mh.isPreHook,
                _hasPost: mh.isPostHook
            });
            _addExecHooks(executionData.executionHooks, hookConfig);
        }

        length = manifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            _storage.supportedIfaces[manifest.interfaceIds[i]] += 1;
        }

        _onInstall(module, moduleInstallData, type(IModule).interfaceId);

        emit ExecutionInstalled(module, manifest);
    }

    function _uninstallExecution(address module, ExecutionManifest calldata manifest, bytes calldata uninstallData)
        internal
    {
        AccountStorage storage _storage = getAccountStorage();

        // Remove components according to the manifest, in reverse order (by component type) of their installation.

        uint256 length = manifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestExecutionHook memory mh = manifest.executionHooks[i];
            ExecutionData storage execData = _storage.executionData[mh.executionSelector];
            HookConfig hookConfig = HookConfigLib.packExecHook({
                _module: module,
                _entityId: mh.entityId,
                _hasPre: mh.isPreHook,
                _hasPost: mh.isPostHook
            });
            _removeExecHooks(execData.executionHooks, hookConfig);
        }

        length = manifest.executionFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = manifest.executionFunctions[i].executionSelector;
            _removeExecutionFunction(selector);
        }

        length = manifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            _storage.supportedIfaces[manifest.interfaceIds[i]] -= 1;
        }

        // Clear the module storage for the account.
        bool onUninstallSuccess = _onUninstall(module, uninstallData);

        emit ExecutionUninstalled(module, onUninstallSuccess, manifest);
    }

    function _onInstall(address module, bytes calldata data, bytes4 interfaceId) internal {
        if (data.length > 0) {
            if (!ERC165Checker.supportsERC165InterfaceUnchecked(module, interfaceId)) {
                revert InterfaceNotSupported(module);
            }
            // solhint-disable-next-line no-empty-blocks
            try IModule(module).onInstall(data) {}
            catch {
                bytes memory revertReason = ExecutionLib.collectReturnData();
                revert ModuleInstallCallbackFailed(module, revertReason);
            }
        }
    }

    function _onUninstall(address module, bytes calldata data) internal returns (bool onUninstallSuccess) {
        onUninstallSuccess = true;
        if (data.length > 0) {
            // Clear the module storage for the account.
            // solhint-disable-next-line no-empty-blocks
            try IModule(module).onUninstall(data) {}
            catch {
                onUninstallSuccess = false;
            }
        }
    }

    function _installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) internal {
        ValidationData storage _validationData =
            getAccountStorage().validationData[validationConfig.moduleEntity()];
        ModuleEntity moduleEntity = validationConfig.moduleEntity();

        for (uint256 i = 0; i < hooks.length; ++i) {
            HookConfig hookConfig = HookConfig.wrap(bytes25(hooks[i][:25]));
            bytes calldata hookData = hooks[i][25:];

            if (hookConfig.isValidationHook()) {
                // Increment the stored length of validation hooks, and revert if the limit is exceeded.

                unchecked {
                    if (uint256(_validationData.validationHookCount) + 1 > MAX_VALIDATION_ASSOC_HOOKS) {
                        revert ValidationAssocHookLimitExceeded();
                    }

                    ++_validationData.validationHookCount;
                }

                if (!_validationData.validationHooks.tryAdd(toSetValue(hookConfig))) {
                    revert PreValidationHookDuplicate();
                }

                _onInstall(hookConfig.module(), hookData, type(IValidationHookModule).interfaceId);

                continue;
            }
            // Hook is an execution hook

            unchecked {
                if (uint256(_validationData.executionHookCount) + 1 > MAX_VALIDATION_ASSOC_HOOKS) {
                    revert ValidationAssocHookLimitExceeded();
                }

                ++_validationData.executionHookCount;
            }

            _addExecHooks(_validationData.executionHooks, hookConfig);

            _onInstall(hookConfig.module(), hookData, type(IExecutionHookModule).interfaceId);
        }

        for (uint256 i = 0; i < selectors.length; ++i) {
            bytes4 selector = selectors[i];
            if (!_validationData.selectors.tryAdd(toSetValue(selector))) {
                revert ValidationAlreadySet(selector, moduleEntity);
            }
        }

        _validationData.isGlobal = validationConfig.isGlobal();
        _validationData.isSignatureValidation = validationConfig.isSignatureValidation();
        _validationData.isUserOpValidation = validationConfig.isUserOpValidation();

        _onInstall(validationConfig.module(), installData, type(IValidationModule).interfaceId);
        emit ValidationInstalled(validationConfig.module(), validationConfig.entityId());
    }

    function _uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes[] calldata hookUninstallDatas
    ) internal {
        ValidationData storage _validationData = getAccountStorage().validationData[validationFunction];
        bool onUninstallSuccess = true;

        _removeValidationFunction(validationFunction);

        // Send `onUninstall` to hooks
        if (hookUninstallDatas.length > 0) {
            HookConfig[] memory execHooks = MemManagementLib.loadExecHooks(_validationData);
            HookConfig[] memory validationHooks = MemManagementLib.loadValidationHooks(_validationData);

            // If any uninstall data is provided, assert it is of the correct length.
            if (hookUninstallDatas.length != validationHooks.length + execHooks.length) {
                revert ArrayLengthMismatch();
            }

            // Hook uninstall data is provided in the order of pre validation hooks, then execution hooks.
            uint256 hookIndex = 0;
            for (uint256 i = 0; i < validationHooks.length; ++i) {
                bytes calldata hookData = hookUninstallDatas[hookIndex];
                (address hookModule,) = ModuleEntityLib.unpack(validationHooks[i].moduleEntity());
                onUninstallSuccess = onUninstallSuccess && _onUninstall(hookModule, hookData);
                hookIndex++;
            }

            for (uint256 i = 0; i < execHooks.length; ++i) {
                bytes calldata hookData = hookUninstallDatas[hookIndex];
                address hookModule = execHooks[i].module();
                onUninstallSuccess = onUninstallSuccess && _onUninstall(hookModule, hookData);
                hookIndex++;
            }
        }

        // Clear all stored hooks
        _validationData.validationHookCount = 0;
        _validationData.validationHooks.clear();

        _validationData.executionHookCount = 0;
        _validationData.executionHooks.clear();

        // Clear selectors
        _validationData.selectors.clear();

        (address module, uint32 entityId) = ModuleEntityLib.unpack(validationFunction);
        onUninstallSuccess = onUninstallSuccess && _onUninstall(module, uninstallData);

        emit ValidationUninstalled(module, entityId, onUninstallSuccess);
    }

    function _isNativeFunction(bytes4 selector) internal pure virtual returns (bool) {
        return KnownSelectorsLib.isNativeFunction(selector);
    }
}
