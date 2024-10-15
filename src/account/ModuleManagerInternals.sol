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
import {
    AccountStorage,
    ExecutionStorage,
    ValidationStorage,
    getAccountStorage,
    toSetValue
} from "./AccountStorage.sol";

/// @title Modular Manager Internal Methods
/// @author Alchemy
/// @notice This abstract contract hosts the internal installation and uninstallation methods of execution and
/// validation functions. Methods here update the account storage.
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

    function _setExecutionFunction(
        bytes4 selector,
        bool skipRuntimeValidation,
        bool allowGlobalValidation,
        address module
    ) internal {
        ExecutionStorage storage _executionStorage = getAccountStorage().executionStorage[selector];

        if (_executionStorage.module != address(0)) {
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

        _executionStorage.module = module;
        _executionStorage.skipRuntimeValidation = skipRuntimeValidation;
        _executionStorage.allowGlobalValidation = allowGlobalValidation;
    }

    function _removeExecutionFunction(bytes4 selector) internal {
        ExecutionStorage storage _executionStorage = getAccountStorage().executionStorage[selector];

        _executionStorage.module = address(0);
        _executionStorage.skipRuntimeValidation = false;
        _executionStorage.allowGlobalValidation = false;
    }

    function _removeValidationFunction(ModuleEntity validationFunction) internal {
        ValidationStorage storage _validationStorage = getAccountStorage().validationStorage[validationFunction];

        _validationStorage.isGlobal = false;
        _validationStorage.isSignatureValidation = false;
        _validationStorage.isUserOpValidation = false;
    }

    function _addExecHooks(LinkedListSet storage hooks, HookConfig hookConfig) internal {
        if (!hooks.tryAdd(toSetValue(hookConfig))) {
            revert ExecutionHookAlreadySet(hookConfig);
        }
    }

    function _removeExecHooks(LinkedListSet storage hooks, HookConfig hookConfig) internal {
        hooks.tryRemove(toSetValue(hookConfig));
    }

    /// @notice Update components according to the manifest.
    function _installExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata moduleInstallData
    ) internal {
        AccountStorage storage _storage = getAccountStorage();

        if (module == address(0)) {
            revert NullModule();
        }

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
            LinkedListSet storage executionHooks = _storage.executionStorage[mh.executionSelector].executionHooks;
            HookConfig hookConfig = HookConfigLib.packExecHook({
                _module: module,
                _entityId: mh.entityId,
                _hasPre: mh.isPreHook,
                _hasPost: mh.isPostHook
            });
            _addExecHooks(executionHooks, hookConfig);
        }

        length = manifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            _storage.supportedIfaces[manifest.interfaceIds[i]] += 1;
        }

        _onInstall(module, moduleInstallData, type(IModule).interfaceId);

        emit ExecutionInstalled(module, manifest);
    }

    /// @notice Remove components according to the manifest, in reverse order (by component type) of their
    /// installation.
    function _uninstallExecution(address module, ExecutionManifest calldata manifest, bytes calldata uninstallData)
        internal
    {
        AccountStorage storage _storage = getAccountStorage();

        uint256 length = manifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestExecutionHook memory mh = manifest.executionHooks[i];
            LinkedListSet storage executionHooks = _storage.executionStorage[mh.executionSelector].executionHooks;
            HookConfig hookConfig = HookConfigLib.packExecHook({
                _module: module,
                _entityId: mh.entityId,
                _hasPre: mh.isPreHook,
                _hasPost: mh.isPostHook
            });
            _removeExecHooks(executionHooks, hookConfig);
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

    /// @dev setup the module storage for the account, reverts are bubbled up into a custom
    /// ModuleInstallCallbackFailed
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

    /// @dev clear the module storage for the account, reverts are IGNORED. Status is included in emitted event.
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

    /// @dev install a validation function for the account. If the validation function is already installed,
    /// certain fields may be updated; more (not duplicated) hooks and selectors can be added.
    function _installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) internal {
        ValidationStorage storage _validationStorage =
            getAccountStorage().validationStorage[validationConfig.moduleEntity()];
        ModuleEntity moduleEntity = validationConfig.moduleEntity();

        uint256 length = hooks.length;
        for (uint256 i = 0; i < length; ++i) {
            HookConfig hookConfig = HookConfig.wrap(bytes25(hooks[i][:25]));
            bytes calldata hookData = hooks[i][25:];

            if (hookConfig.isValidationHook()) {
                // Increment the stored length of validation hooks, and revert if the limit is exceeded.

                // Safety:
                //     validationHookCount is uint8, so math operations here should never overflow
                unchecked {
                    if (uint256(_validationStorage.validationHookCount) + 1 > MAX_VALIDATION_ASSOC_HOOKS) {
                        revert ValidationAssocHookLimitExceeded();
                    }

                    ++_validationStorage.validationHookCount;
                }

                if (!_validationStorage.validationHooks.tryAdd(toSetValue(hookConfig))) {
                    revert PreValidationHookDuplicate();
                }

                _onInstall(hookConfig.module(), hookData, type(IValidationHookModule).interfaceId);
            } else {
                // Hook is an execution hook

                // Safety:
                //     validationHookCount is uint8, so math operations here should never overflow
                unchecked {
                    if (uint256(_validationStorage.executionHookCount) + 1 > MAX_VALIDATION_ASSOC_HOOKS) {
                        revert ValidationAssocHookLimitExceeded();
                    }

                    ++_validationStorage.executionHookCount;
                }

                _addExecHooks(_validationStorage.executionHooks, hookConfig);
                _onInstall(hookConfig.module(), hookData, type(IExecutionHookModule).interfaceId);
            }
        }

        length = selectors.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = selectors[i];
            if (!_validationStorage.selectors.tryAdd(toSetValue(selector))) {
                revert ValidationAlreadySet(selector, moduleEntity);
            }
        }

        _validationStorage.isGlobal = validationConfig.isGlobal();
        _validationStorage.isSignatureValidation = validationConfig.isSignatureValidation();
        _validationStorage.isUserOpValidation = validationConfig.isUserOpValidation();

        _onInstall(validationConfig.module(), installData, type(IValidationModule).interfaceId);
        emit ValidationInstalled(validationConfig.module(), validationConfig.entityId());
    }

    function _uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes[] calldata hookUninstallDatas
    ) internal {
        ValidationStorage storage _validationStorage = getAccountStorage().validationStorage[validationFunction];
        bool onUninstallSuccess = true;

        _removeValidationFunction(validationFunction);

        // Send `onUninstall` to hooks
        if (hookUninstallDatas.length > 0) {
            HookConfig[] memory execHooks = MemManagementLib.loadExecHooks(_validationStorage);
            HookConfig[] memory validationHooks = MemManagementLib.loadValidationHooks(_validationStorage);

            // If any uninstall data is provided, assert it is of the correct length.
            if (hookUninstallDatas.length != validationHooks.length + execHooks.length) {
                revert ArrayLengthMismatch();
            }

            // Hook uninstall data is provided in the order of pre validation hooks, then execution hooks.
            uint256 hookIndex = 0;
            uint256 length = validationHooks.length;
            for (uint256 i = 0; i < length; ++i) {
                bytes calldata hookData = hookUninstallDatas[hookIndex];
                (address hookModule,) = ModuleEntityLib.unpack(validationHooks[i].moduleEntity());
                onUninstallSuccess = onUninstallSuccess && _onUninstall(hookModule, hookData);
                hookIndex++;
            }

            length = execHooks.length;
            for (uint256 i = 0; i < length; ++i) {
                bytes calldata hookData = hookUninstallDatas[hookIndex];
                address hookModule = execHooks[i].module();
                onUninstallSuccess = onUninstallSuccess && _onUninstall(hookModule, hookData);
                hookIndex++;
            }
        }

        // Clear all stored hooks
        _validationStorage.validationHookCount = 0;
        _validationStorage.validationHooks.clear();

        _validationStorage.executionHookCount = 0;
        _validationStorage.executionHooks.clear();

        // Clear selectors
        _validationStorage.selectors.clear();

        (address module, uint32 entityId) = ModuleEntityLib.unpack(validationFunction);
        onUninstallSuccess = onUninstallSuccess && _onUninstall(module, uninstallData);

        emit ValidationUninstalled(module, entityId, onUninstallSuccess);
    }

    function _isNativeFunction(bytes4 selector) internal pure virtual returns (bool) {
        return KnownSelectorsLib.isNativeFunction(selector);
    }
}
