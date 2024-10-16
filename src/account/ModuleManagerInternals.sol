// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {MAX_VALIDATION_ASSOC_HOOKS} from "@erc6900/reference-implementation/helpers/Constants.sol";
import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {
    HookConfig,
    IModularAccount,
    ModuleEntity,
    ValidationConfig
} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";

import {ExecutionLib} from "../libraries/ExecutionLib.sol";
import {KnownSelectorsLib} from "../libraries/KnownSelectorsLib.sol";
import {LinkedListSet, LinkedListSetLib} from "../libraries/LinkedListSetLib.sol";
import {MemManagementLib} from "../libraries/MemManagementLib.sol";
import {ModuleInstallCommons} from "../libraries/ModuleInstallCommons.sol";
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
    error NullModule();
    error ExecutionHookAlreadySet(HookConfig hookConfig);
    error ModuleInstallCallbackFailed(address module, bytes revertReason);
    error ModuleNotInstalled(address module);
    error PreValidationHookDuplicate();
    error ValidationAlreadySet(bytes4 selector, ModuleEntity validationFunction);
    error ValidationAssocHookLimitExceeded();

    function _removeValidationFunction(ModuleEntity validationFunction) internal {
        ValidationStorage storage _validationStorage = getAccountStorage().validationStorage[validationFunction];

        _validationStorage.isGlobal = false;
        _validationStorage.isSignatureValidation = false;
        _validationStorage.isUserOpValidation = false;
    }

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

                ModuleInstallCommons.onInstall(
                    hookConfig.module(), hookData, type(IValidationHookModule).interfaceId
                );
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

                ModuleInstallCommons.addExecHooks(_validationStorage.executionHooks, hookConfig);
                ModuleInstallCommons.onInstall(
                    hookConfig.module(), hookData, type(IExecutionHookModule).interfaceId
                );
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

        ModuleInstallCommons.onInstall(validationConfig.module(), installData, type(IValidationModule).interfaceId);
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
                onUninstallSuccess = onUninstallSuccess && ModuleInstallCommons.onUninstall(hookModule, hookData);
                hookIndex++;
            }

            length = execHooks.length;
            for (uint256 i = 0; i < length; ++i) {
                bytes calldata hookData = hookUninstallDatas[hookIndex];
                address hookModule = execHooks[i].module();
                onUninstallSuccess = onUninstallSuccess && ModuleInstallCommons.onUninstall(hookModule, hookData);
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
        onUninstallSuccess = onUninstallSuccess && ModuleInstallCommons.onUninstall(module, uninstallData);

        emit ValidationUninstalled(module, entityId, onUninstallSuccess);
    }
}
