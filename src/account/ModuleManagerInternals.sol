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

import {LinkedListSet, LinkedListSetLib} from "../libraries/LinkedListSetLib.sol";
import {MemManagementLib} from "../libraries/MemManagementLib.sol";
import {ModuleInstallCommonsLib} from "../libraries/ModuleInstallCommonsLib.sol";
import {ValidationStorage, getAccountStorage, toSetValue} from "./AccountStorage.sol";

/// @title Module Manager Internals
/// @author Alchemy
/// @notice This abstract contract hosts the internal installation and uninstallation methods of execution and
/// validation functions. Methods here update the account storage.
abstract contract ModuleManagerInternals is IModularAccount {
    using LinkedListSetLib for LinkedListSet;
    using ModuleEntityLib for ModuleEntity;
    using ValidationConfigLib for ValidationConfig;
    using HookConfigLib for HookConfig;

    error ArrayLengthMismatch();
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
        ModuleEntity moduleEntity = validationConfig.moduleEntity();

        ValidationStorage storage _validationStorage = getAccountStorage().validationStorage[moduleEntity];

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

                ModuleInstallCommonsLib.onInstall(
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

                ModuleInstallCommonsLib.addExecHooks(_validationStorage.executionHooks, hookConfig);
                ModuleInstallCommonsLib.onInstall(
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

        ModuleInstallCommonsLib.onInstall(
            validationConfig.module(), installData, type(IValidationModule).interfaceId
        );
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
                onUninstallSuccess =
                    onUninstallSuccess && ModuleInstallCommonsLib.onUninstall(hookModule, hookData);
                hookIndex++;
            }

            length = execHooks.length;
            for (uint256 i = 0; i < length; ++i) {
                bytes calldata hookData = hookUninstallDatas[hookIndex];
                address hookModule = execHooks[i].module();
                onUninstallSuccess =
                    onUninstallSuccess && ModuleInstallCommonsLib.onUninstall(hookModule, hookData);
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
        onUninstallSuccess = onUninstallSuccess && ModuleInstallCommonsLib.onUninstall(module, uninstallData);

        emit ValidationUninstalled(module, entityId, onUninstallSuccess);
    }
}
