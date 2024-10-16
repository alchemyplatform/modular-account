// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {HookConfig, ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {
    ExecutionDataView,
    IModularAccountView,
    ValidationDataView
} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";

import {KnownSelectorsLib} from "../libraries/KnownSelectorsLib.sol";
import {MemManagementLib} from "../libraries/MemManagementLib.sol";
import {ExecutionStorage, ValidationStorage, getAccountStorage} from "./AccountStorage.sol";

/// @title Modular Account Data Viewer
/// @author Alchemy
/// @notice This abstract contract implements the two view functions to get validation and execution data for an
/// account.
abstract contract ModularAccountView is IModularAccountView {
    /// @inheritdoc IModularAccountView
    function getExecutionData(bytes4 selector) external view override returns (ExecutionDataView memory data) {
        ExecutionStorage storage executionStorage = getAccountStorage().executionStorage[selector];

        if (KnownSelectorsLib.isNativeFunction(selector)) {
            data.module = address(this);
            data.allowGlobalValidation = true;
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
        ValidationStorage storage validationStorage = getAccountStorage().validationStorage[validationFunction];
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
}
