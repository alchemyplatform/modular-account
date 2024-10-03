// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

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

import {MemManagementLib} from "../libraries/MemManagementLib.sol";
import {ExecutionData, ValidationData, getAccountStorage} from "./AccountStorage.sol";

abstract contract ModularAccountView is IModularAccountView {
    /// @inheritdoc IModularAccountView
    function getExecutionData(bytes4 selector) external view override returns (ExecutionDataView memory data) {
        if (
            selector == IModularAccount.execute.selector || selector == IModularAccount.executeBatch.selector
                || selector == UUPSUpgradeable.upgradeToAndCall.selector
                || selector == IModularAccount.installExecution.selector
                || selector == IModularAccount.uninstallExecution.selector
        ) {
            data.module = address(this);
            data.allowGlobalValidation = true;
        } else {
            ExecutionData storage executionData = getAccountStorage().executionData[selector];
            data.module = executionData.module;
            data.skipRuntimeValidation = executionData.skipRuntimeValidation;
            data.allowGlobalValidation = executionData.allowGlobalValidation;

            HookConfig[] memory hooks = MemManagementLib.loadExecHooks(executionData);
            MemManagementLib.reverseArr(hooks);
            data.executionHooks = hooks;
        }
    }

    /// @inheritdoc IModularAccountView
    function getValidationData(ModuleEntity validationFunction)
        external
        view
        override
        returns (ValidationDataView memory data)
    {
        ValidationData storage validationData = getAccountStorage().validationData[validationFunction];
        data.isGlobal = validationData.isGlobal;
        data.isSignatureValidation = validationData.isSignatureValidation;
        data.isUserOpValidation = validationData.isUserOpValidation;
        data.validationHooks = MemManagementLib.loadValidationHooks(validationData);
        MemManagementLib.reverseArr(data.validationHooks);

        HookConfig[] memory hooks = MemManagementLib.loadExecHooks(validationData);
        MemManagementLib.reverseArr(hooks);
        data.executionHooks = hooks;

        bytes4[] memory selectors = MemManagementLib.loadSelectors(validationData);
        MemManagementLib.reverseArr(selectors);
        data.selectors = selectors;
    }
}
