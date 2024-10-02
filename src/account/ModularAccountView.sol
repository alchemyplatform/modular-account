// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {
    LinkedListSet,
    LinkedListSetLib,
    SetValue
} from "@erc6900/modular-account-libs/libraries/LinkedListSetLib.sol";
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

import {HookConfigLib} from "../libraries/HookConfigLib.sol";
import {ExecutionData, ValidationData, getAccountStorage} from "./AccountStorage.sol";

abstract contract ModularAccountView is IModularAccountView {
    using LinkedListSetLib for LinkedListSet;
    using HookConfigLib for HookConfig;

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

            // Todo: optimize this array reverse.
            SetValue[] memory hooks = executionData.executionHooks.getAll();
            uint256 hooksLength = hooks.length;
            data.executionHooks = new HookConfig[](hooksLength);

            for (uint256 i = 0; i < hooksLength; ++i) {
                data.executionHooks[hooksLength - i - 1] = HookConfig.wrap(bytes25(SetValue.unwrap(hooks[i])));
            }
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
        data.preValidationHooks = validationData.preValidationHooks;

        // Todo: optimize these array reverses

        SetValue[] memory hooks = validationData.executionHooks.getAll();
        uint256 hooksLength = hooks.length;
        data.executionHooks = new HookConfig[](hooksLength);

        for (uint256 i = 0; i < hooksLength; ++i) {
            data.executionHooks[hooksLength - i - 1] = HookConfig.wrap(bytes25(SetValue.unwrap(hooks[i])));
        }

        SetValue[] memory selectors = validationData.selectors.getAll();
        uint256 selectorsLen = selectors.length;
        data.selectors = new bytes4[](selectorsLen);
        for (uint256 j = 0; j < selectorsLen; ++j) {
            data.selectors[selectorsLen - j - 1] = bytes4(SetValue.unwrap(selectors[j]));
        }
    }
}
