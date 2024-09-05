// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {
    HookConfig,
    IModularAccount,
    ModuleEntity
} from "@erc-6900/reference-implementation/interfaces/IModularAccount.sol";
import {
    ExecutionDataView,
    IModularAccountView,
    ValidationDataView
} from "@erc-6900/reference-implementation/interfaces/IModularAccountView.sol";

import {HookConfigLib} from "../helpers/HookConfigLib.sol";
import {ExecutionData, ValidationData, getAccountStorage, toHookConfig} from "./AccountStorage.sol";

abstract contract ModularAccountView is IModularAccountView {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableMap for EnumerableMap.AddressToUintMap;
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

            uint256 executionHooksLen = executionData.executionHooks.length();
            data.executionHooks = new HookConfig[](executionHooksLen);
            for (uint256 i = 0; i < executionHooksLen; ++i) {
                data.executionHooks[i] = toHookConfig(executionData.executionHooks.at(i));
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

        uint256 execHooksLen = validationData.executionHooks.length();
        data.executionHooks = new HookConfig[](execHooksLen);
        for (uint256 i = 0; i < execHooksLen; ++i) {
            data.executionHooks[i] = toHookConfig(validationData.executionHooks.at(i));
        }

        bytes32[] memory selectors = validationData.selectors.values();
        uint256 selectorsLen = selectors.length;
        data.selectors = new bytes4[](selectorsLen);
        for (uint256 j = 0; j < selectorsLen; ++j) {
            data.selectors[j] = bytes4(selectors[j]);
        }
    }
}
