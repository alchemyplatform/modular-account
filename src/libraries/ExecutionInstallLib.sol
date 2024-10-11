// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.26;

import {
    ExecutionManifest,
    ManifestExecutionHook
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {HookConfig, IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

import {AccountStorage, ExecutionData, getAccountStorage, toSetValue} from "../account/AccountStorage.sol";
import {ExecutionLib} from "./ExecutionLib.sol";
import {KnownSelectorsLib} from "./KnownSelectorsLib.sol";
import {LinkedListSet, LinkedListSetLib} from "./LinkedListSetLib.sol";

/// @title ExecutionInstallLib
/// @author Alchemy
///
/// @notice This is a hybrid external-internal library which externally handles execution function installation,
/// while holding some common internal module installation-related functions.
library ExecutionInstallLib {
    using LinkedListSetLib for LinkedListSet;

    error NullModule();
    error InterfaceNotSupported(address module);
    error ModuleInstallCallbackFailed(address module, bytes revertReason);
    error ExecutionFunctionAlreadySet(bytes4 selector);
    error IModuleFunctionNotAllowed(bytes4 selector);
    error Erc4337FunctionNotAllowed(bytes4 selector);
    error ExecutionHookAlreadySet(HookConfig hookConfig);

    // External Functions

    function installExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata moduleInstallData
    ) external {
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
            addExecHooks(executionData.executionHooks, hookConfig);
        }

        length = manifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            _storage.supportedIfaces[manifest.interfaceIds[i]] += 1;
        }

        onInstall(module, moduleInstallData, type(IModule).interfaceId);

        emit IModularAccount.ExecutionInstalled(module, manifest);
    }

    function uninstallExecution(address module, ExecutionManifest calldata manifest, bytes calldata uninstallData)
        external
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
        bool onUninstallSuccess = onUninstall(module, uninstallData);

        emit IModularAccount.ExecutionUninstalled(module, onUninstallSuccess, manifest);
    }

    // Internal Functions

    function addExecHooks(LinkedListSet storage hooks, HookConfig hookConfig) internal {
        if (!hooks.tryAdd(toSetValue(hookConfig))) {
            revert ExecutionHookAlreadySet(hookConfig);
        }
    }

    function onInstall(address module, bytes calldata data, bytes4 interfaceId) internal {
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

    function onUninstall(address module, bytes calldata data) internal returns (bool onUninstallSuccess) {
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

    // Private Functions

    function _setExecutionFunction(
        bytes4 selector,
        bool skipRuntimeValidation,
        bool allowGlobalValidation,
        address module
    ) private {
        ExecutionData storage _executionData = getAccountStorage().executionData[selector];

        if (_executionData.module != address(0)) {
            revert ExecutionFunctionAlreadySet(selector);
        }

        // Note that there is no check for native function selectors. Installing a function with a colliding
        // selector will lead to the installed function being unreachable.

        // Make sure incoming execution function is not a function in IModule
        if (KnownSelectorsLib.isIModuleFunction(selector)) {
            revert IModuleFunctionNotAllowed(selector);
        }

        // Also make sure it doesn't collide with functions defined by ERC-4337 and called by the entry point. This
        // prevents a malicious module from sneaking in a function with the same selector as e.g.
        // `validatePaymasterUserOp` and turning the account into their own personal paymaster.
        if (KnownSelectorsLib.isErc4337Function(selector)) {
            revert Erc4337FunctionNotAllowed(selector);
        }

        _executionData.module = module;
        _executionData.skipRuntimeValidation = skipRuntimeValidation;
        _executionData.allowGlobalValidation = allowGlobalValidation;
    }

    function _removeExecutionFunction(bytes4 selector) private {
        ExecutionData storage _executionData = getAccountStorage().executionData[selector];

        _executionData.module = address(0);
        _executionData.skipRuntimeValidation = false;
        _executionData.allowGlobalValidation = false;
    }

    function _removeExecHooks(LinkedListSet storage hooks, HookConfig hookConfig) private {
        // Todo: use predecessor
        hooks.tryRemove(toSetValue(hookConfig));
    }
}
