// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.26;

import {
    ExecutionManifest,
    ManifestExecutionHook
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {HookConfig, IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";

import {AccountStorage, ExecutionStorage, getAccountStorage, toSetValue} from "../account/AccountStorage.sol";
import {KnownSelectorsLib} from "../libraries/KnownSelectorsLib.sol";
import {LinkedListSet, LinkedListSetLib} from "../libraries/LinkedListSetLib.sol";
import {ModuleInstallCommons} from "../libraries/ModuleInstallCommons.sol";

/// @title ExecutionInstallDelegate
/// @author Alchemy
///
/// @notice This contract acts as an external library which is meant to handle Execution function installations and
/// uninstallations via delegatecall.
contract ExecutionInstallDelegate {
    using LinkedListSetLib for LinkedListSet;

    address internal immutable _THIS_ADDRESS;

    error OnlyDelegateCall();
    error NullModule();
    error InterfaceNotSupported(address module);
    error ModuleInstallCallbackFailed(address module, bytes revertReason);
    error ExecutionFunctionAlreadySet(bytes4 selector);
    error IModuleFunctionNotAllowed(bytes4 selector);
    error Erc4337FunctionNotAllowed(bytes4 selector);
    error ExecutionHookAlreadySet(HookConfig hookConfig);

    modifier onlyDelegateCall() {
        if (address(this) == _THIS_ADDRESS) {
            revert OnlyDelegateCall();
        }
        _;
    }

    constructor() {
        _THIS_ADDRESS = address(this);
    }

    // External Functions

    function installExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata moduleInstallData
    ) external onlyDelegateCall {
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
            ExecutionStorage storage executionStorage = _storage.executionStorage[mh.executionSelector];
            HookConfig hookConfig = HookConfigLib.packExecHook({
                _module: module,
                _entityId: mh.entityId,
                _hasPre: mh.isPreHook,
                _hasPost: mh.isPostHook
            });
            ModuleInstallCommons.addExecHooks(executionStorage.executionHooks, hookConfig);
        }

        length = manifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            _storage.supportedIfaces[manifest.interfaceIds[i]] += 1;
        }

        ModuleInstallCommons.onInstall(module, moduleInstallData, type(IModule).interfaceId);

        emit IModularAccount.ExecutionInstalled(module, manifest);
    }

    function uninstallExecution(address module, ExecutionManifest calldata manifest, bytes calldata uninstallData)
        external
        onlyDelegateCall
    {
        AccountStorage storage _storage = getAccountStorage();

        // Remove components according to the manifest, in reverse order (by component type) of their installation.

        uint256 length = manifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestExecutionHook memory mh = manifest.executionHooks[i];
            ExecutionStorage storage execData = _storage.executionStorage[mh.executionSelector];
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
        bool onUninstallSuccess = ModuleInstallCommons.onUninstall(module, uninstallData);

        emit IModularAccount.ExecutionUninstalled(module, onUninstallSuccess, manifest);
    }

    // Private Functions

    function _setExecutionFunction(
        bytes4 selector,
        bool skipRuntimeValidation,
        bool allowGlobalValidation,
        address module
    ) internal {
        ExecutionStorage storage _executionData = getAccountStorage().executionStorage[selector];

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

    function _removeExecutionFunction(bytes4 selector) internal {
        ExecutionStorage storage _executionData = getAccountStorage().executionStorage[selector];

        _executionData.module = address(0);
        _executionData.skipRuntimeValidation = false;
        _executionData.allowGlobalValidation = false;
    }

    function _removeExecHooks(LinkedListSet storage hooks, HookConfig hookConfig) internal {
        // Todo: use predecessor
        hooks.tryRemove(toSetValue(hookConfig));
    }
}
