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
import {ModuleInstallCommonsLib} from "../libraries/ModuleInstallCommonsLib.sol";

/// @title Execution Install Delegate
/// @author Alchemy
/// @notice This contract acts as an external library which is meant to handle execution function installations and
/// uninstallations via delegatecall.
contract ExecutionInstallDelegate {
    using LinkedListSetLib for LinkedListSet;

    address internal immutable _THIS_ADDRESS;

    error Erc4337FunctionNotAllowed(bytes4 selector);
    error ExecutionFunctionAlreadySet(bytes4 selector);
    error ExecutionFunctionNotSet(bytes4 selector);
    error ExecutionHookNotSet(HookConfig hookConfig);
    error IModuleFunctionNotAllowed(bytes4 selector);
    error NullModule();
    error OnlyDelegateCall();

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

    /// @notice Update components according to the manifest.
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
            LinkedListSet storage executionHooks = _storage.executionStorage[mh.executionSelector].executionHooks;
            HookConfig hookConfig = HookConfigLib.packExecHook({
                _module: module,
                _entityId: mh.entityId,
                _hasPre: mh.isPreHook,
                _hasPost: mh.isPostHook
            });
            ModuleInstallCommonsLib.addExecHooks(executionHooks, hookConfig);
        }

        length = manifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            _storage.supportedIfaces[manifest.interfaceIds[i]] += 1;
        }

        ModuleInstallCommonsLib.onInstall(module, moduleInstallData, type(IModule).interfaceId);

        emit IModularAccount.ExecutionInstalled(module, manifest);
    }

    /// @notice Remove components according to the manifest, in reverse order (by component type) of their
    /// installation.
    function uninstallExecution(address module, ExecutionManifest calldata manifest, bytes calldata uninstallData)
        external
        onlyDelegateCall
    {
        AccountStorage storage _storage = getAccountStorage();

        if (module == address(0)) {
            revert NullModule();
        }

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
        bool onUninstallSuccess = ModuleInstallCommonsLib.onUninstall(module, uninstallData);

        emit IModularAccount.ExecutionUninstalled(module, onUninstallSuccess, manifest);
    }

    // Private Functions

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

        // Note that there is no check for native function selectors. Installing a function with a colliding
        // selector will lead to the installed function being unreachable.

        // Make sure incoming execution function is not a function in IModule
        if (KnownSelectorsLib.isIModuleFunction(uint32(selector))) {
            revert IModuleFunctionNotAllowed(selector);
        }

        // Also make sure it doesn't collide with functions defined by ERC-4337 and called by the entry point. This
        // prevents a malicious module from sneaking in a function with the same selector as e.g.
        // `validatePaymasterUserOp` and turning the account into their own personal paymaster.
        if (KnownSelectorsLib.isErc4337Function(uint32(selector))) {
            revert Erc4337FunctionNotAllowed(selector);
        }

        _executionStorage.module = module;
        _executionStorage.skipRuntimeValidation = skipRuntimeValidation;
        _executionStorage.allowGlobalValidation = allowGlobalValidation;
    }

    function _removeExecutionFunction(bytes4 selector) internal {
        ExecutionStorage storage _executionStorage = getAccountStorage().executionStorage[selector];

        if (_executionStorage.module == address(0)) {
            revert ExecutionFunctionNotSet(selector);
        }

        _executionStorage.module = address(0);
        _executionStorage.skipRuntimeValidation = false;
        _executionStorage.allowGlobalValidation = false;
    }

    function _removeExecHooks(LinkedListSet storage hooks, HookConfig hookConfig) internal {
        if (!hooks.tryRemove(toSetValue(hookConfig))) {
            revert ExecutionHookNotSet(hookConfig);
        }
    }
}
