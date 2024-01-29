// This file is part of Modular Account.
//
// Copyright 2024 Alchemy Insights, Inc.
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General
// Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.22;

import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

import {AccountStorageV1} from "../account/AccountStorageV1.sol";
import {CastLib} from "../helpers/CastLib.sol";
import {FunctionReferenceLib} from "../helpers/FunctionReferenceLib.sol";
import {KnownSelectors} from "../helpers/KnownSelectors.sol";
import {
    IPlugin,
    ManifestAssociatedFunction,
    ManifestAssociatedFunctionType,
    ManifestExecutionHook,
    ManifestExternalCallPermission,
    ManifestFunction,
    PluginManifest
} from "../interfaces/IPlugin.sol";
import {FunctionReference, IPluginManager} from "../interfaces/IPluginManager.sol";
import {CountableLinkedListSetLib} from "../libraries/CountableLinkedListSetLib.sol";
import {LinkedListSet, LinkedListSetLib} from "../libraries/LinkedListSetLib.sol";

/// @title Plugin Manager Internals
/// @author Alchemy
/// @notice Contains functions to manage the state and behavior of plugin installs and uninstalls.
abstract contract PluginManagerInternals is IPluginManager, AccountStorageV1 {
    using LinkedListSetLib for LinkedListSet;
    using CountableLinkedListSetLib for LinkedListSet;
    using FunctionReferenceLib for FunctionReference;

    // Grouping of arguments to `uninstallPlugin` to avoid "stack too deep"
    // errors when building without via-ir.
    struct UninstallPluginArgs {
        address plugin;
        PluginManifest manifest;
        bool forceUninstall;
        uint256 callbackGasLimit;
    }

    // As per the EIP-165 spec, no interface should ever match 0xffffffff
    bytes4 internal constant _INVALID_INTERFACE_ID = 0xffffffff;

    // These flags are used in LinkedListSet values to optimize lookups.
    // It's important that they don't overlap with bit 1 and bit 2, which are reserved bits used to indicate
    // the sentinel value and the existence of a next value, respectively.
    uint16 internal constant _PRE_EXEC_HOOK_HAS_POST_FLAG = 0x0004; // bit 3

    error ArrayLengthMismatch();
    error DuplicateHookLimitExceeded(bytes4 selector, FunctionReference hook);
    error DuplicatePreRuntimeValidationHookLimitExceeded(bytes4 selector, FunctionReference hook);
    error DuplicatePreUserOpValidationHookLimitExceeded(bytes4 selector, FunctionReference hook);
    error Erc4337FunctionNotAllowed(bytes4 selector);
    error ExecutionFunctionAlreadySet(bytes4 selector);
    error InterfaceNotAllowed();
    error InvalidDependenciesProvided();
    error InvalidPluginManifest();
    error IPluginFunctionNotAllowed(bytes4 selector);
    error MissingPluginDependency(address dependency);
    error NativeFunctionNotAllowed(bytes4 selector);
    error NullFunctionReference();
    error PluginAlreadyInstalled(address plugin);
    error PluginDependencyViolation(address plugin);
    error PluginInstallCallbackFailed(address plugin, bytes revertReason);
    error PluginInterfaceNotSupported(address plugin);
    error PluginNotInstalled(address plugin);
    error PluginUninstallCallbackFailed(address plugin, bytes revertReason);
    error RuntimeValidationFunctionAlreadySet(bytes4 selector, FunctionReference validationFunction);
    error UserOpValidationFunctionAlreadySet(bytes4 selector, FunctionReference validationFunction);

    // Storage update operations

    function _setExecutionFunction(bytes4 selector, address plugin) internal {
        SelectorData storage selectorData = _getAccountStorage().selectorData[selector];

        if (selectorData.plugin != address(0)) {
            revert ExecutionFunctionAlreadySet(selector);
        }

        // Make sure incoming execution function does not collide with any native functions (data are stored on the
        // account implementation contract)
        if (KnownSelectors.isNativeFunction(selector)) {
            revert NativeFunctionNotAllowed(selector);
        }

        // Make sure incoming execution function is not a function in IPlugin
        if (KnownSelectors.isIPluginFunction(selector)) {
            revert IPluginFunctionNotAllowed(selector);
        }

        // Also make sure it doesn't collide with functions defined by ERC-4337
        // and called by the entry point. This prevents a malicious plugin from
        // sneaking in a function with the same selector as e.g.
        // `validatePaymasterUserOp` and turning the account into their own
        // personal paymaster.
        if (KnownSelectors.isErc4337Function(selector)) {
            revert Erc4337FunctionNotAllowed(selector);
        }

        selectorData.plugin = plugin;
    }

    function _addUserOpValidationFunction(bytes4 selector, FunctionReference validationFunction) internal {
        _assertNotNullFunction(validationFunction);

        SelectorData storage selectorData = _getAccountStorage().selectorData[selector];

        if (!selectorData.userOpValidation.isEmpty()) {
            revert UserOpValidationFunctionAlreadySet(selector, validationFunction);
        }

        selectorData.userOpValidation = validationFunction;
    }

    function _addRuntimeValidationFunction(bytes4 selector, FunctionReference validationFunction) internal {
        _assertNotNullFunction(validationFunction);

        SelectorData storage selectorData = _getAccountStorage().selectorData[selector];

        if (!selectorData.runtimeValidation.isEmpty()) {
            revert RuntimeValidationFunctionAlreadySet(selector, validationFunction);
        }

        selectorData.runtimeValidation = validationFunction;
    }

    function _addExecHooks(bytes4 selector, FunctionReference preExecHook, FunctionReference postExecHook)
        internal
    {
        SelectorData storage selectorData = _getAccountStorage().selectorData[selector];

        _addHooks(selectorData.executionHooks, selector, preExecHook, postExecHook);

        if (!preExecHook.isEmpty()) {
            selectorData.hasPreExecHooks = true;
        } else if (!postExecHook.isEmpty()) {
            // Only set this flag if the pre hook is empty and the post hook is non-empty.
            selectorData.hasPostOnlyExecHooks = true;
        }
    }

    function _removeExecHooks(bytes4 selector, FunctionReference preExecHook, FunctionReference postExecHook)
        internal
    {
        SelectorData storage selectorData = _getAccountStorage().selectorData[selector];

        (bool shouldClearHasPreHooks, bool shouldClearHasPostOnlyHooks) =
            _removeHooks(selectorData.executionHooks, preExecHook, postExecHook);

        if (shouldClearHasPreHooks) {
            selectorData.hasPreExecHooks = false;
        }

        if (shouldClearHasPostOnlyHooks) {
            selectorData.hasPostOnlyExecHooks = false;
        }
    }

    function _addHooks(
        HookGroup storage hooks,
        bytes4 selector,
        FunctionReference preExecHook,
        FunctionReference postExecHook
    ) internal {
        if (!preExecHook.isEmpty()) {
            // add pre or pre/post pair of exec hooks
            if (!hooks.preHooks.tryIncrement(CastLib.toSetValue(preExecHook))) {
                revert DuplicateHookLimitExceeded(selector, preExecHook);
            }

            if (!postExecHook.isEmpty()) {
                // can ignore return val of tryEnableFlags here as tryIncrement above must have succeeded
                hooks.preHooks.tryEnableFlags(CastLib.toSetValue(preExecHook), _PRE_EXEC_HOOK_HAS_POST_FLAG);
                if (!hooks.associatedPostHooks[preExecHook].tryIncrement(CastLib.toSetValue(postExecHook))) {
                    revert DuplicateHookLimitExceeded(selector, postExecHook);
                }
            }
        } else {
            // both pre and post hooks cannot be null
            _assertNotNullFunction(postExecHook);

            if (!hooks.postOnlyHooks.tryIncrement(CastLib.toSetValue(postExecHook))) {
                revert DuplicateHookLimitExceeded(selector, postExecHook);
            }
        }
    }

    function _removeHooks(HookGroup storage hooks, FunctionReference preExecHook, FunctionReference postExecHook)
        internal
        returns (bool shouldClearHasPreHooks, bool shouldClearHasPostOnlyHooks)
    {
        if (!preExecHook.isEmpty()) {
            // If decrementing results in removal, this also clears the flag _PRE_EXEC_HOOK_HAS_POST_FLAG.
            // Can ignore the return value because the manifest was checked to match the hash.
            hooks.preHooks.tryDecrement(CastLib.toSetValue(preExecHook));

            // Update the cached flag value for the pre-exec hooks, as it may change with a removal.
            if (hooks.preHooks.isEmpty()) {
                // The "has pre exec hooks" flag should be disabled
                shouldClearHasPreHooks = true;
            }

            if (!postExecHook.isEmpty()) {
                // Remove the associated post-exec hook, if it is set to the expected value.
                // Can ignore the return value because the manifest was checked to match the hash.
                hooks.associatedPostHooks[preExecHook].tryDecrement(CastLib.toSetValue(postExecHook));

                if (hooks.associatedPostHooks[preExecHook].isEmpty()) {
                    // We can ignore return val of tryDisableFlags here as tryDecrement above must have succeeded
                    // in either removing the element or decrementing its count.
                    hooks.preHooks.tryDisableFlags(CastLib.toSetValue(preExecHook), _PRE_EXEC_HOOK_HAS_POST_FLAG);
                }
            }
        } else {
            // If this else branch is reached, it must be a post-only exec hook, because installation would fail
            // when both the pre and post exec hooks are empty.

            // Can ignore the return value because the manifest was checked to match the hash.
            hooks.postOnlyHooks.tryDecrement(CastLib.toSetValue(postExecHook));

            // Update the cached flag value for the post-only exec hooks, as it may change with a removal.
            if (hooks.postOnlyHooks.isEmpty()) {
                // The "has post only hooks" flag should be disabled
                shouldClearHasPostOnlyHooks = true;
            }
        }
    }

    function _addPreUserOpValidationHook(bytes4 selector, FunctionReference preUserOpValidationHook) internal {
        _assertNotNullFunction(preUserOpValidationHook);

        SelectorData storage selectorData = _getAccountStorage().selectorData[selector];
        if (!selectorData.preUserOpValidationHooks.tryIncrement(CastLib.toSetValue(preUserOpValidationHook))) {
            revert DuplicatePreUserOpValidationHookLimitExceeded(selector, preUserOpValidationHook);
        }
        // add the pre user op validation hook to the cache for the given selector
        if (!selectorData.hasPreUserOpValidationHooks) {
            selectorData.hasPreUserOpValidationHooks = true;
        }
    }

    function _removePreUserOpValidationHook(bytes4 selector, FunctionReference preUserOpValidationHook) internal {
        SelectorData storage selectorData = _getAccountStorage().selectorData[selector];
        // Can ignore the return value because the manifest was checked to match the hash.
        selectorData.preUserOpValidationHooks.tryDecrement(CastLib.toSetValue(preUserOpValidationHook));

        if (selectorData.preUserOpValidationHooks.isEmpty()) {
            selectorData.hasPreUserOpValidationHooks = false;
        }
    }

    function _addPreRuntimeValidationHook(bytes4 selector, FunctionReference preRuntimeValidationHook) internal {
        _assertNotNullFunction(preRuntimeValidationHook);

        SelectorData storage selectorData = _getAccountStorage().selectorData[selector];
        if (!selectorData.preRuntimeValidationHooks.tryIncrement(CastLib.toSetValue(preRuntimeValidationHook))) {
            revert DuplicatePreRuntimeValidationHookLimitExceeded(selector, preRuntimeValidationHook);
        }
        // add the pre runtime validation hook's existence to the validator cache for the given selector
        if (!selectorData.hasPreRuntimeValidationHooks) {
            selectorData.hasPreRuntimeValidationHooks = true;
        }
    }

    function _removePreRuntimeValidationHook(bytes4 selector, FunctionReference preRuntimeValidationHook)
        internal
    {
        SelectorData storage selectorData = _getAccountStorage().selectorData[selector];
        // Can ignore the return value because the manifest was checked to match the hash.
        selectorData.preRuntimeValidationHooks.tryDecrement(CastLib.toSetValue(preRuntimeValidationHook));

        if (selectorData.preRuntimeValidationHooks.isEmpty()) {
            selectorData.hasPreRuntimeValidationHooks = false;
        }
    }

    function _installPlugin(
        address plugin,
        bytes32 manifestHash,
        bytes memory pluginInstallData,
        FunctionReference[] memory dependencies
    ) internal {
        AccountStorage storage storage_ = _getAccountStorage();

        // Check if the plugin exists, also invalidate null address.
        if (!storage_.plugins.tryAdd(CastLib.toSetValue(plugin))) {
            revert PluginAlreadyInstalled(plugin);
        }

        // Check that the plugin supports the IPlugin interface.
        if (!ERC165Checker.supportsInterface(plugin, type(IPlugin).interfaceId)) {
            revert PluginInterfaceNotSupported(plugin);
        }

        // Check manifest hash.
        PluginManifest memory manifest = IPlugin(plugin).pluginManifest();
        if (!_isValidPluginManifest(manifest, manifestHash)) {
            revert InvalidPluginManifest();
        }

        // Check that the dependencies match the manifest.
        uint256 length = dependencies.length;
        if (length != manifest.dependencyInterfaceIds.length) {
            revert InvalidDependenciesProvided();
        }

        for (uint256 i = 0; i < length; ++i) {
            // Check the dependency interface id over the address of the dependency.
            (address dependencyAddr,) = dependencies[i].unpack();

            // Check that the dependency is installed. This also blocks self-dependencies.
            if (storage_.pluginData[dependencyAddr].manifestHash == bytes32(0)) {
                revert MissingPluginDependency(dependencyAddr);
            }

            // Check that the dependency supports the expected interface.
            if (!ERC165Checker.supportsInterface(dependencyAddr, manifest.dependencyInterfaceIds[i])) {
                revert InvalidDependenciesProvided();
            }

            // Increment the dependency's dependents counter.
            storage_.pluginData[dependencyAddr].dependentCount += 1;
        }

        // Update components according to the manifest.

        // Install execution functions
        length = manifest.executionFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            _setExecutionFunction(manifest.executionFunctions[i], plugin);
        }

        // Add installed plugin and selectors this plugin can call
        length = manifest.permittedExecutionSelectors.length;
        for (uint256 i = 0; i < length; ++i) {
            storage_.callPermitted[_getPermittedCallKey(plugin, manifest.permittedExecutionSelectors[i])] = true;
        }

        // Add the permitted external calls to the account.
        if (manifest.permitAnyExternalAddress) {
            storage_.pluginData[plugin].anyExternalAddressPermitted = true;
        } else {
            // Only store the specific permitted external calls if "permit any" flag was not set.
            length = manifest.permittedExternalCalls.length;
            for (uint256 i = 0; i < length; ++i) {
                ManifestExternalCallPermission memory externalCallPermission = manifest.permittedExternalCalls[i];

                PermittedExternalCallData storage permittedExternalCallData =
                    storage_.permittedExternalCalls[IPlugin(plugin)][externalCallPermission.externalAddress];

                permittedExternalCallData.addressPermitted = true;

                if (externalCallPermission.permitAnySelector) {
                    permittedExternalCallData.anySelectorPermitted = true;
                } else {
                    uint256 externalContractSelectorsLength = externalCallPermission.selectors.length;
                    for (uint256 j = 0; j < externalContractSelectorsLength; ++j) {
                        permittedExternalCallData.permittedSelectors[externalCallPermission.selectors[j]] = true;
                    }
                }
            }
        }

        // Add user operation validation functions
        length = manifest.userOpValidationFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestAssociatedFunction memory mv = manifest.userOpValidationFunctions[i];
            _addUserOpValidationFunction(
                mv.executionSelector,
                _resolveManifestFunction(
                    mv.associatedFunction, plugin, dependencies, ManifestAssociatedFunctionType.NONE
                )
            );
        }

        // Add runtime validation functions
        length = manifest.runtimeValidationFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestAssociatedFunction memory mv = manifest.runtimeValidationFunctions[i];
            _addRuntimeValidationFunction(
                mv.executionSelector,
                _resolveManifestFunction(
                    mv.associatedFunction,
                    plugin,
                    dependencies,
                    ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW
                )
            );
        }

        // Passed to _resolveManifestFunction when DEPENDENCY is not a valid function type.
        FunctionReference[] memory noDependencies = new FunctionReference[](0);

        // Add pre user operation validation hooks
        length = manifest.preUserOpValidationHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestAssociatedFunction memory mh = manifest.preUserOpValidationHooks[i];
            _addPreUserOpValidationHook(
                mh.executionSelector,
                _resolveManifestFunction(
                    mh.associatedFunction,
                    plugin,
                    noDependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                )
            );
        }

        // Add pre runtime validation hooks
        length = manifest.preRuntimeValidationHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestAssociatedFunction memory mh = manifest.preRuntimeValidationHooks[i];
            _addPreRuntimeValidationHook(
                mh.executionSelector,
                _resolveManifestFunction(
                    mh.associatedFunction,
                    plugin,
                    noDependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                )
            );
        }

        // Add pre and post execution hooks
        length = manifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestExecutionHook memory mh = manifest.executionHooks[i];
            _addExecHooks(
                mh.executionSelector,
                _resolveManifestFunction(
                    mh.preExecHook, plugin, noDependencies, ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                ),
                _resolveManifestFunction(
                    mh.postExecHook, plugin, noDependencies, ManifestAssociatedFunctionType.NONE
                )
            );
        }

        // Add new interface ids the plugin enabled for the account
        length = manifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 interfaceId = manifest.interfaceIds[i];
            if (interfaceId == type(IPlugin).interfaceId || interfaceId == _INVALID_INTERFACE_ID) {
                revert InterfaceNotAllowed();
            }
            storage_.supportedInterfaces[interfaceId] += 1;
        }

        // Add the plugin metadata to the account
        storage_.pluginData[plugin].manifestHash = manifestHash;
        storage_.pluginData[plugin].dependencies = dependencies;

        // Mark whether or not this plugin may spend native token amounts
        if (manifest.canSpendNativeToken) {
            storage_.pluginData[plugin].canSpendNativeToken = true;
        }

        // Initialize the plugin storage for the account.
        // solhint-disable-next-line no-empty-blocks
        try IPlugin(plugin).onInstall(pluginInstallData) {}
        catch (bytes memory revertReason) {
            revert PluginInstallCallbackFailed(plugin, revertReason);
        }

        emit PluginInstalled(plugin, manifestHash, dependencies);
    }

    function _uninstallPlugin(UninstallPluginArgs memory args, bytes calldata pluginUninstallData) internal {
        AccountStorage storage storage_ = _getAccountStorage();

        // Check if the plugin exists.
        if (!storage_.plugins.tryRemove(CastLib.toSetValue(args.plugin))) {
            revert PluginNotInstalled(args.plugin);
        }

        PluginData memory pluginData = storage_.pluginData[args.plugin];

        // Check manifest hash.
        if (!_isValidPluginManifest(args.manifest, pluginData.manifestHash)) {
            revert InvalidPluginManifest();
        }

        // Ensure that there are no dependent plugins.
        if (pluginData.dependentCount != 0) {
            revert PluginDependencyViolation(args.plugin);
        }

        // Remove this plugin as a dependent from its dependencies.
        FunctionReference[] memory dependencies = pluginData.dependencies;
        uint256 length = dependencies.length;
        for (uint256 i = 0; i < length; ++i) {
            FunctionReference dependency = dependencies[i];
            (address dependencyAddr,) = dependency.unpack();

            // Decrement the dependent count for the dependency function.
            storage_.pluginData[dependencyAddr].dependentCount -= 1;
        }

        // Remove the plugin metadata from the account.
        delete storage_.pluginData[args.plugin];

        // Remove components according to the manifest, in reverse order (by component type) of their installation.

        // Passed to _resolveManifestFunction when DEPENDENCY is not a valid function type.
        FunctionReference[] memory noDependencies = new FunctionReference[](0);

        // Remove pre and post execution function hooks
        length = args.manifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestExecutionHook memory mh = args.manifest.executionHooks[i];
            _removeExecHooks(
                mh.executionSelector,
                _resolveManifestFunction(
                    mh.preExecHook,
                    args.plugin,
                    noDependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                ),
                _resolveManifestFunction(
                    mh.postExecHook, args.plugin, noDependencies, ManifestAssociatedFunctionType.NONE
                )
            );
        }

        // Remove pre runtime validation function hooks
        length = args.manifest.preRuntimeValidationHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestAssociatedFunction memory mh = args.manifest.preRuntimeValidationHooks[i];

            _removePreRuntimeValidationHook(
                mh.executionSelector,
                _resolveManifestFunction(
                    mh.associatedFunction,
                    args.plugin,
                    noDependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                )
            );
        }

        // Remove pre user op validation function hooks
        length = args.manifest.preUserOpValidationHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestAssociatedFunction memory mh = args.manifest.preUserOpValidationHooks[i];

            _removePreUserOpValidationHook(
                mh.executionSelector,
                _resolveManifestFunction(
                    mh.associatedFunction,
                    args.plugin,
                    noDependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                )
            );
        }

        // Remove runtime validation function hooks
        length = args.manifest.runtimeValidationFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 executionSelector = args.manifest.runtimeValidationFunctions[i].executionSelector;
            storage_.selectorData[executionSelector].runtimeValidation =
                FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE;
        }

        // Remove user op validation function hooks
        length = args.manifest.userOpValidationFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 executionSelector = args.manifest.userOpValidationFunctions[i].executionSelector;
            storage_.selectorData[executionSelector].userOpValidation =
                FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE;
        }

        // Remove permitted external call permissions, anyExternalAddressPermitted is cleared when pluginData being
        // deleted
        if (!args.manifest.permitAnyExternalAddress) {
            // Only clear the specific permitted external calls if "permit any" flag was not set.
            length = args.manifest.permittedExternalCalls.length;
            for (uint256 i = 0; i < length; ++i) {
                ManifestExternalCallPermission memory externalCallPermission =
                    args.manifest.permittedExternalCalls[i];

                PermittedExternalCallData storage permittedExternalCallData =
                    storage_.permittedExternalCalls[IPlugin(args.plugin)][externalCallPermission.externalAddress];

                permittedExternalCallData.addressPermitted = false;

                // Only clear this flag if it was set in the constructor.
                if (externalCallPermission.permitAnySelector) {
                    permittedExternalCallData.anySelectorPermitted = false;
                } else {
                    uint256 externalContractSelectorsLength = externalCallPermission.selectors.length;
                    for (uint256 j = 0; j < externalContractSelectorsLength; ++j) {
                        permittedExternalCallData.permittedSelectors[externalCallPermission.selectors[j]] = false;
                    }
                }
            }
        }

        // Remove permitted account execution function call permissions
        length = args.manifest.permittedExecutionSelectors.length;
        for (uint256 i = 0; i < length; ++i) {
            storage_.callPermitted[_getPermittedCallKey(args.plugin, args.manifest.permittedExecutionSelectors[i])]
            = false;
        }

        // Remove installed execution function
        length = args.manifest.executionFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            storage_.selectorData[args.manifest.executionFunctions[i]].plugin = address(0);
        }

        // Decrease supported interface ids' counters
        length = args.manifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            storage_.supportedInterfaces[args.manifest.interfaceIds[i]] -= 1;
        }

        // Clear the plugin storage for the account.
        bool onUninstallSucceeded = true;
        // solhint-disable-next-line no-empty-blocks
        try IPlugin(args.plugin).onUninstall{gas: args.callbackGasLimit}(pluginUninstallData) {}
        catch (bytes memory revertReason) {
            if (!args.forceUninstall) {
                revert PluginUninstallCallbackFailed(args.plugin, revertReason);
            }
            onUninstallSucceeded = false;
        }

        emit PluginUninstalled(args.plugin, onUninstallSucceeded);
    }

    function _isValidPluginManifest(PluginManifest memory manifest, bytes32 manifestHash)
        internal
        pure
        returns (bool)
    {
        return manifestHash == keccak256(abi.encode(manifest));
    }

    function _resolveManifestFunction(
        ManifestFunction memory manifestFunction,
        address plugin,
        // Can be empty to indicate that type DEPENDENCY is invalid for this function.
        FunctionReference[] memory dependencies,
        // Indicates which magic value, if any, is permissible for the function to resolve.
        ManifestAssociatedFunctionType allowedMagicValue
    ) internal pure returns (FunctionReference) {
        if (manifestFunction.functionType == ManifestAssociatedFunctionType.SELF) {
            return FunctionReferenceLib.pack(plugin, manifestFunction.functionId);
        }
        if (manifestFunction.functionType == ManifestAssociatedFunctionType.DEPENDENCY) {
            uint256 index = manifestFunction.dependencyIndex;
            if (index < dependencies.length) {
                return dependencies[index];
            }
            revert InvalidPluginManifest();
        }
        if (manifestFunction.functionType == ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW) {
            if (allowedMagicValue == ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW) {
                return FunctionReferenceLib._RUNTIME_VALIDATION_ALWAYS_ALLOW;
            }
            revert InvalidPluginManifest();
        }
        if (manifestFunction.functionType == ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY) {
            if (allowedMagicValue == ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY) {
                return FunctionReferenceLib._PRE_HOOK_ALWAYS_DENY;
            }
            revert InvalidPluginManifest();
        }
        return FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE; // Empty checks are done elsewhere
    }

    function _assertNotNullFunction(FunctionReference functionReference) internal pure {
        if (functionReference.isEmpty()) {
            revert NullFunctionReference();
        }
    }
}
