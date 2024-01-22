// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

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
import {IPluginManager} from "../interfaces/IPluginManager.sol";

import {AccountStorageV1} from "../libraries/AccountStorageV1.sol";
import {CastLib} from "../libraries/CastLib.sol";
import {CountableLinkedListSetLib} from "../libraries/CountableLinkedListSetLib.sol";
import {FunctionReference, FunctionReferenceLib} from "../libraries/FunctionReferenceLib.sol";
import {LinkedListSet, LinkedListSetLib} from "../libraries/LinkedListSetLib.sol";

/// @title Plugin Manager Internals
/// @author Alchemy
/// @notice Contains functions to manage the state and behavior of plugin installs and uninstalls.
abstract contract PluginManagerInternals is IPluginManager, AccountStorageV1 {
    using LinkedListSetLib for LinkedListSet;
    using CountableLinkedListSetLib for LinkedListSet;

    // Grouping of arguments to `uninstallPlugin` to avoid "stack too deep"
    // errors when building without via-ir.
    struct UninstallPluginArgs {
        address plugin;
        PluginManifest manifest;
        bool forceUninstall;
        uint256 callbackGasLimit;
    }

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
    error IPluginFunctionNotAllowed(bytes4 selector);
    error IPluginInterfaceNotAllowed();
    error InvalidDependenciesProvided();
    error InvalidPluginManifest();
    error MissingPluginDependency(address dependency);
    error NativeFunctionNotAllowed(bytes4 selector);
    error NullFunctionReference();
    error PluginAlreadyInstalled(address plugin);
    error PluginApplyHookCallbackFailed(address providingPlugin, bytes revertReason);
    error PluginDependencyViolation(address plugin);
    error PluginHookUnapplyCallbackFailed(address providingPlugin, bytes revertReason);
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

        if (selectorData.userOpValidation != FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE) {
            revert UserOpValidationFunctionAlreadySet(selector, validationFunction);
        }

        selectorData.userOpValidation = validationFunction;
    }

    function _addRuntimeValidationFunction(bytes4 selector, FunctionReference validationFunction) internal {
        _assertNotNullFunction(validationFunction);

        SelectorData storage selectorData = _getAccountStorage().selectorData[selector];

        if (selectorData.runtimeValidation != FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE) {
            revert RuntimeValidationFunctionAlreadySet(selector, validationFunction);
        }

        selectorData.runtimeValidation = validationFunction;
    }

    function _addExecHooks(bytes4 selector, FunctionReference preExecHook, FunctionReference postExecHook)
        internal
    {
        SelectorData storage selectorData = _getAccountStorage().selectorData[selector];

        _addHooks(selectorData.executionHooks, selector, preExecHook, postExecHook);

        if (preExecHook != FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE) {
            selectorData.hasPreExecHooks = true;
        } else if (postExecHook != FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE) {
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

    function _enableExecFromPlugin(bytes4 selector, address plugin, AccountStorage storage storage_) internal {
        PermittedCallData storage permittedCallData =
            storage_.permittedCalls[_getPermittedCallKey(plugin, selector)];

        // If there are duplicates, this will just enable the flag again. This is not a problem, since the boolean
        // will be set to false twice during uninstall, which is fine.
        permittedCallData.callPermitted = true;
    }

    function _addPermittedCallHooks(
        bytes4 selector,
        address plugin,
        FunctionReference preExecHook,
        FunctionReference postExecHook
    ) internal {
        PermittedCallData storage permittedCallData =
            _getAccountStorage().permittedCalls[_getPermittedCallKey(plugin, selector)];

        _addHooks(permittedCallData.permittedCallHooks, selector, preExecHook, postExecHook);

        if (preExecHook != FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE) {
            permittedCallData.hasPrePermittedCallHooks = true;
        } else if (postExecHook != FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE) {
            // Only set this flag if the pre hook is empty and the post hook is non-empty.
            permittedCallData.hasPostOnlyPermittedCallHooks = true;
        }
    }

    function _removePermittedCallHooks(
        bytes4 selector,
        address plugin,
        FunctionReference preExecHook,
        FunctionReference postExecHook
    ) internal {
        PermittedCallData storage permittedCallData =
            _getAccountStorage().permittedCalls[_getPermittedCallKey(plugin, selector)];

        (bool shouldClearHasPreHooks, bool shouldClearHasPostOnlyHooks) =
            _removeHooks(permittedCallData.permittedCallHooks, preExecHook, postExecHook);

        if (shouldClearHasPreHooks) {
            permittedCallData.hasPrePermittedCallHooks = false;
        }

        if (shouldClearHasPostOnlyHooks) {
            permittedCallData.hasPostOnlyPermittedCallHooks = false;
        }
    }

    function _addHooks(
        HookGroup storage hooks,
        bytes4 selector,
        FunctionReference preExecHook,
        FunctionReference postExecHook
    ) internal {
        if (preExecHook != FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE) {
            // add pre or pre/post pair of exec hooks
            if (!hooks.preHooks.tryIncrement(CastLib.toSetValue(preExecHook))) {
                revert DuplicateHookLimitExceeded(selector, preExecHook);
            }

            if (postExecHook != FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE) {
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
        if (preExecHook != FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE) {
            // If decrementing results in removal, this also clears the flag _PRE_EXEC_HOOK_HAS_POST_FLAG.
            // Can ignore the return value because the manifest was checked to match the hash.
            hooks.preHooks.tryDecrement(CastLib.toSetValue(preExecHook));

            // Update the cached flag value for the pre-exec hooks, as it may change with a removal.
            if (hooks.preHooks.isEmpty()) {
                // The "has pre exec hooks" flag should be disabled
                shouldClearHasPreHooks = true;
            }

            if (postExecHook != FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE) {
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
        bytes memory pluginInitData,
        FunctionReference[] memory dependencies,
        InjectedHook[] memory injectedHooks
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
            _enableExecFromPlugin(manifest.permittedExecutionSelectors[i], plugin, storage_);
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

        // Add injected hooks
        length = injectedHooks.length;
        // Manually set injected hooks array length
        StoredInjectedHook[] storage injectedHooksArray = storage_.pluginData[plugin].injectedHooks;
        assembly ("memory-safe") {
            sstore(injectedHooksArray.slot, length)
        }
        for (uint256 i = 0; i < length; ++i) {
            InjectedHook memory hook = injectedHooks[i];

            // Check that the dependency is installed. This also blocks self-dependencies.
            if (storage_.pluginData[hook.providingPlugin].manifestHash == bytes32(0)) {
                revert MissingPluginDependency(hook.providingPlugin);
            }

            injectedHooksArray[i] = StoredInjectedHook({
                providingPlugin: hook.providingPlugin,
                selector: hook.selector,
                preExecHookFunctionId: hook.injectedHooksInfo.preExecHookFunctionId,
                isPostHookUsed: hook.injectedHooksInfo.isPostHookUsed,
                postExecHookFunctionId: hook.injectedHooksInfo.postExecHookFunctionId
            });

            // Increment the dependent count for the plugin providing the hook.
            storage_.pluginData[hook.providingPlugin].dependentCount += 1;

            _addPermittedCallHooks(
                hook.selector,
                plugin,
                FunctionReferenceLib.pack(hook.providingPlugin, hook.injectedHooksInfo.preExecHookFunctionId),
                hook.injectedHooksInfo.isPostHookUsed
                    ? FunctionReferenceLib.pack(hook.providingPlugin, hook.injectedHooksInfo.postExecHookFunctionId)
                    : FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE
            );
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

        // Add pre user operation validation hooks
        length = manifest.preUserOpValidationHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestAssociatedFunction memory mh = manifest.preUserOpValidationHooks[i];
            _addPreUserOpValidationHook(
                mh.executionSelector,
                _resolveManifestFunction(
                    mh.associatedFunction,
                    plugin,
                    dependencies,
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
                    dependencies,
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
                    mh.preExecHook, plugin, dependencies, ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                ),
                _resolveManifestFunction(
                    mh.postExecHook, plugin, dependencies, ManifestAssociatedFunctionType.NONE
                )
            );
        }

        // Add pre and post permitted call hooks
        length = manifest.permittedCallHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            _addPermittedCallHooks(
                manifest.permittedCallHooks[i].executionSelector,
                plugin,
                _resolveManifestFunction(
                    manifest.permittedCallHooks[i].preExecHook,
                    plugin,
                    dependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                ),
                _resolveManifestFunction(
                    manifest.permittedCallHooks[i].postExecHook,
                    plugin,
                    dependencies,
                    ManifestAssociatedFunctionType.NONE
                )
            );
        }

        // Add new interface ids the plugin enabled for the account
        length = manifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 interfaceId = manifest.interfaceIds[i];
            if (interfaceId == type(IPlugin).interfaceId) {
                revert IPluginInterfaceNotAllowed();
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

        // Call injected hooks' onHookApply after all setup, this is before calling plugin onInstall
        length = injectedHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            InjectedHook memory hook = injectedHooks[i];

            /* solhint-disable no-empty-blocks */
            try IPlugin(hook.providingPlugin).onHookApply(
                plugin, hook.injectedHooksInfo, injectedHooks[i].hookApplyData
            ) {} catch (bytes memory revertReason) {
                revert PluginApplyHookCallbackFailed(hook.providingPlugin, revertReason);
            }
            /* solhint-enable no-empty-blocks */

            // zero out hookApplyData to reduce log cost
            injectedHooks[i].hookApplyData = new bytes(0);
        }

        // Initialize the plugin storage for the account.
        // solhint-disable-next-line no-empty-blocks
        try IPlugin(plugin).onInstall(pluginInitData) {}
        catch (bytes memory revertReason) {
            revert PluginInstallCallbackFailed(plugin, revertReason);
        }

        emit PluginInstalled(plugin, manifestHash, dependencies, injectedHooks);
    }

    function _uninstallPlugin(
        UninstallPluginArgs memory args,
        bytes calldata uninstallData,
        bytes[] calldata hookUnapplyData
    ) internal {
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

        // Remove pre and post permitted call hooks
        length = args.manifest.permittedCallHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            _removePermittedCallHooks(
                args.manifest.permittedCallHooks[i].executionSelector,
                args.plugin,
                _resolveManifestFunction(
                    args.manifest.permittedCallHooks[i].preExecHook,
                    args.plugin,
                    dependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                ),
                _resolveManifestFunction(
                    args.manifest.permittedCallHooks[i].postExecHook,
                    args.plugin,
                    dependencies,
                    ManifestAssociatedFunctionType.NONE
                )
            );
        }

        // Remove pre and post execution function hooks
        length = args.manifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestExecutionHook memory mh = args.manifest.executionHooks[i];
            _removeExecHooks(
                mh.executionSelector,
                _resolveManifestFunction(
                    mh.preExecHook, args.plugin, dependencies, ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                ),
                _resolveManifestFunction(
                    mh.postExecHook, args.plugin, dependencies, ManifestAssociatedFunctionType.NONE
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
                    dependencies,
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
                    dependencies,
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

        // Remove injected hooks
        length = pluginData.injectedHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            StoredInjectedHook memory hook = pluginData.injectedHooks[i];

            // Decrement the dependent count for the plugin providing the hook.
            storage_.pluginData[hook.providingPlugin].dependentCount -= 1;

            _removePermittedCallHooks(
                hook.selector,
                args.plugin,
                FunctionReferenceLib.pack(hook.providingPlugin, hook.preExecHookFunctionId),
                hook.isPostHookUsed
                    ? FunctionReferenceLib.pack(hook.providingPlugin, hook.postExecHookFunctionId)
                    : FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE
            );
        }

        // Remove permitted account execution function call permissions
        length = args.manifest.permittedExecutionSelectors.length;
        for (uint256 i = 0; i < length; ++i) {
            storage_.permittedCalls[_getPermittedCallKey(args.plugin, args.manifest.permittedExecutionSelectors[i])]
                .callPermitted = false;
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

        // Call onHookUnapply on all injected hooks
        bool callbacksSucceeded = true;
        length = pluginData.injectedHooks.length;
        bool hasUnapplyHookData = hookUnapplyData.length != 0;
        if (hasUnapplyHookData && hookUnapplyData.length != length) {
            revert ArrayLengthMismatch();
        }
        for (uint256 i = 0; i < length; ++i) {
            StoredInjectedHook memory hook = pluginData.injectedHooks[i];

            /* solhint-disable no-empty-blocks */
            try IPlugin(hook.providingPlugin).onHookUnapply{gas: args.callbackGasLimit}(
                args.plugin,
                InjectedHooksInfo({
                    preExecHookFunctionId: hook.preExecHookFunctionId,
                    isPostHookUsed: hook.isPostHookUsed,
                    postExecHookFunctionId: hook.postExecHookFunctionId
                }),
                hasUnapplyHookData ? hookUnapplyData[i] : bytes("")
            ) {} catch (bytes memory revertReason) {
                if (!args.forceUninstall) {
                    revert PluginHookUnapplyCallbackFailed(hook.providingPlugin, revertReason);
                }
                callbacksSucceeded = false;
                emit PluginIgnoredHookUnapplyCallbackFailure(args.plugin, hook.providingPlugin);
            }
            /* solhint-enable no-empty-blocks */
        }

        // Clear the plugin storage for the account.
        // solhint-disable-next-line no-empty-blocks
        try IPlugin(args.plugin).onUninstall{gas: args.callbackGasLimit}(uninstallData) {}
        catch (bytes memory revertReason) {
            if (!args.forceUninstall) {
                revert PluginUninstallCallbackFailed(args.plugin, revertReason);
            }
            callbacksSucceeded = false;
            emit PluginIgnoredUninstallCallbackFailure(args.plugin);
        }

        emit PluginUninstalled(args.plugin, callbacksSucceeded);
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
        FunctionReference[] memory dependencies,
        // Indicates which magic value, if any, is permissible for the function to resolve.
        ManifestAssociatedFunctionType allowedMagicValue
    ) internal pure returns (FunctionReference) {
        if (manifestFunction.functionType == ManifestAssociatedFunctionType.SELF) {
            return FunctionReferenceLib.pack(plugin, manifestFunction.functionId);
        } else if (manifestFunction.functionType == ManifestAssociatedFunctionType.DEPENDENCY) {
            return dependencies[manifestFunction.dependencyIndex];
        } else if (manifestFunction.functionType == ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW)
        {
            if (allowedMagicValue == ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW) {
                return FunctionReferenceLib._RUNTIME_VALIDATION_ALWAYS_ALLOW;
            } else {
                revert InvalidPluginManifest();
            }
        } else if (manifestFunction.functionType == ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY) {
            if (allowedMagicValue == ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY) {
                return FunctionReferenceLib._PRE_HOOK_ALWAYS_DENY;
            } else {
                revert InvalidPluginManifest();
            }
        }
        return FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE; // Empty checks are done elsewhere
    }

    function _assertNotNullFunction(FunctionReference functionReference) internal pure {
        if (functionReference == FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE) {
            revert NullFunctionReference();
        }
    }
}
