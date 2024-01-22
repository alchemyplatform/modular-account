// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {IPlugin} from "../interfaces/IPlugin.sol";

import {FunctionReference} from "../libraries/FunctionReferenceLib.sol";
import {LinkedListSet} from "../libraries/LinkedListSetLib.sol";

/// @title Account Storage V1
/// @author Alchemy
/// @notice Contains the storage layout for upgradeable modular accounts.
contract AccountStorageV1 {
    /// @custom:storage-location erc7201:Alchemy.UpgradeableModularAccount.Storage_V1
    struct AccountStorage {
        // AccountStorageInitializable variables
        uint8 initialized;
        bool initializing;
        // Plugin metadata storage
        LinkedListSet plugins;
        mapping(address => PluginData) pluginData;
        // Execution functions and their associated functions
        mapping(bytes4 => SelectorData) selectorData;
        // bytes24 key = address(calling plugin) || bytes4(selector of execution function)
        mapping(bytes24 => PermittedCallData) permittedCalls;
        // key = address(calling plugin) || target address
        mapping(IPlugin => mapping(address => PermittedExternalCallData)) permittedExternalCalls;
        // For ERC165 introspection, each count indicates support from account or an installed plugin
        // 0 indicate the account does not support the interface and all plugins that support this interface have
        // been uninstalled
        mapping(bytes4 => uint256) supportedInterfaces;
    }

    struct PluginData {
        bool anyExternalAddressPermitted;
        // boolean to indicate if the plugin can spend native tokens, if any of the execution function can spend
        // native tokens, a plugin is considered to be able to spend native tokens of the accounts
        bool canSpendNativeToken;
        bytes32 manifestHash;
        FunctionReference[] dependencies;
        // Tracks the number of times this plugin has been used as a dependency function
        uint256 dependentCount;
        StoredInjectedHook[] injectedHooks;
    }

    /// @dev A version of IPluginManager.InjectedHook used to track injected hooks in storage. Omits the
    /// hookApplyData field, which is not needed for storage, and flattens the struct.
    struct StoredInjectedHook {
        // The plugin that provides the hook
        address providingPlugin;
        // Either a plugin-defined execution function, or the native function executeFromPluginExternal
        bytes4 selector;
        // Contents of the InjectedHooksInfo struct
        uint8 preExecHookFunctionId;
        bool isPostHookUsed;
        uint8 postExecHookFunctionId;
    }

    /// @dev Represents data associated with a plugin's permission to use `executeFromPlugin` to interact with
    /// another plugin installed on the account.
    struct PermittedCallData {
        bool callPermitted;
        // Cached flags indicating whether or not this function has pre permitted call hooks and
        // post-only permitted call hooks.
        bool hasPrePermittedCallHooks;
        bool hasPostOnlyPermittedCallHooks;
        HookGroup permittedCallHooks;
    }

    /// @dev Represents data associated with a plugin's permission to use `executeFromPluginExternal` to interact
    /// with contracts and addresses external to the account and its plugins.
    struct PermittedExternalCallData {
        // Is this address on the permitted addresses list? If it is, we either have a
        // list of allowed selectors, or the flag that allows any selector.
        bool addressPermitted;
        bool anySelectorPermitted;
        mapping(bytes4 => bool) permittedSelectors;
    }

    struct HookGroup {
        // NOTE: this uses the flag _PRE_EXEC_HOOK_HAS_POST_FLAG to indicate whether
        // an element has an associated post-exec hook.
        LinkedListSet preHooks;
        // bytes21 key = pre exec hook function reference
        mapping(FunctionReference => LinkedListSet) associatedPostHooks;
        LinkedListSet postOnlyHooks;
    }

    /// @dev Represents data associated with a specifc function selector.
    struct SelectorData {
        // The plugin that implements this execution function.
        // If this is a native function, the address must remain address(0).
        address plugin;
        // Cached flags indicating whether or not this function has pre-execution hooks and
        // post-only hooks. Flags for pre-validation hooks stored in the same storage word
        // as the validation function itself, to use a warm storage slot when loading.
        bool hasPreExecHooks;
        bool hasPostOnlyExecHooks;
        // The specified validation functions for this function selector.
        FunctionReference userOpValidation;
        bool hasPreUserOpValidationHooks;
        FunctionReference runtimeValidation;
        bool hasPreRuntimeValidationHooks;
        // The pre validation hooks for this function selector.
        LinkedListSet preUserOpValidationHooks;
        LinkedListSet preRuntimeValidationHooks;
        // The execution hooks for this function selector.
        HookGroup executionHooks;
    }

    /// @dev the same storage slot will be used versions V1.x.y of upgradeable modular accounts. Follows ERC-7201.
    /// bytes = keccak256(
    ///     abi.encode(uint256(keccak256("Alchemy.UpgradeableModularAccount.Storage_V1")) - 1)
    /// ) & ~bytes32(uint256(0xff));
    bytes32 internal constant _V1_STORAGE_SLOT = 0xade46bbfcf6f898a43d541e42556d456ca0bf9b326df8debc0f29d3f811a0300;

    function _getAccountStorage() internal pure returns (AccountStorage storage storage_) {
        assembly ("memory-safe") {
            storage_.slot := _V1_STORAGE_SLOT
        }
    }

    function _getPermittedCallKey(address addr, bytes4 selector) internal pure returns (bytes24) {
        return bytes24(bytes20(addr)) | (bytes24(selector) >> 160);
    }
}
