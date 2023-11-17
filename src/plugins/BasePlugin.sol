// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

import {IPlugin, PluginManifest, PluginMetadata} from "../interfaces/IPlugin.sol";
import {IPluginManager} from "../interfaces/IPluginManager.sol";
import {UserOperation} from "../interfaces/erc4337/UserOperation.sol";

/// @title Base contract for plugins
/// @dev Implements ERC-165 to support IPlugin's interface, which is a requirement
/// for plugin installation. This also ensures that plugin interactions cannot
/// happen via the standard execution funtions `execute` and `executeBatch`.
/// Note that the plugins implement BasePlugins cannot be installed when creating an account (aka installed in the
/// account constructor) unless onInstall is overriden without checking codesize of caller (account). Checking
/// codesize of account is to prevent EOA from accidentally calling plugin and initiate states which will make it
/// unusable in the future when EOA can be upgraded into an smart contract account.
abstract contract BasePlugin is ERC165, IPlugin {
    error AlreadyInitialized();
    error InvalidAction();
    error NotImplemented();
    error NotContractCaller();
    error NotInitialized();

    modifier isNotInitialized(address account) {
        if (_isInitialized(account)) {
            revert AlreadyInitialized();
        }
        _;
    }

    modifier isInitialized(address account) {
        if (!_isInitialized(account)) {
            revert NotInitialized();
        }
        _;
    }

    modifier staysInitialized(address account) {
        if (!_isInitialized(account)) {
            revert NotInitialized();
        }
        _;
        if (!_isInitialized(account)) {
            revert InvalidAction();
        }
    }

    /// @notice Initialize plugin data for the modular account.
    /// @dev Called by the modular account during `installPlugin`.
    /// @param data Optional bytes array to be decoded and used by the plugin to setup initial plugin data for the
    /// modular account.
    function onInstall(bytes calldata data) external virtual {
        if (msg.sender.code.length == 0) {
            revert NotContractCaller();
        }
        _onInstall(data);
    }

    /// @notice Clear plugin data for the modular account.
    /// @dev Called by the modular account during `uninstallPlugin`.
    /// @param data Optional bytes array to be decoded and used by the plugin to clear plugin data for the modular
    /// account.
    function onUninstall(bytes calldata data) external virtual {
        (data);
        revert NotImplemented();
    }

    /// @notice Run the pre user operation validation hook specified by the `functionId`.
    /// @dev Pre user operation validation hooks MUST NOT return an authorizer value other than 0 or 1.
    /// @param functionId An identifier that routes the call to different internal implementations, should there be
    /// more than one.
    /// @param userOp The user operation.
    /// @param userOpHash The user operation hash.
    /// @return Packed validation data for validAfter (6 bytes), validUntil (6 bytes), and authorizer (20 bytes).
    function preUserOpValidationHook(uint8 functionId, UserOperation calldata userOp, bytes32 userOpHash)
        external
        virtual
        returns (uint256)
    {
        (functionId, userOp, userOpHash);
        revert NotImplemented();
    }

    /// @notice Run the user operation validationFunction specified by the `functionId`.
    /// @param functionId An identifier that routes the call to different internal implementations, should there be
    /// more than one.
    /// @param userOp The user operation.
    /// @param userOpHash The user operation hash.
    /// @return Packed validation data for validAfter (6 bytes), validUntil (6 bytes), and authorizer (20 bytes).
    function userOpValidationFunction(uint8 functionId, UserOperation calldata userOp, bytes32 userOpHash)
        external
        virtual
        returns (uint256)
    {
        (functionId, userOp, userOpHash);
        revert NotImplemented();
    }

    /// @notice Run the pre runtime validation hook specified by the `functionId`.
    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param functionId An identifier that routes the call to different internal implementations, should there be
    /// more than one.
    /// @param sender The caller address.
    /// @param value The call value.
    /// @param data The calldata sent.
    function preRuntimeValidationHook(uint8 functionId, address sender, uint256 value, bytes calldata data)
        external
        virtual
    {
        (functionId, sender, value, data);
        revert NotImplemented();
    }

    /// @notice Run the runtime validationFunction specified by the `functionId`.
    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param functionId An identifier that routes the call to different internal implementations, should there be
    /// more than one.
    /// @param sender The caller address.
    /// @param value The call value.
    /// @param data The calldata sent.
    function runtimeValidationFunction(uint8 functionId, address sender, uint256 value, bytes calldata data)
        external
        virtual
    {
        (functionId, sender, value, data);
        revert NotImplemented();
    }

    /// @notice Run the pre execution hook specified by the `functionId`.
    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param functionId An identifier that routes the call to different internal implementations, should there be
    /// more than one.
    /// @param sender The caller address.
    /// @param value The call value.
    /// @param data The calldata sent.
    /// @return Context to pass to a post execution hook, if present. An empty bytes array MAY be returned.
    function preExecutionHook(uint8 functionId, address sender, uint256 value, bytes calldata data)
        external
        virtual
        returns (bytes memory)
    {
        (functionId, sender, value, data);
        revert NotImplemented();
    }

    /// @notice Run the post execution hook specified by the `functionId`.
    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param functionId An identifier that routes the call to different internal implementations, should there be
    /// more than one.
    /// @param preExecHookData The context returned by its associated pre execution hook.
    function postExecutionHook(uint8 functionId, bytes calldata preExecHookData) external virtual {
        (functionId, preExecHookData);
        revert NotImplemented();
    }

    /// @notice A hook that runs when a hook this plugin owns is installed onto another plugin
    /// @dev Optional, use to implement any required setup logic
    /// @param pluginAppliedOn The plugin that the hook is being applied on
    /// @param injectedHooksInfo Contains pre/post exec hook information
    /// @param data Any optional data for setup
    function onHookApply(
        address pluginAppliedOn,
        IPluginManager.InjectedHooksInfo calldata injectedHooksInfo,
        bytes calldata data
    ) external virtual {
        (pluginAppliedOn, injectedHooksInfo, data);
    }

    /// @notice A hook that runs when a hook this plugin owns is unapplied from another plugin
    /// @dev Optional, use to implement any required unapplied logic
    /// @param pluginAppliedOn The plugin that the hook was applied on
    /// @param injectedHooksInfo Contains pre/post exec hook information
    /// @param data Any optional data for the unapplied call
    function onHookUnapply(
        address pluginAppliedOn,
        IPluginManager.InjectedHooksInfo calldata injectedHooksInfo,
        bytes calldata data
    ) external virtual {
        (pluginAppliedOn, injectedHooksInfo, data);
    }

    /// @notice Describe the contents and intended configuration of the plugin.
    /// @dev This manifest MUST stay constant over time.
    /// @return A manifest describing the contents and intended configuration of the plugin.
    function pluginManifest() external pure virtual returns (PluginManifest memory) {
        revert NotImplemented();
    }

    /// @notice Describe the metadata of the plugin.
    /// @dev This metadata MUST stay constant over time.
    /// @return A metadata struct describing the plugin.
    function pluginMetadata() external pure virtual returns (PluginMetadata memory);

    /// @dev Returns true if this contract implements the interface defined by
    /// `interfaceId`. See the corresponding
    /// https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
    /// to learn more about how these ids are created.
    ///
    /// This function call must use less than 30 000 gas.
    ///
    /// Supporting the IPlugin interface is a requirement for plugin installation. This is also used
    /// by the modular account to prevent standard execution functions `execute` and `executeBatch` from
    /// making calls to plugins.
    /// @param interfaceId The interface ID to check for support.
    /// @return True if the contract supports `interfaceId`.
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IPlugin).interfaceId || super.supportsInterface(interfaceId);
    }

    /// @notice Initialize plugin data for the modular account.
    /// @dev Called by the modular account during `installPlugin`.
    /// @param data Optional bytes array to be decoded and used by the plugin to setup initial plugin data for the
    /// modular account.
    function _onInstall(bytes calldata data) internal virtual {
        (data);
        revert NotImplemented();
    }

    /// @notice Check if the account has initialized this plugin yet
    /// @dev This function should be overwritten for plugins that have state-changing onInstall's
    /// @param account The account to check
    /// @return True if the account has initialized this plugin
    // solhint-disable-next-line no-empty-blocks
    function _isInitialized(address account) internal view virtual returns (bool) {}
}
