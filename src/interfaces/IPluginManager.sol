// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

type FunctionReference is bytes21;

/// @title Plugin Manager Interface
interface IPluginManager {
    event PluginInstalled(address indexed plugin, bytes32 manifestHash, FunctionReference[] dependencies);
    event PluginUninstalled(address indexed plugin, bool indexed callbacksSucceeded);
    event PluginIgnoredHookUnapplyCallbackFailure(address indexed plugin, address indexed providingPlugin);
    event PluginIgnoredUninstallCallbackFailure(address indexed plugin);

    /// @notice Install a plugin to the modular account.
    /// @param plugin The plugin to install.
    /// @param manifestHash The hash of the plugin manifest.
    /// @param pluginInitData Optional data to be decoded and used by the plugin to setup initial plugin data for
    /// the modular account.
    /// @param dependencies The dependencies of the plugin, as described in the manifest.
    function installPlugin(
        address plugin,
        bytes32 manifestHash,
        bytes calldata pluginInitData,
        FunctionReference[] calldata dependencies
    ) external;

    /// @notice Uninstall a plugin from the modular account.
    /// @dev Uninstalling owner plugins outside of a replace operation via executeBatch risks losing the account!
    /// @param plugin The plugin to uninstall.
    /// @param config An optional, implementation-specific field that accounts may use to ensure consistency
    /// guarantees.
    /// @param pluginUninstallData Optional data to be decoded and used by the plugin to clear plugin data for the
    /// modular account.
    function uninstallPlugin(address plugin, bytes calldata config, bytes calldata pluginUninstallData) external;
}
