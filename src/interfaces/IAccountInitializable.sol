// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.22;

/// @title Account Initializable Interface
interface IAccountInitializable {
    /// @notice Initialize the account with a set of plugins.
    /// @dev No dependencies may be provided with this installation.
    /// @param plugins The plugins to install.
    /// @param pluginInitData The plugin init data for each plugin.
    function initialize(address[] calldata plugins, bytes calldata pluginInitData) external;
}
