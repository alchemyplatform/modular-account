// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

/// @title Account Initializable Interface
/// @author Alchemy
interface IAccountInitializable {
    /// @notice Initializes the account with a set of plugins
    /// @dev No dependencies or hooks can be injected with this installation
    /// @param plugins The plugins to install
    /// @param pluginInitData The plugin init data for each plugin
    function initialize(address[] calldata plugins, bytes calldata pluginInitData) external;
}
