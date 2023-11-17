// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

/// @title Plugin Executor Interface
interface IPluginExecutor {
    /// @notice Method from cals made from plugins to other plugin execution functions. Plugins are not allowed to
    /// call accounts native functions.
    /// @dev Permissions must be granted to the calling plugin for the call to go through
    /// @param data The call data for the call.
    /// @return The return data from the call.
    function executeFromPlugin(bytes calldata data) external payable returns (bytes memory);

    /// @notice Method from calls made from plugins to external addresses.
    /// @dev If the target is a plugin, the call SHOULD revert. Permissions must be granted to the calling plugin
    /// for the call to go through
    /// @param target The address to be called.
    /// @param value The value to pass.
    /// @param data The data to pass.
    /// @return The result of the call
    function executeFromPluginExternal(address target, uint256 value, bytes calldata data)
        external
        payable
        returns (bytes memory);
}
