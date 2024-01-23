// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.22;

struct Call {
    // The target address for account to call.
    address target;
    // The value sent with the call.
    uint256 value;
    // The call data for the call.
    bytes data;
}

/// @title Standard Executor Interface
interface IStandardExecutor {
    /// @notice Standard execute method.
    /// @dev If the target is a plugin, the call SHOULD revert.
    /// @param target The target address for account to call.
    /// @param value The value sent with the call.
    /// @param data The call data for the call.
    /// @return The return data from the call.
    function execute(address target, uint256 value, bytes calldata data) external payable returns (bytes memory);

    /// @notice Standard executeBatch method.
    /// @dev If the target is a plugin, the call SHOULD revert. If any of the transactions revert, the entire batch
    /// reverts
    /// @param calls The array of calls.
    /// @return An array containing the return data from the calls.
    function executeBatch(Call[] calldata calls) external payable returns (bytes[] memory);
}
