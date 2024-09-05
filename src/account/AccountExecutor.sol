// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

abstract contract AccountExecutor {
    /// @param target The address of the contract to call.
    /// @param value The value to send with the call.
    /// @param data The call data.
    /// @return result The return data of the call, or the error message from the call if call reverts.
    function _exec(address target, uint256 value, bytes memory data) internal returns (bytes memory result) {
        bool success;
        (success, result) = target.call{value: value}(data);

        if (!success) {
            // Directly bubble up revert messages
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }
}
