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

import {UserOperation} from "../interfaces/erc4337/UserOperation.sol";
import {IPlugin} from "../interfaces/IPlugin.sol";

/// @title Account Executor
/// @author Alchemy
/// @notice Provides internal functions for executing calls on a modular account.
abstract contract AccountExecutor {
    error PluginCallDenied(address plugin);

    /// @dev If the target is a plugin (as determined by its support for the IPlugin interface), revert.
    /// This prevents the modular account from calling plugins (both installed and uninstalled) outside
    /// of the normal flow (via execution functions installed on the account), which could lead to data
    /// inconsistencies and unexpected behavior.
    /// @param target The address of the contract to call.
    /// @param value The value to send with the call.
    /// @param data The call data.
    /// @return result The return data of the call, or the error message from the call if call reverts.
    function _exec(address target, uint256 value, bytes memory data) internal returns (bytes memory result) {
        if (ERC165Checker.supportsInterface(target, type(IPlugin).interfaceId)) {
            revert PluginCallDenied(target);
        }

        bool success;
        (success, result) = target.call{value: value}(data);

        if (!success) {
            // Directly bubble up revert messages
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /// @dev Performs an `_executeRaw` for a call buffer holding a call to one of:
    /// - Pre Runtime Validation Hook
    /// - Runtime Validation
    /// - Pre Execution Hook
    /// And if it fails, reverts with the appropriate custom error.
    function _executeRuntimePluginFunction(bytes memory buffer, address plugin, bytes4 errorSelector) internal {
        if (!_executeRaw(plugin, buffer)) {
            _revertOnRuntimePluginFunctionFail(buffer, plugin, errorSelector);
        }
    }

    function _executeRaw(address plugin, bytes memory buffer) internal returns (bool success) {
        assembly ("memory-safe") {
            success :=
                call(
                    gas(),
                    plugin,
                    /*value*/
                    0,
                    /*argOffset*/
                    add(buffer, 0x20), // jump over 32 bytes for length
                    /*argSize*/
                    mload(buffer),
                    /*retOffset*/
                    0,
                    /*retSize*/
                    0
                )
        }
    }

    function _executeUserOpPluginFunction(bytes memory buffer, address plugin)
        internal
        returns (uint256 validationData)
    {
        assembly ("memory-safe") {
            switch and(
                gt(returndatasize(), 0x1f),
                call(
                    /*forward all gas, but can't use gas opcode due to validation opcode restrictions*/
                    not(0),
                    plugin,
                    /*value*/
                    0,
                    /*argOffset*/
                    add(buffer, 0x20), // jump over 32 bytes for length
                    /*argSize*/
                    mload(buffer),
                    /*retOffset*/
                    0,
                    /*retSize*/
                    0x20
                )
            )
            case 0 {
                // Bubble up the revert if the call reverts.
                let m := mload(0x40)
                returndatacopy(m, 0x00, returndatasize())
                revert(m, returndatasize())
            }
            default {
                // Otherwise, we return the first word of the return data as the validation data
                validationData := mload(0)
            }
        }
    }

    function _allocateRuntimeCallBuffer(bytes calldata data) internal view returns (bytes memory buffer) {
        buffer = abi.encodeWithSelector(bytes4(0), 0, msg.sender, msg.value, data);
    }

    function _allocateUserOpCallBuffer(bytes4 selector, UserOperation calldata userOp, bytes32 userOpHash)
        internal
        pure
        returns (bytes memory buffer)
    {
        buffer = abi.encodeWithSelector(selector, 0, userOp, userOpHash);
    }

    /// @dev Updates which plugin function the buffer will call.
    function _updatePluginCallBufferSelector(bytes memory buffer, bytes4 pluginSelector) internal pure {
        assembly ("memory-safe") {
            // We only want to write to the first 4 bytes, so we first load the first word,
            // mask out the fist 4 bytes, then OR in the new selector.
            let existingWord := mload(add(buffer, 0x20))
            // Clear the upper 4 bytes of the existing word
            existingWord := shr(32, shl(32, existingWord))
            // Clear the lower 28 bytes of the selector
            pluginSelector := shl(224, shr(224, pluginSelector))
            // OR in the new selector
            existingWord := or(existingWord, pluginSelector)
            mstore(add(buffer, 0x20), existingWord)
        }
    }

    function _updatePluginCallBufferFunctionId(bytes memory buffer, uint8 functionId) internal pure {
        assembly ("memory-safe") {
            // The function ID is a uint8 type, which is left-padded.
            // We do want to mask it, however, because this is an internal function and the upper bits may not be
            // cleared.
            mstore(add(buffer, 0x24), and(functionId, 0xff))
        }
    }

    /// @dev Re-interpret the existing call buffer as just a bytes memory hold msg.data.
    /// Since it's already there, and we don't plan on using the buffer again, we can write over the other fields
    /// to store calldata length before the data, then return a new memory pointer holding the length.
    function _convertRuntimeCallBufferToExecBuffer(bytes memory runtimeCallBuffer)
        internal
        pure
        returns (bytes memory execCallBuffer)
    {
        if (runtimeCallBuffer.length == 0) {
            // There was no existing call buffer. This case is never reached in actual code, but in the event that
            // it would be, we would need to re-collect all the calldata.
            execCallBuffer = msg.data;
        } else {
            assembly ("memory-safe") {
                // Skip forward to point to the new "length-holding" field.
                // Since the existing buffer is already ABI-encoded, we can just skip to the inner callData field.
                // This field is location  bytes ahead. It skips over:
                // - (32 bytes) The original buffer's length field
                // - (4 bytes) Selector
                // - (32 bytes) Function id
                // - (32 bytes) Sender
                // - (32 bytes) Value
                // - (32 bytes) data offset
                // Total: 164 bytes
                execCallBuffer := add(runtimeCallBuffer, 164)
            }
        }
    }

    /// @dev Used by pre exec hooks to store data for post exec hooks.
    function _collectReturnData() internal pure returns (bytes memory returnData) {
        assembly ("memory-safe") {
            // Allocate a buffer of that size, advancing the memory pointer to the nearest word
            returnData := mload(0x40)
            mstore(returnData, returndatasize())
            mstore(0x40, and(add(add(returnData, returndatasize()), 0x3f), not(0x1f)))

            // Copy over the return data
            returndatacopy(add(returnData, 0x20), 0, returndatasize())
        }
    }

    /// @dev This function reverts with one of the following custom error types:
    /// - PreRuntimeValidationHookFailed
    /// - RuntimeValidationFunctionReverted
    /// - PreExecHookReverted
    /// Since they all take the same parameters, we can just switch the selector as needed.
    /// The last parameter, revertReason, is copied from return data.
    function _revertOnRuntimePluginFunctionFail(bytes memory buffer, address plugin, bytes4 errorSelector)
        internal
        pure
    {
        assembly ("memory-safe") {
            // Call failed, revert with the established error format and the provided selector
            // The error format is:
            // - Custom error selector
            // - plugin address
            // - function id
            // - byte offset and length of revert reason
            // - byte memory revertReason
            // Total size: 132 bytes (4 byte selector + 4 * 32 byte words) + length of revert reason
            let errorStart := mload(0x40)
            // We add the extra size for the abi encoded fields at the same time as the selector,
            // which is after the word-alignment step.
            // Pad errorSize to nearest word
            let errorSize := and(add(returndatasize(), 0x1f), not(0x1f))
            // Add the abi-encoded fields length (128 bytes) and the selector's size (4 bytes)
            // to the error size.
            errorSize := add(errorSize, 132)
            // Store the selector in the start of the error buffer.
            // Any set lower bits will be cleared with the subsequest mstore.
            mstore(errorStart, errorSelector)
            mstore(add(errorStart, 0x04), plugin)
            // Store the function id in the next word, as retrieved from the buffer
            mstore(add(errorStart, 0x24), mload(add(buffer, 0x24)))
            // Store the offset and length of the revert reason in the next two words
            mstore(add(errorStart, 0x44), 0x60)
            mstore(add(errorStart, 0x64), returndatasize())

            // Copy over the revert reason
            returndatacopy(add(errorStart, 0x84), 0, returndatasize())

            // Revert
            revert(errorStart, errorSize)
        }
    }
}
