// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {Address} from "@openzeppelin/contracts/utils/Address.sol";

import {AccountStorageV1} from "../account/AccountStorageV1.sol";

/// @title Account Storage Initializable
/// @author Alchemy
/// @notice This enables functions that can be called only once per implementation with the same storage layout
/// @dev Adapted from OpenZeppelin's Initializable and modified to use a diamond storage pattern. Removed
/// Initialized() event since the account already emits an event on initialization.
abstract contract AccountStorageInitializable is AccountStorageV1 {
    error AlreadyInitialized();
    error AlreadyInitializing();

    /// @notice Modifier to put on function intended to be called only once per implementation
    /// @dev Reverts if the contract has already been initialized
    modifier initializer() {
        AccountStorage storage storage_ = _getAccountStorage();
        bool isTopLevelCall = !storage_.initializing;
        if (
            isTopLevelCall && storage_.initialized < 1
                || !Address.isContract(address(this)) && storage_.initialized == 1
        ) {
            storage_.initialized = 1;
            if (isTopLevelCall) {
                storage_.initializing = true;
            }
            _;
            if (isTopLevelCall) {
                storage_.initializing = false;
            }
        } else {
            revert AlreadyInitialized();
        }
    }

    /// @notice Internal function to disable calls to initialization functions
    /// @dev Reverts if the contract has already been initialized
    function _disableInitializers() internal virtual {
        AccountStorage storage storage_ = _getAccountStorage();
        if (storage_.initializing) {
            revert AlreadyInitializing();
        }
        if (storage_.initialized != type(uint8).max) {
            storage_.initialized = type(uint8).max;
        }
    }
}
