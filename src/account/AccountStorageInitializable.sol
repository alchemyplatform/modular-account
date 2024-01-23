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
