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

library FactoryHelpers {
    /// @dev The owner array must be in strictly ascending order and not include the 0 address.
    /// @param owners encoded bytes array of owner addresses
    /// @return bool if the owners array is valid
    function isValidOwnerArray(address[] calldata owners) internal pure returns (bool) {
        address currentOwnerValue;
        for (uint256 i = 0; i < owners.length; ++i) {
            if (owners[i] <= currentOwnerValue) {
                return false;
            }
            currentOwnerValue = owners[i];
        }
        return true;
    }

    /// @notice Gets this factory's create2 salt based on the input params
    /// @param salt additional entropy for create2
    /// @param owners encoded bytes array of owner addresses
    /// @return combinedSalt of salt and owners
    function getCombinedSalt(uint256 salt, bytes memory owners) internal pure returns (bytes32) {
        return keccak256(abi.encode(salt, owners));
    }
}
