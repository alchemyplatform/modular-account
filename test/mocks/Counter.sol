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

pragma solidity ^0.8.26;

/// @title A public counter for anyone to use.
contract Counter {
    uint256 public number;

    /// @notice Set the counter's number to a new value.
    /// @param newNumber The new number for the counter.
    function setNumber(uint256 newNumber) public {
        number = newNumber;
    }

    /// @notice Increase the counter's value by one.
    /// @dev The number is not in an unchecked block, so overflows will revert.
    function increment() public {
        number++;
    }

    /// @notice Decrement the counter's value by one.
    /// @dev The number is not in an unchecked block, so overflows will revert.
    function decrement() public {
        number--;
    }
}
