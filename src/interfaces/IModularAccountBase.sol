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

interface IModularAccountBase {
    /// @notice Create a contract.
    /// @param value The value to send to the new contract constructor
    /// @param initCode The initCode to deploy.
    /// @param isCreate2 The bool to indicate which method to use to deploy.
    /// @param salt The salt for deployment.
    /// @return createdAddr The created contract address.
    function performCreate(uint256 value, bytes calldata initCode, bool isCreate2, bytes32 salt)
        external
        payable
        returns (address createdAddr);
}
