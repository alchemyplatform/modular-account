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

pragma solidity ^0.8.28;

/// @title IERC7821
/// @notice Minimal Batch Executor Interface (ERC-7821)
interface IERC7821 {
    /// @dev Executes the calls in `executionData`.
    /// Reverts and bubbles up error if any call fails.
    /// @param mode The execution mode, encoded as a bytes32.
    /// @param executionData The ABI-encoded batch call data.
    function execute(bytes32 mode, bytes calldata executionData) external payable;

    /// @dev Returns whether the execution mode is supported.
    /// @param mode The execution mode to check.
    /// @return Whether the mode is supported.
    function supportsExecutionMode(bytes32 mode) external view returns (bool);
}
