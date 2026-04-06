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

import {Call} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

interface IModularAccountBase {
    /// @notice Emitted when executeWithPreCalls completes. Always emitted regardless of whether calls succeeded.
    /// @param success Whether the calls batch succeeded.
    /// @param results The return data from the calls batch, empty if calls reverted.
    event ExecuteWithPreCallsResult(bool indexed success, bytes[] results);

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

    /// @notice Execute a two-phase batch: preCalls must all succeed (or the entire call reverts), then calls are
    /// executed atomically — if any call in the calls batch fails, the calls batch reverts but the overall
    /// function still succeeds. An event is emitted with the result.
    /// @param preCalls The array of calls that must succeed. Reverts if any fail.
    /// @param calls The array of calls to attempt. Failures are caught and reported via event.
    /// @return success Whether the calls batch succeeded.
    /// @return results The return data from the calls batch, empty if calls reverted.
    function executeWithPreCalls(Call[] calldata preCalls, Call[] calldata calls)
        external
        payable
        returns (bool success, bytes[] memory results);
}
