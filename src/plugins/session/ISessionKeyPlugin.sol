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

import {UserOperation} from "../../interfaces/erc4337/UserOperation.sol";
import {Call} from "../../interfaces/IStandardExecutor.sol";

interface ISessionKeyPlugin {
    enum FunctionId {
        USER_OP_VALIDATION_SESSION_KEY
    }

    // Valid access control types for contract access control lists.
    enum ContractAccessControlType {
        // Allowlist is default
        ALLOWLIST,
        DENYLIST,
        // Disables contract access control
        ALLOW_ALL_ACCESS
    }

    // Struct returned by view functions to provide information about a session key's spend limit.
    // Used for native token, ERC-20, and gas spend limits.
    struct SpendLimitInfo {
        bool hasLimit;
        uint256 limit;
        uint256 limitUsed;
        uint48 refreshInterval;
        uint48 lastUsedTime;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @notice Perform a batch execution with a session key.
    /// @dev The session key address is included as a parameter so context may be preserved across validation and
    /// execution.
    /// @param calls The array of calls to be performed.
    /// @param sessionKey The session key to be used for the execution.
    /// @return The array of return data from the executions.
    function executeWithSessionKey(Call[] calldata calls, address sessionKey) external returns (bytes[] memory);

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin only state updating functions       ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin only view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
}
