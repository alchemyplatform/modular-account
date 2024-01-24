// This work is marked with CC0 1.0 Universal.
//
// SPDX-License-Identifier: CC0-1.0
//
// To view a copy of this license, visit http://creativecommons.org/publicdomain/zero/1.0

pragma solidity ^0.8.22;

import {IEntryPoint} from "./erc4337/IEntryPoint.sol";

/// @title Account View Interface
interface IAccountView {
    /// @notice Get the entry point for this account.
    /// @return entryPoint The entry point for this account.
    function entryPoint() external view returns (IEntryPoint);

    /// @notice Get the account nonce.
    /// @dev Uses key 0.
    /// @return nonce The next account nonce.
    function getNonce() external view returns (uint256);
}
