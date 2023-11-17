// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {IEntryPoint} from "./erc4337/IEntryPoint.sol";

/// @title Account View Interface
interface IAccountView {
    /// @notice Gets the entry point for this account
    /// @return entryPoint The entry point for this account
    function entryPoint() external view returns (IEntryPoint);

    /// @notice Get the account nonce.
    /// @dev uses key 0
    /// @return nonce The next account nonce.
    function getNonce() external view returns (uint256);
}
