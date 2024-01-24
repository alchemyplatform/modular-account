// This work is marked with CC0 1.0 Universal.
//
// SPDX-License-Identifier: CC0-1.0
//
// To view a copy of this license, visit http://creativecommons.org/publicdomain/zero/1.0

pragma solidity ^0.8.22;

import {UserOperation} from "./UserOperation.sol";

/// @notice Interface for the ERC-4337 aggregator
interface IAggregator {
    function validateSignatures(UserOperation[] calldata, bytes calldata) external view;
    function validateUserOpSignature(UserOperation calldata) external view returns (bytes memory);
    function aggregateSignatures(UserOperation[] calldata) external view returns (bytes memory);
}
