// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {UserOperation} from "./UserOperation.sol";

/// @notice Interface for the ERC-4337 aggregator
interface IAggregator {
    function validateSignatures(UserOperation[] calldata, bytes calldata) external view;
    function validateUserOpSignature(UserOperation calldata) external view returns (bytes memory);
    function aggregateSignatures(UserOperation[] calldata) external view returns (bytes memory);
}
