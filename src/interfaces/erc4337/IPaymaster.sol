// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {UserOperation} from "./UserOperation.sol";

/// @notice Interface for the ERC-4337 paymaster
interface IPaymaster {
    enum PostOpMode {
        opSucceeded,
        opReverted,
        postOpReverted
    }

    function validatePaymasterUserOp(UserOperation calldata, bytes32, uint256)
        external
        returns (bytes memory, uint256);

    function postOp(PostOpMode, bytes calldata, uint256) external;
}
