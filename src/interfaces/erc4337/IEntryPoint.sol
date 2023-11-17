// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {UserOperation} from "./UserOperation.sol";

/// @notice Interface for the ERC-4337 entry point
interface IEntryPoint {
    error FailedOp(uint256 i, string s);

    function depositTo(address) external payable;
    function addStake(uint32) external payable;
    function unlockStake() external;
    function withdrawStake(address payable) external;
    function handleOps(UserOperation[] calldata, address payable) external;
    function getNonce(address, uint192) external view returns (uint256);
    function getUserOpHash(UserOperation calldata) external view returns (bytes32);
}
