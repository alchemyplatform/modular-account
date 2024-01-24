// This work is marked with CC0 1.0 Universal.
//
// SPDX-License-Identifier: CC0-1.0
//
// To view a copy of this license, visit http://creativecommons.org/publicdomain/zero/1.0

pragma solidity ^0.8.22;

import {IEntryPoint} from "./IEntryPoint.sol";
import {UserOperation} from "./UserOperation.sol";

/// @notice Interface for the ERC-4337 account
interface IAccount {
    /// @notice Validates a user operation, presumably by checking the signature and nonce. The entry point will
    /// call this function to ensure that a user operation sent to it has been authorized, and thus that it should
    /// call the account with the operation's call data and charge the account for  gas in the absense of a
    /// paymaster. If the signature is correctly formatted but invalid, this should return 1; other failures may
    /// revert instead. In the case of a success, this can optionally return a signature aggregator and/or a time
    /// range during which the operation is valid.
    /// @param userOp the operation to be validated
    /// @param userOpHash hash of the operation
    /// @param missingAccountFunds amount that the account must send to the entry point as part of validation to
    /// pay for gas
    /// @return validationData Either 1 for an invalid signature, or a packed structure containing an optional
    /// aggregator address in the first 20 bytes followed by two 6-byte timestamps representing the "validUntil"
    /// and "validAfter" times at which the operation is valid (a "validUntil" of 0 means it is valid forever).
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData);
}
