// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {IAccount} from "@eth-infinitism/account-abstraction/interfaces/IAccount.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

/// @title Account Base
/// @author Alchemy
/// @dev An optimized implementation of a base account contract for ERC-4337.
/// Provides a public view function for getting the EntryPoint address, but does not provide one for getting the
/// nonce. The nonce may be retrieved from the EntryPoint contract.
/// Implementing contracts should override the _validateUserOp function to provide account-specific validation
/// logic.
abstract contract AccountBase is IAccount {
    IEntryPoint internal immutable _ENTRY_POINT;

    error NotEntryPoint();

    constructor(IEntryPoint _entryPoint) {
        _ENTRY_POINT = _entryPoint;
    }

    /// @inheritdoc IAccount
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        override
        returns (uint256 validationData)
    {
        _requireFromEntryPoint();

        validationData = _validateUserOp(userOp, userOpHash);

        // Pay the prefund if necessary.
        assembly ("memory-safe") {
            if missingAccountFunds {
                // Ignore failure (it's EntryPoint's job to verify, not the account's).
                pop(call(gas(), caller(), missingAccountFunds, codesize(), 0x00, codesize(), 0x00))
            }
        }
    }

    /// @notice Gets the entry point for this account
    /// @return entryPoint The entry point for this account
    function entryPoint() external view returns (IEntryPoint) {
        return _ENTRY_POINT;
    }

    /// @notice Account-specific implementation of user op validation. Override this function to define the
    /// account's validation logic.
    function _validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        returns (uint256 validationData);

    /// @notice Revert if the sender is not the EntryPoint.
    function _requireFromEntryPoint() internal view {
        if (msg.sender != address(_ENTRY_POINT)) {
            revert NotEntryPoint();
        }
    }
}
