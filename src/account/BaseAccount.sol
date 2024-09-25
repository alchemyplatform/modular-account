// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {IAccount} from "@eth-infinitism/account-abstraction/interfaces/IAccount.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

/// @dev An optimized implementation of a base account contract for ERC-4337.
/// Provides a public view function for getting the EntryPoint address, but does not provide one for getting the
/// nonce. The nonce may be retrieved from the EntryPoint contract.
/// Implementing contracts should override the _validateUserOp function to provide account-specific validation
/// logic.
abstract contract BaseAccount is IAccount {
    error NotEntryPoint();

    /// @inheritdoc IAccount
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        virtual
        override
        returns (uint256 validationData)
    {
        _requireFromEntryPoint();

        validationData = _validateUserOp(userOp, userOpHash);

        // Pay the prefund if necessary.
        // todo: storage-warming optimization if nonzero requiredPrefund
        assembly ("memory-safe") {
            if missingAccountFunds {
                // Ignore failure (it's EntryPoint's job to verify, not the account's).
                pop(call(gas(), caller(), missingAccountFunds, codesize(), 0x00, codesize(), 0x00))
            }
        }
    }

    /// @notice Get the EntryPoint address used by this account.
    /// @return The EntryPoint address.
    function entryPoint() public view virtual returns (IEntryPoint);

    /// @notice Account-specific implementation of user op validation. Override this function to define the
    /// account's validation logic.
    function _validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        returns (uint256 validationData);

    /// @notice Revert if the sender is not the EntryPoint.
    function _requireFromEntryPoint() internal view virtual {
        if (msg.sender != address(entryPoint())) {
            revert NotEntryPoint();
        }
    }
}
