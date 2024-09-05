// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {AccountStorage, getAccountStorage} from "./AccountStorage.sol";

/// @title AccountStorageInitializable
/// @dev Bulk of the impl is lifted from OZ 5.0 Initializible
abstract contract AccountStorageInitializable {
    /**
     * @dev Triggered when the contract has been initialized or reinitialized.
     */
    event Initialized(uint64 version);

    /**
     * @dev The contract is already initialized.
     */
    error InvalidInitialization();

    /**
     * @dev The contract is not initializing.
     */
    error NotInitializing();

    /// @notice Modifier to put on function intended to be called only once per implementation
    /// @dev Reverts if the contract has already been initialized
    modifier initializer() {
        AccountStorage storage $ = getAccountStorage();

        // Cache values to avoid duplicated sloads
        bool isTopLevelCall = !$.initializing;
        uint64 initialized = $.initialized;

        // Allowed calls:
        // - initialSetup: the contract is not in the initializing state and no previous version was
        //                 initialized
        // - construction: the contract is initialized at version 1 (no reininitialization) and the
        //                 current contract is just being deployed
        bool initialSetup = initialized == 0 && isTopLevelCall;
        bool construction = initialized == 1 && address(this).code.length == 0;

        if (!initialSetup && !construction) {
            revert InvalidInitialization();
        }
        $.initialized = 1;
        if (isTopLevelCall) {
            $.initializing = true;
        }
        _;
        if (isTopLevelCall) {
            $.initializing = false;
            emit Initialized(1);
        }
    }

    /// @notice Internal function to disable calls to initialization functions
    /// @dev Reverts if the contract has already been initialized
    function _disableInitializers() internal virtual {
        AccountStorage storage $ = getAccountStorage();
        if ($.initializing) {
            revert InvalidInitialization();
        }
        if ($.initialized != type(uint8).max) {
            $.initialized = type(uint8).max;
            emit Initialized(type(uint8).max);
        }
    }
}
