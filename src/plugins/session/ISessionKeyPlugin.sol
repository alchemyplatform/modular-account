// This file is part of Modular Account.
//
// Copyright 2024 Alchemy Insights, Inc.
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General
// Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.22;

import {UserOperation} from "../../interfaces/erc4337/UserOperation.sol";
import {Call} from "../../interfaces/IStandardExecutor.sol";

interface ISessionKeyPlugin {
    enum FunctionId {
        USER_OP_VALIDATION_SESSION_KEY
    }

    // Valid access control types for contract access control lists.
    enum ContractAccessControlType {
        // Allowlist is default
        ALLOWLIST,
        DENYLIST,
        // Disables contract access control
        ALLOW_ALL_ACCESS
    }

    // Struct returned by view functions to provide information about a session key's spend limit.
    // Used for native token, ERC-20, and gas spend limits.
    struct SpendLimitInfo {
        bool hasLimit;
        uint256 limit;
        uint256 limitUsed;
        uint48 refreshInterval;
        uint48 lastUsedTime;
    }

    /// @notice Emitted when a session key is added.
    /// @param account The account that owns the session key.
    /// @param sessionKey The session key that was added.
    /// @param tag The tag that was associated with the key.
    event SessionKeyAdded(address indexed account, address indexed sessionKey, bytes32 indexed tag);

    /// @notice Emitted when a session key is removed.
    /// @param account The account that owns the session key.
    /// @param sessionKey The session key that was removed.
    event SessionKeyRemoved(address indexed account, address indexed sessionKey);

    /// @notice Emitted when a session key is rotated, which replaces a key while keeping the same permissions.
    /// @dev Rotating a key into itself is possible, and does not change the key's permissions.
    /// @param account The account that owns the session key.
    /// @param oldSessionKey The session key that was rotated away.
    /// @param newSessionKey The session key that was rotated to.
    event SessionKeyRotated(address indexed account, address indexed oldSessionKey, address indexed newSessionKey);

    /// @notice Emitted when a session key's permissions are updated.
    /// @param account The account that owns the session key.
    /// @param sessionKey The session key that was updated.
    /// @param updates The updates that were performed. Updates are ABI-encoded calls to the functions defined in
    /// `ISessionKeyPermissionsUpdates`, and are not external functions implemented by this contract.
    event PermissionsUpdated(address indexed account, address indexed sessionKey, bytes[] updates);

    error ERC20SpendLimitExceeded(address account, address sessionKey, address token);
    error InvalidPermissionsUpdate(bytes4 updateSelector);
    error InvalidSessionKey(address sessionKey);
    error InvalidSignature(address sessionKey);
    error InvalidToken(address token);
    error LengthMismatch();
    error NativeTokenSpendLimitExceeded(address account, address sessionKey);
    error PermissionsCheckFailed();
    error SessionKeyNotFound(address sessionKey);

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @notice Perform a batch execution with a session key.
    /// @dev The session key address is included as a parameter so context may be preserved across validation and
    /// execution.
    /// @param calls The array of calls to be performed.
    /// @param sessionKey The session key to be used for the execution.
    /// @return The array of return data from the executions.
    function executeWithSessionKey(Call[] calldata calls, address sessionKey) external returns (bytes[] memory);

    /// @notice Add a session key.
    /// @param sessionKey The session key to register.
    /// @param tag An optional tag that can be used to identify the key.
    /// @param permissionUpdates The initial permission updates to apply to the key.
    function addSessionKey(address sessionKey, bytes32 tag, bytes[] calldata permissionUpdates) external;

    /// @notice Remove a session key.
    /// @param sessionKey The session key to remove.
    /// @param predecessor The list predecessor of the key, as returned by `findPredecessor`.
    function removeSessionKey(address sessionKey, bytes32 predecessor) external;

    /// @notice Move a session key's registration status and existing permissions to another session key.
    /// @param oldSessionKey The session key to move.
    /// @param predecessor The list predecessor of the old session key, as returned by `findPredecessor`.
    /// @param newSessionKey The session key to move to.
    function rotateSessionKey(address oldSessionKey, bytes32 predecessor, address newSessionKey) external;

    /// @notice Performs a sequence of updates to a session key's permissions. These updates are abi-encoded calls
    /// to the functions defined in `ISessionKeyPermissionsUpdates`, and are not external functions implemented by
    /// this contract.
    /// @param sessionKey The session key for which to update permissions.
    /// @param updates The abi-encoded updates to perform.
    function updateKeyPermissions(address sessionKey, bytes[] calldata updates) external;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin only state updating functions       ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @notice An externally available function, callable by anyone, that resets the "last used" timestamp on a
    /// session key. This helps a session key get "unstuck" if it was used in a setting where every call it made
    /// while using a new interval's gas limit reverted. Since this plugin internally tracks when that reset should
    /// happen, this function does not need other validation.
    /// @param account The account that owns the session key.
    /// @param sessionKey The session key to reset.
    function resetSessionKeyGasLimitTimestamp(address account, address sessionKey) external;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin only view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @notice Get the session keys of the account.
    /// This function is not added to accounts during installation.
    /// @param account The account to get the session keys of.
    /// @return The array of session keys of the account.
    function sessionKeysOf(address account) external view returns (address[] memory);

    /// @notice Check if a session key is a session key of the account.
    /// This function is not added to accounts during installation.
    /// @param account The account to check.
    /// @param sessionKey The session key to check.
    /// @return The boolean whether the session key is a session key of the account.
    function isSessionKeyOf(address account, address sessionKey) external view returns (bool);

    /// @notice Get the list predecessor of a session key. This is used as an extra parameter to make removing
    /// session keys more efficient.
    /// This function is not added to accounts during installation.
    /// @param account The account to check.
    /// @param sessionKey The session key to check.
    /// @return The list predecessor of the session key.
    function findPredecessor(address account, address sessionKey) external view returns (bytes32);

    /// @notice Get the access control type for a session key on an account.
    /// @param account The account to check.
    /// @param sessionKey The session key to check.
    /// @return The access control type for the session key on the account.
    function getAccessControlType(address account, address sessionKey)
        external
        view
        returns (ContractAccessControlType);

    /// @notice Get an access control entry for a session key on an account.
    /// @param account The account to check.
    /// @param sessionKey The session key to check.
    /// @param targetAddress The target address to check.
    /// @return isOnList Whether the target address is on the list (either allowlist or blocklist depending on the
    /// access control type).
    /// @return checkSelectors Whether the target address should be checked for selectors during permissions
    /// enforcement.
    function getAccessControlEntry(address account, address sessionKey, address targetAddress)
        external
        view
        returns (bool isOnList, bool checkSelectors);

    /// @notice Get whether a selector is on the access control list for a session key on an account.
    /// @param account The account to check.
    /// @param sessionKey The session key to check.
    /// @param targetAddress The target address to check.
    /// @param selector The selector to check.
    /// @return isOnList Whether the selector is on the list (either allowlist or blocklist depending on the
    /// access control type).
    function isSelectorOnAccessControlList(
        address account,
        address sessionKey,
        address targetAddress,
        bytes4 selector
    ) external view returns (bool isOnList);

    /// @notice Get the active time range for a session key on an account.
    /// @param account The account to check.
    /// @param sessionKey The session key to check.
    /// @return validAfter The time after which the session key is valid.
    /// @return validUntil The time until which the session key is valid.
    function getKeyTimeRange(address account, address sessionKey)
        external
        view
        returns (uint48 validAfter, uint48 validUntil);

    /// @notice Get the native token spend limit for a session key on an account.
    /// @param account The account to check.
    /// @param sessionKey The session key to check.
    /// @return A struct with fields describing the state of native token spending limits on this session key.
    function getNativeTokenSpendLimitInfo(address account, address sessionKey)
        external
        view
        returns (SpendLimitInfo memory);

    /// @notice Get the gas spend limit for a session key on an account.
    /// @param account The account to check.
    /// @param sessionKey The session key to check.
    /// @return info A struct with fields describing the state of gas spending limits on this session key.
    /// @return shouldReset Whether this session key must be reset by calling `resetSessionKeyGasLimitTimestamp`
    /// before it can be used.
    function getGasSpendLimit(address account, address sessionKey)
        external
        view
        returns (SpendLimitInfo memory info, bool shouldReset);

    /// @notice Get the ERC20 spend limit for a session key on an account.
    /// @param account The account to check.
    /// @param sessionKey The session key to check.
    /// @param token The token to check.
    /// @return A struct with fields describing the state of ERC20 spending limits on this session key.
    function getERC20SpendLimitInfo(address account, address sessionKey, address token)
        external
        view
        returns (SpendLimitInfo memory);

    /// @notice Get the required paymaster address for a session key on an account, if any.
    /// @param account The account to check.
    /// @param sessionKey The session key to check.
    /// @return The required paymaster address for this session key on this account, or the zero address if the
    /// rule is disabled.
    function getRequiredPaymaster(address account, address sessionKey) external view returns (address);
}
