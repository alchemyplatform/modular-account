// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Call} from "../../interfaces/IStandardExecutor.sol";
import {UserOperation} from "../../interfaces/erc4337/UserOperation.sol";

interface ISessionKeyPlugin {
    enum FunctionId {
        USER_OP_VALIDATION_SESSION_KEY
    }

    error InvalidSessionKey(address sessionKey);
    error NotAuthorized(address caller);
    error SessionKeyNotFound(address sessionKey);
    error UnableToRemove(address sessionKey);

    struct SessionKeyToRemove {
        address sessionKey;
        bytes32 predecessor;
    }

    /// @notice Perform a batch execution with a session key.
    /// @dev The session key address is included as a parameter so context may be preserved across validation and
    /// execution.
    /// @param calls The array of calls to be performed.
    /// @param sessionKey The session key to be used for the execution.
    /// @return The array of return data from the executions.
    function executeWithSessionKey(Call[] calldata calls, address sessionKey) external returns (bytes[] memory);

    /// @notice Get the session keys of the account.
    /// @return The array of session keys of the account.
    function getSessionKeys() external view returns (address[] memory);

    /// @notice Check if a session key is a session key of the account.
    /// @param sessionKey The session key to check.
    /// @return The boolean whether the session key is a session key of the account.
    function isSessionKey(address sessionKey) external view returns (bool);

    /// @notice Add and remove session keys from the account.
    /// Note that the session keys to remove will be removed prior to any being added, and they will be removed in
    /// order from first to last. If the predecessor changes due to a prior removal, the caller should pass in the
    /// updated predecessor.
    /// @param sessionKeysToAdd The array of session keys to add to the account.
    /// @param sessionKeysToRemove The array of session keys to remove from the account, along with their
    /// predecessor in the list.
    function updateSessionKeys(
        address[] calldata sessionKeysToAdd,
        SessionKeyToRemove[] calldata sessionKeysToRemove
    ) external;

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
}
