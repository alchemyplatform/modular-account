// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {UserOperation} from "../../../interfaces/erc4337/UserOperation.sol";

interface ISessionKeyPermissionsPlugin {
    enum FunctionId {
        PRE_USER_OP_VALIDATION_HOOK_CHECK_PERMISSIONS,
        PRE_EXECUTION_HOOK_UPDATE_LIMITS
    }

    enum ContractAccessControlType {
        ALLOWLIST, // Allowlist is default
        DENYLIST,
        NONE
    }

    struct SpendLimitInfo {
        bool hasLimit;
        uint256 limit;
        uint256 limitUsed;
        uint48 refreshInterval;
        uint48 lastUsedTime;
    }

    /// @notice Emitted when a session key is registered.
    /// @param account The account that owns the session key.
    /// @param sessionKey The session key that was registered.
    /// @param tag The tag that was associated with the key.
    event KeyRegistered(address indexed account, address indexed sessionKey, bytes32 indexed tag);

    /// @notice Emitted when a session key's permissions are updated.
    /// @param account The account that owns the session key.
    /// @param sessionKey The session key that was updated.
    /// @param updates The updates that were performed. Updates are ABI-encoded
    event PermissionsUpdated(address indexed account, address indexed sessionKey, bytes[] updates);

    /// @notice Emitted when a session key is rotated, which transfers permissions from one key to another.
    /// @param account The account that owns the session key.
    /// @param oldSessionKey The session key that was rotated away.
    /// @param newSessionKey The session key that was rotated to.
    event KeyRotated(address indexed account, address indexed oldSessionKey, address indexed newSessionKey);

    error ERC20SpendLimitExceeded(address account, address sessionKey, address token);
    error KeyAlreadyRegistered(address sessionKey);
    error KeyNotRegistered(address sessionKey);
    error InvalidPermissionsUpdate();
    error InvalidToken();
    error NativeTokenSpendLimitExceeded(address account, address sessionKey);

    /// @notice Register a key with the permissions plugin. Without this step, key cannot be used while the
    /// permissions plugin is installed.
    /// @param sessionKey The session key to register.
    /// @param tag An optional tag that can be used to identify the key.
    function registerKey(address sessionKey, bytes32 tag) external;

    /// @notice Move a session key's registration status and existing permissions to another session key.
    /// @param oldSessionKey The session key to move.
    /// @param newSessionKey The session key to move to.
    function rotateKey(address oldSessionKey, address newSessionKey) external;

    /// @notice Performs a sequence of updates to a session key's permissions. These updates are abi-encoded calls
    /// to the functions defined in `ISessionKeyPermissionsUpdates`, and are not external functions implemented by
    /// this contract.
    /// @param sessionKey The session key for which to update permissions.
    /// @param updates The abi-encoded updates to perform.
    function updateKeyPermissions(address sessionKey, bytes[] calldata updates) external;

    /// @notice An externally available function, callable by anyone, that resets the "last used" timestamp on a
    /// session key. This helps a session key get "unstuck" if it was used in a setting where every call it made
    /// while using a new interval's gas limit reverted. Since this plugin internally tracks when that reset should
    /// happen, this function does not need other validation.
    /// @param account The account that owns the session key.
    /// @param sessionKey The session key to reset.
    function resetSessionKeyGasLimitTimestamp(address account, address sessionKey) external;

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
