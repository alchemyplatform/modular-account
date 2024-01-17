// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {ISessionKeyPermissionsPlugin} from "./ISessionKeyPermissionsPlugin.sol";

/// @notice This interface defines the functions that may be used to update a session key's permissions.
/// The functions defined here are not actually implemented, but instead are abi-encoded as arguments to the
/// update function `updateKeyPermissions`.
interface ISessionKeyPermissionsUpdates {
    /// @notice Update the session key's "access control type". The access control type determines whether the list
    /// is treated as an allowlist, denylist, or if the listis ignored. Note that if the list type is changed, the
    /// previous elements from the list are not cleared, and instead reinterpretted as entries in the new list
    /// type.
    /// @param contractAccessControlType The new access control type.
    function setAccessListType(ISessionKeyPermissionsPlugin.ContractAccessControlType contractAccessControlType)
        external;

    /// @notice Add or remove a contract address from the access list, optionally specifying whether to check
    /// selectors.
    /// @param contractAddress The contract address to add or remove.
    /// @param isOnList Whether the contract address should be on the list.
    /// @param checkSelectors Whether to check selectors for the contract address.
    function updateAccessListAddressEntry(address contractAddress, bool isOnList, bool checkSelectors) external;

    /// @notice Add or remove a function selector from the access list.
    /// @param contractAddress The contract address to add or remove.
    /// @param selector The function selector to add or remove.
    /// @param isOnList Whether the function selector should be on the list.
    function updateAccessListFunctionEntry(address contractAddress, bytes4 selector, bool isOnList) external;

    /// @notice Sets the time range for a session key.
    /// @param validAfter The time after which the session key may be used.
    /// @param validUntil The time before which the session key may be used.
    function updateTimeRange(uint48 validAfter, uint48 validUntil) external;

    /// @notice Sets the native token spend limit for a session key. This specifies how much of the native token
    /// the session key may use, optionally with a refresh interval that specifies how often the limit is reset.
    /// If a refresh interval is already set and a new refresh interval is specified, then any existing interval
    /// spend data will be cleared and a new interval will start.
    /// @param spendLimit The maximum amount of native token the session key may spend.
    /// @param refreshInterval The time interval over which the spend limit is enforced. If zero, there is no time
    /// interval by which the limit is refreshed.
    function setNativeTokenSpendLimit(uint256 spendLimit, uint48 refreshInterval) external;

    /// @notice Sets the ERC-20 spend limit for a session key. This specifies how much of the ERC-20 token the
    /// session key may use, optionally with a refresh interval that specifies how often the limit is reset. If
    /// a refresh interval is already set and a new refresh interval is specified, then any existing interval
    /// spend data will be cleared and a new interval will start.
    /// @param token The ERC-20 token address.
    /// @param spendLimit The maximum amount of the ERC-20 token the session key may spend.
    /// @param refreshInterval The time interval over which the spend limit is enforced. If zero, the spend limit
    /// is never refreshed.
    function setERC20SpendLimit(address token, uint256 spendLimit, uint48 refreshInterval) external;

    /// @notice Sets the gas spend limit for a session key. This specifies how much of the native token the
    /// session key may spend on gas fees, optionally with a refresh interval that specifies how often the limit
    /// is reset. If a refresh interval is already set and a new refresh interval is specified, then any existing
    /// interval spend data will be cleared and a new interval will start. Note that the session key permissions
    /// enforcement will usually overestimate the gas usage per user operation.
    /// @dev If the account is staked, a malicious session key user may abuse gas limits to cause reputation damage
    /// to the account. This is because when a gas limit is set, there are state updates during validation that can
    /// potentially cause future user ops in the same bundle to fail. Intelligent bundlers may re-simulate and
    /// remove the latter ops that exceed the gas limits, but this is not a guarantee.
    /// @param spendLimit The maximum amount of native token the session key may spend on gas. This will always be
    /// the result of an overestimate, however.
    /// @param refreshInterval The time interval by which the spend limit is refreshed. If zero, the spend limit is
    /// never refreshed.
    function setGasSpendLimit(uint256 spendLimit, uint48 refreshInterval) external;

    /// @notice Sets the required paymaster for a session key.
    /// @param requiredPaymaster The required paymaster for the session key. If the rule should be removed, this
    /// should be address(0).
    function setRequiredPaymaster(address requiredPaymaster) external;
}
