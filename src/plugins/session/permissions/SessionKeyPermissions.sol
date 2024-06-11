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

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {UserOperation} from "../../../interfaces/erc4337/UserOperation.sol";
import {Call} from "../../../interfaces/IStandardExecutor.sol";
import {IStandardExecutor} from "../../../interfaces/IStandardExecutor.sol";
import {SIG_VALIDATION_PASSED, SIG_VALIDATION_FAILED} from "../../../libraries/Constants.sol";
import {ISessionKeyPlugin} from "../ISessionKeyPlugin.sol";
import {ISessionKeyPermissionsUpdates} from "./ISessionKeyPermissionsUpdates.sol";
import {SessionKeyPermissionsBase} from "./SessionKeyPermissionsBase.sol";

/// @title Session Key Permissions
/// @author Alchemy
/// @notice This plugin allows users to configure and enforce permissions on session keys that have been
/// added by SessionKeyPlugin.
abstract contract SessionKeyPermissions is ISessionKeyPlugin, SessionKeyPermissionsBase {
    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Internal / Private functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @dev A check to run during user op validation that checks the permissions of the session key used to
    /// validate the user op. Note that this function does not check ERC-20 spend limits, which are checked
    /// during the execution phase.
    function _checkUserOpPermissions(UserOperation calldata userOp, Call[] memory calls, address sessionKey)
        internal
        returns (uint256)
    {
        // This step does not need to assert that the key id is nonzero, since the user op signature check implies
        // that.
        SessionKeyId keyId = _sessionKeyIdOf(msg.sender, sessionKey);
        SessionKeyData storage sessionKeyData = _sessionKeyDataOf(msg.sender, keyId);

        // The session key's start time is the max of the key-specific validAfter and any time restrictions imposed
        // by spending limits.
        uint48 currentValidAfter = sessionKeyData.validAfter;
        uint48 validUntil = sessionKeyData.validUntil;
        uint256 nativeTokenSpend;

        uint256 callsLength = calls.length;
        // Only return validation success when there is at least one call
        require(callsLength > 0, "Must have at least one call");
        {
            ContractAccessControlType accessControlType = sessionKeyData.contractAccessControlType;
            for (uint256 i = 0; i < callsLength; ++i) {
                Call memory call = calls[i];
                nativeTokenSpend += call.value;
                _checkCallPermissions(accessControlType, keyId, call.target, call.data);
            }
        }

        if (!sessionKeyData.nativeTokenSpendLimitBypassed) {
            uint48 spendLimitValidAfter = _checkSpendLimitUsage(
                nativeTokenSpend,
                sessionKeyData.nativeTokenSpendLimitTimeInfo,
                sessionKeyData.nativeTokenSpendLimit
            );
            currentValidAfter = _max(currentValidAfter, spendLimitValidAfter);
        }

        if (sessionKeyData.hasGasLimit) {
            // Gas limit checking is the only type of permissions checking that has state changes performed during
            // validation. This can potentially cause reputation damage to staked accounts if multiple user
            // operations are accepted into the same bundle, then validation for one of the later operations fails
            // due to the state change from the first. To protect from this, we require session keys to use their
            // own address as the key portion of the user operation nonce field, in order to guarantee that they
            // are used sequentially.
            if (uint192(userOp.nonce >> 64) != uint192(uint160(sessionKey))) {
                revert("Must use session key as key portion of nonce when gas limit checking is enabled");
            }

            // Multiplier for the verification gas limit is 3 if there is a paymaster, 1 otherwise.
            // This is defined in EntryPoint v0.6.0, which uses the limit for the user op validation + paymaster
            // validation, then again for up to two more calls of `postOp`. Later versions of the EntryPoint may
            // change this scale factor or the usage of the verification gas limit, so this value should be checked
            // and updated if porting this plugin to a newer version of 4337.
            uint256 multiplier = userOp.paymasterAndData.length > 0 ? 3 : 1;
            uint256 maxGasFee = (
                userOp.callGasLimit + userOp.verificationGasLimit * multiplier + userOp.preVerificationGas
            ) * userOp.maxFeePerGas;
            (uint48 gasLimitValidAfter) = _checkAndUpdateGasLimitUsage(maxGasFee, sessionKeyData);
            currentValidAfter = _max(currentValidAfter, gasLimitValidAfter);
        }

        if (sessionKeyData.hasRequiredPaymaster) {
            // Technically this following line would right-pad the contents of the paymasterAndData bytes field if
            // it is <20 bytes, which seems like it could cause false positive matches. However, the EntryPoint
            // validates that if the paymasterAndData field is >0 length, then the first 20 bytes must be a valid
            // paymaster address, so this is safe. (It would revert with "AA93 invalid paymasterAndData").
            // Additionally, we don't have to worry about a zero-length paymasterAndData being casted to
            // address(0), because then the subsequent check will fail, as it is impossible to have
            // sessionKeyData.hasRequiredPaymaster == true and a zero address sessionKeyData.requiredPaymaster, by
            // how the rule's updating function works.
            address userOpPaymaster = address(bytes20(userOp.paymasterAndData));
            require(userOpPaymaster == sessionKeyData.requiredPaymaster, "Must use required paymaster");
        }
        // A packed struct of: SIG_VALIDATION_PASSED or SIG_VALIDATION_FAILED, and two
        // 6-byte timestamps indicating the start and end times at which the op is valid.
        return uint160(SIG_VALIDATION_PASSED) | (uint256(validUntil) << 160) | (uint256(currentValidAfter) << 208);
    }

    /// @dev Checks permissions on a per-call basis. Should be run during user op validation once per `Call` struct
    /// in the user op's calldata.
    function _checkCallPermissions(
        ContractAccessControlType accessControlType,
        SessionKeyId keyId,
        address target,
        bytes memory callData
    ) internal view {
        // This right-pads the selector variable if callData is <4 bytes.
        bytes4 selector = bytes4(callData);

        ContractData storage contractData = _contractDataOf(msg.sender, keyId, target);

        // Validate access control
        if (accessControlType == ContractAccessControlType.ALLOWLIST) {
            if (!contractData.isOnList) revert("Target address not on allowlist");
            if (!contractData.checkSelectors) return;
            // If selectors are specified, the function must be on the list.
            FunctionData storage functionData = _functionDataOf(msg.sender, keyId, target, selector);
            require(functionData.isOnList, "Function selector not on allowlist");
        } else if (accessControlType == ContractAccessControlType.DENYLIST) {
            if (!contractData.isOnList) return;
            if (!contractData.checkSelectors) revert("Target address on denylist");
            // If selectors are specified, the function must not be on the list.
            // A denylist with function selectors allows function calls that are not on the list.
            FunctionData storage functionData = _functionDataOf(msg.sender, keyId, target, selector);
            require(!functionData.isOnList, "Function selector on denylist");
        }

        // Check the selector in use if the target is a known ERC-20 contract with a spending limit.
        if (contractData.isERC20WithSpendLimit && !isAllowedERC20Function(selector)) {
            revert("Function selector not allowed for ERC20 contract with spending limit");
        }
    }

    /// @dev Runs during execution to re-check and update the spend limits of the session key in use.
    function _updateLimitsPreExec(address account, Call[] calldata calls, address sessionKey) internal {
        uint256 callsLength = calls.length;

        uint256 newNativeTokenUsage;

        // This step does not need to assert that the key id is nonzero, since the user op signature check implies
        // that.
        SessionKeyId keyId = _sessionKeyIdOf(msg.sender, sessionKey);
        SessionKeyData storage sessionKeyData = _sessionKeyDataOf(msg.sender, keyId);

        for (uint256 i = 0; i < callsLength; ++i) {
            Call memory call = calls[i];
            newNativeTokenUsage += call.value;

            ContractData storage contractData = _contractDataOf(account, keyId, call.target);
            if (contractData.isERC20WithSpendLimit) {
                // Tally up the amount being spent in each call to an ERC-20 contract.
                // Since this is a runtime-only check, we can interact with the stored limits after each call in
                // the batch and can still enforce the limits as intended.
                uint256 spendAmount = _getTokenSpendAmount(call.data);
                if (
                    !_runtimeUpdateSpendLimitUsage(
                        spendAmount, contractData.erc20SpendLimitTimeInfo, contractData.erc20SpendLimit
                    )
                ) {
                    revert("ERC20 spend limit exceeded");
                }
            }
        }

        if (!sessionKeyData.nativeTokenSpendLimitBypassed) {
            // Only run this step if a native token limit is set.
            if (
                !_runtimeUpdateSpendLimitUsage(
                    newNativeTokenUsage,
                    sessionKeyData.nativeTokenSpendLimitTimeInfo,
                    sessionKeyData.nativeTokenSpendLimit
                )
            ) {
                revert("Spend limit exceeded");
            }
        }

        if (sessionKeyData.gasLimitResetThisBundle) {
            // If the gas limit was reset during validation, we must reset the flag here and update the last used
            // field to `block.timestamp`. Note that if execution reverts, this step will be undone, and the flag
            // will remain set on the key. If there is enough gas still within the next interval to support another
            // call that succeeds, then the issue will be fixed. If, however, the gas in the upcoming interval is
            // exhausted and the flag remains enabled, that session key will be stuck until the owner or another
            // actor forces the last used timestamp to be reset and the flag cleared.
            sessionKeyData.gasLimitResetThisBundle = false;
            sessionKeyData.gasLimitTimeInfo.lastUsed = uint48(block.timestamp);
        }
    }

    /// @dev For use within user op validation
    function _checkSpendLimitUsage(uint256 newUsage, SpendLimitTimeInfo storage timeInfo, SpendLimit storage limit)
        internal
        view
        returns (uint48)
    {
        // This value will be coalesced with the overall key's start time to return the max value, so it is ok to
        // declare it as zero here and only use it if needed.
        uint48 validAfter;

        uint48 lastUsed = timeInfo.lastUsed;
        uint48 refreshInterval = timeInfo.refreshInterval;

        uint256 currentUsage = limit.limitUsed;
        uint256 spendLimit = limit.limitAmount;

        // Gracefully report SIG_FAIL on overflow, rather than revert.
        uint256 newTotalUsage;
        unchecked {
            newTotalUsage = newUsage + currentUsage;
            if (newTotalUsage < newUsage) {
                // If we overflow, fail early.
                revert("Spend limit overflow");
            }
        }

        if (refreshInterval == 0) {
            // We don't have a refresh interval reset, so just check that the spend limits are not exceeded.
            // The limits are not updated until the pre exec hook, in order to use `block.timestamp`.
            require(newTotalUsage <= spendLimit, "Spend limit exceeded");
        }
        // RefreshInterval != 0, meaning we have a time period over which the spend limit resets.
        else if (newTotalUsage <= spendLimit) {
            // The spend amount here fits within the existing interval,
            // so we're OK to just accept the result.
        }
        // The spend amount does not fit within the current interval.
        // It may or may not fit into the next one.
        else if (newUsage <= spendLimit) {
            // The spend amount fits into the next interval, so we're OK to accept the result, if we
            // wait until the refresh and start of the next interval.
            validAfter = lastUsed + refreshInterval;
        } else {
            // The spend amount does not fit, even into the next interval,
            // so we must reject the operation.
            revert("Spend limit exceeded, even including next interval");
        }

        return (validAfter);
    }

    /// @dev For use within user op validation. Gas limits are both checked and updated within the user op
    /// validation phase.
    function _checkAndUpdateGasLimitUsage(uint256 newUsage, SessionKeyData storage keyData)
        internal
        returns (uint48)
    {
        uint48 validAfter;

        uint48 lastUsed = keyData.gasLimitTimeInfo.lastUsed;
        uint48 refreshInterval = keyData.gasLimitTimeInfo.refreshInterval;

        uint256 currentUsage = keyData.gasLimit.limitUsed;
        uint256 gasLimit = keyData.gasLimit.limitAmount;

        bool gasLimitResetThisBundle = keyData.gasLimitResetThisBundle;

        // Gracefully report SIG_FAIL on overflow, rather than revert.
        uint256 newTotalUsage;
        unchecked {
            newTotalUsage = newUsage + currentUsage;
            if (newTotalUsage < newUsage) {
                // If we overflow, fail early.
                revert("Gas limit overflow");
            }
        }

        if (refreshInterval == 0) {
            // We don't have a refresh interval reset, so just check that the gas limits are not exceeded and
            // update their amounts.
            require(newTotalUsage <= gasLimit, "Gas limit exceeded");
            // Conditionally update as a gas optimization for the failure case.
            keyData.gasLimit.limitUsed = newTotalUsage;
        }
        // RefreshInterval != 0, meaning we have a time period over which the gas limit resets.
        else if (newTotalUsage <= gasLimit) {
            // The gas amount here fits within the existing refresh interval,
            // so we're OK to just accept the result.
            keyData.gasLimit.limitUsed = newTotalUsage;
            // If this is an incremental usage after a failed "reset" attempt, then enforce this existing
            // validAfter window.
            validAfter = (gasLimitResetThisBundle ? lastUsed + refreshInterval : 0);
        }
        // The gas amount does not fit within the current refresh interval.
        // It may or may not fit into the next one, provided the next interval usage has not already started.
        else if (newUsage <= gasLimit && !gasLimitResetThisBundle) {
            // The gas amount fits into the next refresh interval, so we're OK to accept the result, if we
            // wait until the start of the next refresh interval.
            validAfter = lastUsed + refreshInterval;

            // NOTE: This section is different than the other spend limit checks, due to how gas limits are
            // updated during validation, and the fact that `block.timestamp` is inaccessible during
            // validation.
            // If we allow this check to complete at this point without updating some state to indicate that a new
            // interval has started, there is a risk that this particular call
            // path can cause a session key to burn more gas per time than the limit was set at. This can
            // happen if the "new interval" case keeps getting triggered while the execution phase reverts,
            // due to the fact that those reverts will undo the state change updating the "last used time"
            // variable. To address this, we set a flag here called `gasLimitResetThisBundle` to indicate that
            // during execution, the plugin should attempt to update the last used time to the current
            // `block.timestamp`.

            keyData.gasLimitResetThisBundle = true;
            keyData.gasLimit.limitUsed = newUsage;
        } else {
            // The gas amount does not fit, even into the next refresh interval,
            // so we must reject the operation.
            revert("Gas limit exceeded");
        }

        return (validAfter);
    }

    /// @dev Re-check and update the spend limit during the execution phase.
    /// We MUST re-check the limits, despite the fact that they are checked during validation.
    // This is to protect from the case where multiple user operations are included in the same bundle, which
    // can happen either if the account is staked or if the bundle is sent by someone other than a 4337-compliant
    // bundler.
    function _runtimeUpdateSpendLimitUsage(
        uint256 newUsage,
        SpendLimitTimeInfo storage timeInfo,
        SpendLimit storage limit
    ) internal returns (bool) {
        uint48 refreshInterval = timeInfo.refreshInterval;
        uint48 lastUsed = timeInfo.lastUsed;
        uint256 spendLimit = limit.limitAmount;
        uint256 currentUsage = limit.limitUsed;

        if (refreshInterval == 0 || lastUsed + refreshInterval > block.timestamp) {
            // We either don't have a refresh interval, or the current one is still active.

            // Must re-check the limits to handle changes due to other user ops.
            // We manually check for overflows here to give a more informative error message.
            uint256 newTotalUsage;
            unchecked {
                newTotalUsage = newUsage + currentUsage;
            }
            if (newTotalUsage < newUsage || newTotalUsage > spendLimit) {
                // If we overflow, or if the limit is exceeded, fail here and revert in the parent context.
                return false;
            }

            // We won't update the refresh interval last used variable now, so just update the spend limit.
            limit.limitUsed = newTotalUsage;
        } else {
            // We have a interval active that is currently resetting.
            // Must re-check the amount to handle changes due to other user ops.
            // It only needs to fit within the new refresh interval, since the old one has passed.
            if (newUsage > spendLimit) {
                return false;
            }

            // The refresh interval has passed, so we can reset the spend limit to the new usage.
            limit.limitUsed = newUsage;
            timeInfo.lastUsed = uint48(block.timestamp);
        }

        return true;
    }

    // ERC-20 decoding logic

    /// @notice Decode the amount of a token a call is sending/approving.
    /// @dev This only supports the following standard ERC-20 functions:
    /// - transfer(address,uint256)
    /// - approve(address,uint256), in this case, the approve amount is always counted towards spending limits even
    /// if there are existing approval allowances
    /// @param callData The calldata of the transaction.
    /// @return The amount of the token being sent. Zero if the call is not recognized as a spend.
    function _getTokenSpendAmount(bytes memory callData) internal pure returns (uint256) {
        // Get the selector.
        // Right-padding with zeroes here is OK, because none of the selectors we're comparing this to have
        // trailing zero bytes.
        bytes4 selector = bytes4(callData);

        if (isAllowedERC20Function(selector)) {
            // Expected length: 68 bytes (4 selector + 32 address + 32 amount)
            if (callData.length < 68) {
                return 0;
            }

            // Load the amount being sent/approved.
            // Solidity doesn't support access a whole word from a bytes memory at once, only a single byte, and
            // trying to use abi.decode would require copying the data to remove the selector, which is expensive.
            // Instead, we use inline assembly to load the amount directly. This is safe because we've checked the
            // length of the call data.
            uint256 amount;
            assembly ("memory-safe") {
                // Jump 68 words forward: 32 for the length field, 4 for the selector, and 32 for the to address.
                amount := mload(add(callData, 68))
            }
            return amount;
        }
        // Unrecognized function selector
        return 0;
    }

    /// @dev A helper function re-used across the spend limit updating functions.
    function _updateSpendLimits(
        uint256 newLimit,
        uint48 newRefreshInterval,
        SpendLimitTimeInfo storage timeInfo,
        SpendLimit storage spendLimit
    ) internal returns (bool isEnabled) {
        if (newLimit == type(uint256).max) {
            isEnabled = false;
            // This field must be manually cleared to have the expected behavior if the spend limit is re-enabled
            // in the future.
            // Other fields are implicity replaced once the spend limit is configured.
            spendLimit.limitUsed = 0;
        } else {
            isEnabled = true;
            spendLimit.limitAmount = newLimit;
            timeInfo.refreshInterval = newRefreshInterval;
            if (newRefreshInterval == 0) {
                timeInfo.lastUsed = 0;
            } else {
                timeInfo.lastUsed = uint48(block.timestamp);
            }
        }
    }

    function _max(uint48 a, uint48 b) internal pure returns (uint48) {
        return a > b ? a : b;
    }

    function isAllowedERC20Function(bytes4 selector) internal pure returns (bool) {
        return selector == IERC20.transfer.selector || selector == IERC20.approve.selector;
    }
}
