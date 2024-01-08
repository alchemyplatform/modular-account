// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {Call} from "../../../interfaces/IStandardExecutor.sol";
import {BasePlugin} from "../../BasePlugin.sol";
import {ISessionKeyPermissionsPlugin} from "./ISessionKeyPermissionsPlugin.sol";
import {ISessionKeyPermissionsUpdates} from "./ISessionKeyPermissionsUpdates.sol";
import {ISessionKeyPlugin} from "../ISessionKeyPlugin.sol";
import {SessionKeyPermissionsLoupe} from "./SessionKeyPermissionsLoupe.sol";

import {
    IPlugin,
    ManifestAssociatedFunction,
    ManifestAssociatedFunctionType,
    ManifestExecutionHook,
    ManifestFunction,
    PluginManifest,
    PluginMetadata,
    SelectorPermission
} from "../../../interfaces/IPlugin.sol";
import {IStandardExecutor} from "../../../interfaces/IStandardExecutor.sol";
import {UserOperation} from "../../../interfaces/erc4337/UserOperation.sol";

/// @title Session Key Permissions Plugin
/// @author Alchemy
/// @notice This plugin allows users to configure and enforce permissions on session keys that have been
/// added by SessionKeyPlugin.
contract SessionKeyPermissionsPlugin is ISessionKeyPermissionsPlugin, SessionKeyPermissionsLoupe, BasePlugin {
    string internal constant _NAME = "Session Key Permissions Plugin";
    string internal constant _VERSION = "1.0.0";
    string internal constant _AUTHOR = "Alchemy";

    // Constants used in the manifest
    uint256 internal constant _MANIFEST_DEPENDENCY_INDEX_OWNER_USER_OP_VALIDATION = 0;
    uint256 internal constant _MANIFEST_DEPENDENCY_INDEX_OWNER_RUNTIME_VALIDATION = 1;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc ISessionKeyPermissionsPlugin
    function registerKey(address sessionKey, bytes32 tag) external override {
        SessionKeyId keyId = _sessionKeyIdOf(msg.sender, sessionKey);
        if (SessionKeyId.unwrap(keyId) != 0) {
            revert KeyAlreadyRegistered(sessionKey);
        }
        // Register the key with a new ID, and update the ID counter
        // We use pre increment to prevent the first id from being zero
        _updateSessionKeyId(msg.sender, sessionKey, SessionKeyId.wrap(bytes32(++_keyIdCounter[msg.sender])));

        emit KeyRegistered(msg.sender, sessionKey, tag);
    }

    /// @inheritdoc ISessionKeyPermissionsPlugin
    function rotateKey(address oldSessionKey, address newSessionKey) external override {
        // Assert that the new key is not already registered
        SessionKeyId newKeyId = _sessionKeyIdOf(msg.sender, newSessionKey);
        if (SessionKeyId.unwrap(newKeyId) != bytes32(0)) {
            revert KeyAlreadyRegistered(newSessionKey);
        }
        // Assert that the old key is registered
        SessionKeyId keyId = _sessionKeyIdOf(msg.sender, oldSessionKey);
        _assertRegistered(keyId, oldSessionKey);
        // Update the key ID of the old key to zero, and the new key to the old key's ID
        _updateSessionKeyId(msg.sender, oldSessionKey, SessionKeyId.wrap(bytes32(0)));
        _updateSessionKeyId(msg.sender, newSessionKey, keyId);

        emit KeyRotated(msg.sender, oldSessionKey, newSessionKey);
    }

    /// @inheritdoc ISessionKeyPermissionsPlugin
    function updateKeyPermissions(address sessionKey, bytes[] calldata updates) external override {
        (SessionKeyData storage sessionKeyData, SessionKeyId keyId) = _loadSessionKey(msg.sender, sessionKey);

        uint256 length = updates.length;
        for (uint256 i = 0; i < length;) {
            _performSessionKeyPermissionsUpdate(keyId, sessionKeyData, updates[i]);

            unchecked {
                ++i;
            }
        }

        emit PermissionsUpdated(msg.sender, sessionKey, updates);
    }

    /// @inheritdoc ISessionKeyPermissionsPlugin
    function resetSessionKeyGasLimitTimestamp(address account, address sessionKey) external override {
        (SessionKeyData storage sessionKeyData,) = _loadSessionKey(account, sessionKey);
        if (sessionKeyData.gasLimitResetThisBundle) {
            sessionKeyData.gasLimitResetThisBundle = false;
            sessionKeyData.gasLimitTimeInfo.lastUsed = uint48(block.timestamp);
        }
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function preUserOpValidationHook(uint8 functionId, UserOperation calldata userOp, bytes32)
        external
        override
        returns (uint256)
    {
        if (functionId == uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_CHECK_PERMISSIONS)) {
            return _checkUserOpPermissions(userOp);
        }
        revert NotImplemented();
    }

    function preExecutionHook(uint8 functionId, address, uint256, bytes calldata data)
        external
        override
        returns (bytes memory)
    {
        if (functionId == uint8(FunctionId.PRE_EXECUTION_HOOK_UPDATE_LIMITS)) {
            _updateLimitsPreExec(msg.sender, data);
        }
        return "";
    }

    /// @inheritdoc BasePlugin
    function onInstall(bytes calldata) external override {}

    /// @inheritdoc BasePlugin
    function onUninstall(bytes calldata) external override {}

    /// @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.dependencyInterfaceIds = new bytes4[](2);
        manifest.dependencyInterfaceIds[_MANIFEST_DEPENDENCY_INDEX_OWNER_USER_OP_VALIDATION] =
            type(IPlugin).interfaceId;
        manifest.dependencyInterfaceIds[_MANIFEST_DEPENDENCY_INDEX_OWNER_RUNTIME_VALIDATION] =
            type(IPlugin).interfaceId;

        manifest.executionFunctions = new bytes4[](3);
        manifest.executionFunctions[0] = ISessionKeyPermissionsPlugin.updateKeyPermissions.selector;
        manifest.executionFunctions[1] = ISessionKeyPermissionsPlugin.registerKey.selector;
        manifest.executionFunctions[2] = ISessionKeyPermissionsPlugin.rotateKey.selector;

        // Associate the owner's user op and runtime validator with permissions config
        ManifestFunction memory ownerUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: 0, // unused since it's a dependency
            dependencyIndex: _MANIFEST_DEPENDENCY_INDEX_OWNER_USER_OP_VALIDATION
        });
        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](3);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.updateKeyPermissions.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.registerKey.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: this.rotateKey.selector,
            associatedFunction: ownerUserOpValidationFunction
        });

        ManifestFunction memory ownerRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: 0, // unused since it's a dependency
            dependencyIndex: _MANIFEST_DEPENDENCY_INDEX_OWNER_RUNTIME_VALIDATION
        });
        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](3);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.updateKeyPermissions.selector,
            associatedFunction: ownerRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.registerKey.selector,
            associatedFunction: ownerRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: this.rotateKey.selector,
            associatedFunction: ownerRuntimeValidationFunction
        });

        // Apply the "enforcing" pre validation hook and pre exec hook
        manifest.preUserOpValidationHooks = new ManifestAssociatedFunction[](1);
        manifest.preUserOpValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: ISessionKeyPlugin.executeWithSessionKey.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_CHECK_PERMISSIONS),
                dependencyIndex: 0 // Unused.
            })
        });

        manifest.executionHooks = new ManifestExecutionHook[](1);
        manifest.executionHooks[0] = ManifestExecutionHook({
            executionSelector: ISessionKeyPlugin.executeWithSessionKey.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_EXECUTION_HOOK_UPDATE_LIMITS),
                dependencyIndex: 0 // Unused.
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.NONE,
                functionId: 0, // Unused.
                dependencyIndex: 0 // Unused.
            })
        });

        return manifest;
    }

    /// @inheritdoc BasePlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = _NAME;
        metadata.version = _VERSION;
        metadata.author = _AUTHOR;

        // Permission strings
        string memory modifyOwnershipPermission = "Modify Session Key Permissions";

        // Permission descriptions
        metadata.permissionDescriptors = new SelectorPermission[](1);
        metadata.permissionDescriptors[0] = SelectorPermission({
            functionSelector: this.updateKeyPermissions.selector,
            permissionDescription: modifyOwnershipPermission
        });

        return metadata;
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return
            interfaceId == type(ISessionKeyPermissionsPlugin).interfaceId || super.supportsInterface(interfaceId);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Internal / Private functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @dev A pre user op validation hook that checks the permissions of the key used to validate the user op.
    function _checkUserOpPermissions(UserOperation calldata userOp) internal returns (uint256) {
        // Decode the executions array and the session key from the user op's calldata
        (Call[] memory calls, address sessionKey) = abi.decode(userOp.callData[4:], (Call[], address));

        (SessionKeyData storage sessionKeyData, SessionKeyId keyId) = _loadSessionKey(msg.sender, sessionKey);

        // The session key's start time is the max of the key-specific validAfter and any time restrictions imposed
        // by spending limits.
        uint48 currentValidAfter = sessionKeyData.validAfter;
        uint256 nativeTokenSpend;

        uint256 callsLength = calls.length;
        // Only return validation success when there is at least one call
        bool validationSuccess = callsLength > 0;
        {
            ContractAccessControlType accessControlType = sessionKeyData.contractAccessControlType;
            for (uint256 i = 0; i < callsLength;) {
                Call memory call = calls[i];
                nativeTokenSpend += call.value;
                validationSuccess =
                    validationSuccess && _checkCallPermissions(accessControlType, keyId, call.target, call.data);

                unchecked {
                    ++i;
                }
            }
        }

        if (!sessionKeyData.nativeTokenSpendLimitBypassed) {
            (bool spendLimitSuccess, uint48 spendLimitValidAfter) = _checkSpendLimitUsage(
                nativeTokenSpend,
                sessionKeyData.nativeTokenSpendLimitTimeInfo,
                sessionKeyData.nativeTokenSpendLimit
            );
            validationSuccess = validationSuccess && spendLimitSuccess;
            currentValidAfter = _max(currentValidAfter, spendLimitValidAfter);
        }

        if (sessionKeyData.hasGasLimit) {
            // Multiplier for the verification gas limit is 3 if there is a paymaster, 1 otherwise.
            // This is defined in EntryPoint v0.6.0, which uses the limit for the user op validation + paymaster
            // validation, then again for up to two more calls of `postOp`. Later versions of the EntryPoint may
            // change this scale factor or the usage of the verification gas limit, so this value should be checked
            // and updated if porting this plugin to a newer version of 4337.
            uint256 multiplier = userOp.paymasterAndData.length > 0 ? 3 : 1;
            uint256 maxGasFee = (
                userOp.callGasLimit + userOp.verificationGasLimit * multiplier + userOp.preVerificationGas
            ) * userOp.maxFeePerGas;
            (bool gasLimitSuccess, uint48 gasLimitValidAfter) =
                _checkAndUpdateGasLimitUsage(maxGasFee, sessionKeyData);
            validationSuccess = validationSuccess && gasLimitSuccess;
            currentValidAfter = _max(currentValidAfter, gasLimitValidAfter);

            // Gas limit checking is the only type of permissions checking that has state changes performed during
            // validation. This can potentially cause reputation damage to staked accounts if multiple user
            // operations are accepted into the same bundle, then validation for one of the later operations fails
            // due to the state change from the first. To protect from this, we require session keys to use their
            // own address as the key portion of the user operation nonce field, in order to guarantee that they
            // are used sequentially.
            if (uint192(userOp.nonce >> 64) != uint192(uint160(sessionKey))) {
                validationSuccess = false;
            }
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
            validationSuccess = validationSuccess && (userOpPaymaster == sessionKeyData.requiredPaymaster);
        }
        // Validation return data is 1 in the case of an invalid signature,
        // otherwise a packed struct of the aggregator address (0 here), and two
        // 6-byte timestamps indicating the start and end times at which the op
        // is valid.
        return uint160(!validationSuccess ? 1 : 0) | (uint256(sessionKeyData.validUntil) << 160)
            | (uint256(currentValidAfter) << (208));
    }

    /// @dev Checks permissions on a per-call basis. Should be run in the pre user op validation hook once per
    /// `Call` struct in the user op's calldata.
    function _checkCallPermissions(
        ContractAccessControlType accessControlType,
        SessionKeyId keyId,
        address target,
        bytes memory callData
    ) internal view returns (bool validationSuccess) {
        validationSuccess = true;

        // This right-pads the selector variable if callData is <4 bytes.
        bytes4 selector = bytes4(callData);

        ContractData storage contractData = _contractDataOf(msg.sender, keyId, target);

        // Validate access control
        if (accessControlType == ContractAccessControlType.ALLOWLIST) {
            if (!contractData.isOnList) return false;
            if (!contractData.checkSelectors) return true;
            // If selectors are specified, the function must be on the list.
            FunctionData storage functionData = _functionDataOf(msg.sender, keyId, target, selector);
            validationSuccess = functionData.isOnList;
        } else if (accessControlType == ContractAccessControlType.DENYLIST) {
            if (!contractData.isOnList) return true;
            if (!contractData.checkSelectors) return false;
            // If selectors are specified, the function must not be on the list.
            // A denylist with function selectors allows function calls that are not on the list.
            FunctionData storage functionData = _functionDataOf(msg.sender, keyId, target, selector);
            validationSuccess = !functionData.isOnList;
        }
    }

    /// @dev Runs as a pre exec hook, and updates the spend limits of the session key in use
    function _updateLimitsPreExec(address account, bytes calldata callData) internal {
        (Call[] memory calls, address sessionKey) = abi.decode(callData[4:], (Call[], address));
        uint256 callsLength = calls.length;

        uint256 newNativeTokenUsage;

        (SessionKeyData storage sessionKeyData, SessionKeyId keyId) = _loadSessionKey(account, sessionKey);

        for (uint256 i = 0; i < callsLength;) {
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
                    revert ERC20SpendLimitExceeded(msg.sender, sessionKey, call.target);
                }
            }

            unchecked {
                ++i;
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
                revert NativeTokenSpendLimitExceeded(msg.sender, sessionKey);
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
        returns (bool, uint48)
    {
        bool validationSuccess;
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
                return (false, 0);
            }
        }

        if (refreshInterval == 0) {
            // We don't have a refresh interval reset, so just check that the spend limits are not exceeded.
            // The limits are not updated until the pre exec hook, in order to use `block.timestamp`.
            validationSuccess = (newTotalUsage <= spendLimit);
        }
        // RefreshInterval != 0, meaning we have a time period over which the spend limit resets.
        else if (newTotalUsage <= spendLimit) {
            // The spend amount here fits within the existing interval,
            // so we're OK to just accept the result.
            validationSuccess = true;
        }
        // The spend amount does not fit within the current interval.
        // It may or may not fit into the next one.
        else if (newUsage <= spendLimit) {
            // The spend amount fits into the next interval, so we're OK to accept the result, if we
            // wait until the refresh and start of the next interval.
            validationSuccess = true;
            validAfter = lastUsed + refreshInterval;
        } else {
            // The spend amount does not fit, even into the next interval,
            // so we must reject the operation.
            validationSuccess = false;
        }

        return (validationSuccess, validAfter);
    }

    /// @dev For use within user op validation. Gas limits are both checked and updated within the user op
    /// validation phase.
    function _checkAndUpdateGasLimitUsage(uint256 newUsage, SessionKeyData storage keyData)
        internal
        returns (bool, uint48)
    {
        bool validationSuccess;
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
                return (false, 0);
            }
        }

        if (refreshInterval == 0) {
            // We don't have a refresh interval reset, so just check that the gas limits are not exceeded and
            // update their amounts.
            validationSuccess = newTotalUsage <= gasLimit;
            if (validationSuccess) {
                // Conditionally update as a gas optimization for the failure case.
                keyData.gasLimit.limitUsed = newTotalUsage;
            }
        }
        // RefreshInterval != 0, meaning we have a time period over which the gas limit resets.
        else if (newTotalUsage <= gasLimit) {
            // The gas amount here fits within the existing refresh interval,
            // so we're OK to just accept the result.
            validationSuccess = true;
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
            validationSuccess = true;
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
            validationSuccess = false;
        }

        return (validationSuccess, validAfter);
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

        if (selector == IERC20.transfer.selector || selector == IERC20.approve.selector) {
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

    // Permissions updating functions

    function _performSessionKeyPermissionsUpdate(
        SessionKeyId keyId,
        SessionKeyData storage sessionKeyData,
        bytes calldata update
    ) internal {
        if (update.length < 4) {
            revert InvalidPermissionsUpdate();
        }

        bytes4 updateSelector = bytes4(update);

        // If/else chain to find the right interal update function to perform.
        if (updateSelector == ISessionKeyPermissionsUpdates.setAccessListType.selector) {
            ContractAccessControlType contractAccessControlType =
                abi.decode(update[4:], (ContractAccessControlType));
            _setAccessListType(sessionKeyData, contractAccessControlType);
        } else if (updateSelector == ISessionKeyPermissionsUpdates.updateAccessListAddressEntry.selector) {
            (address contractAddress, bool isOnList, bool checkSelectors) =
                abi.decode(update[4:], (address, bool, bool));
            _updateAccessListAddressEntry(keyId, contractAddress, isOnList, checkSelectors);
        } else if (updateSelector == ISessionKeyPermissionsUpdates.updateAccessListFunctionEntry.selector) {
            (address contractAddress, bytes4 selector, bool isOnList) =
                abi.decode(update[4:], (address, bytes4, bool));
            _updateAccessListFunctionEntry(keyId, contractAddress, selector, isOnList);
        } else if (updateSelector == ISessionKeyPermissionsUpdates.updateTimeRange.selector) {
            (uint48 validAfter, uint48 validUntil) = abi.decode(update[4:], (uint48, uint48));
            _updateTimeRange(sessionKeyData, validAfter, validUntil);
        } else if (updateSelector == ISessionKeyPermissionsUpdates.setNativeTokenSpendLimit.selector) {
            (uint256 ethSpendLimit, uint48 refreshInterval) = abi.decode(update[4:], (uint256, uint48));
            _setNativeTokenSpendLimit(sessionKeyData, ethSpendLimit, refreshInterval);
        } else if (updateSelector == ISessionKeyPermissionsUpdates.setERC20SpendLimit.selector) {
            (address token, uint256 spendLimit, uint48 refreshInterval) =
                abi.decode(update[4:], (address, uint256, uint48));
            _setERC20SpendLimit(keyId, token, spendLimit, refreshInterval);
        } else if (updateSelector == ISessionKeyPermissionsUpdates.setGasSpendLimit.selector) {
            (uint256 spendLimit, uint48 refreshInterval) = abi.decode(update[4:], (uint256, uint48));
            _setGasSpendLimit(sessionKeyData, spendLimit, refreshInterval);
        } else if (updateSelector == ISessionKeyPermissionsUpdates.setRequiredPaymaster.selector) {
            address requiredPaymaster = abi.decode(update[4:], (address));
            _setRequiredPaymaster(sessionKeyData, requiredPaymaster);
        } else {
            revert InvalidPermissionsUpdate();
        }
    }

    function _setAccessListType(
        SessionKeyData storage sessionKeyData,
        ContractAccessControlType contractAccessControlType
    ) internal {
        sessionKeyData.contractAccessControlType = contractAccessControlType;
    }

    function _updateAccessListAddressEntry(
        SessionKeyId keyId,
        address contractAddress,
        bool isOnList,
        bool checkSelectors
    ) internal {
        ContractData storage contractData = _contractDataOf(msg.sender, keyId, contractAddress);
        contractData.isOnList = isOnList;
        contractData.checkSelectors = checkSelectors;
    }

    function _updateAccessListFunctionEntry(
        SessionKeyId keyId,
        address contractAddress,
        bytes4 selector,
        bool isOnList
    ) internal {
        FunctionData storage functionData = _functionDataOf(msg.sender, keyId, contractAddress, selector);
        functionData.isOnList = isOnList;
    }

    function _updateTimeRange(SessionKeyData storage sessionKeyData, uint48 validAfter, uint48 validUntil)
        internal
    {
        sessionKeyData.validAfter = validAfter;
        sessionKeyData.validUntil = validUntil;
    }

    function _setNativeTokenSpendLimit(
        SessionKeyData storage sessionKeyData,
        uint256 ethSpendLimit,
        uint48 refreshInterval
    ) internal {
        // The flag we store for native token spend is inverted from other similar flags
        sessionKeyData.nativeTokenSpendLimitBypassed = !_updateSpendLimits(
            ethSpendLimit,
            refreshInterval,
            sessionKeyData.nativeTokenSpendLimitTimeInfo,
            sessionKeyData.nativeTokenSpendLimit
        );
    }

    function _setERC20SpendLimit(SessionKeyId keyId, address token, uint256 spendLimit, uint48 refreshInterval)
        internal
    {
        if (token == address(0)) {
            revert InvalidToken();
        }

        ContractData storage tokenContractData = _contractDataOf(msg.sender, keyId, token);

        tokenContractData.isERC20WithSpendLimit = _updateSpendLimits(
            spendLimit,
            refreshInterval,
            tokenContractData.erc20SpendLimitTimeInfo,
            tokenContractData.erc20SpendLimit
        );
    }

    function _setGasSpendLimit(SessionKeyData storage sessionKeyData, uint256 spendLimit, uint48 refreshInterval)
        internal
    {
        // Start by clearing the reset flag, if set.
        if (sessionKeyData.gasLimitResetThisBundle) {
            sessionKeyData.gasLimitResetThisBundle = false;
            // Don't need to update the last used timestamp, since that will be updated within _updateSpendLimits.
        }
        sessionKeyData.hasGasLimit = _updateSpendLimits(
            spendLimit, refreshInterval, sessionKeyData.gasLimitTimeInfo, sessionKeyData.gasLimit
        );
    }

    function _setRequiredPaymaster(SessionKeyData storage sessionKeyData, address requiredPaymaster) internal {
        if (requiredPaymaster == address(0)) {
            sessionKeyData.hasRequiredPaymaster = false;
        } else {
            sessionKeyData.hasRequiredPaymaster = true;
            sessionKeyData.requiredPaymaster = requiredPaymaster;
        }
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
}
