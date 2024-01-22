// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {ISessionKeyPlugin} from "../ISessionKeyPlugin.sol";
import {SessionKeyPermissionsBase} from "./SessionKeyPermissionsBase.sol";

abstract contract SessionKeyPermissionsLoupe is SessionKeyPermissionsBase {
    /// @inheritdoc ISessionKeyPlugin
    function getAccessControlType(address account, address sessionKey)
        external
        view
        returns (ContractAccessControlType)
    {
        (SessionKeyData storage sessionKeyData,) = _loadSessionKey(account, sessionKey);
        return sessionKeyData.contractAccessControlType;
    }

    /// @inheritdoc ISessionKeyPlugin
    function getAccessControlEntry(address account, address sessionKey, address contractAddress)
        external
        view
        returns (bool isOnList, bool checkSelectors)
    {
        SessionKeyId keyId = _sessionKeyIdOf(account, sessionKey);
        _assertKeyExists(keyId, sessionKey);
        ContractData storage contractData = _contractDataOf(account, keyId, contractAddress);
        return (contractData.isOnList, contractData.checkSelectors);
    }

    /// @inheritdoc ISessionKeyPlugin
    function isSelectorOnAccessControlList(
        address account,
        address sessionKey,
        address contractAddress,
        bytes4 selector
    ) external view returns (bool isOnList) {
        SessionKeyId keyId = _sessionKeyIdOf(account, sessionKey);
        _assertKeyExists(keyId, sessionKey);
        FunctionData storage functionData = _functionDataOf(account, keyId, contractAddress, selector);
        return functionData.isOnList;
    }

    /// @inheritdoc ISessionKeyPlugin
    function getKeyTimeRange(address account, address sessionKey)
        external
        view
        returns (uint48 validAfter, uint48 validUntil)
    {
        (SessionKeyData storage sessionKeyData,) = _loadSessionKey(account, sessionKey);
        return (sessionKeyData.validAfter, sessionKeyData.validUntil);
    }

    /// @inheritdoc ISessionKeyPlugin
    function getNativeTokenSpendLimitInfo(address account, address sessionKey)
        external
        view
        returns (SpendLimitInfo memory info)
    {
        (SessionKeyData storage sessionKeyData,) = _loadSessionKey(account, sessionKey);

        if (!sessionKeyData.nativeTokenSpendLimitBypassed) {
            info.hasLimit = true;
            info.limit = sessionKeyData.nativeTokenSpendLimit.limitAmount;
            info.limitUsed = sessionKeyData.nativeTokenSpendLimit.limitUsed;
            info.refreshInterval = sessionKeyData.nativeTokenSpendLimitTimeInfo.refreshInterval;
            info.lastUsedTime = sessionKeyData.nativeTokenSpendLimitTimeInfo.lastUsed;
        }
        // If the limit is bypassed, report false for hasLimit and zeros for the other fields.
        // These are the default values for SpendLimitInfo, so we don't need to set them explicitly.
    }

    /// @inheritdoc ISessionKeyPlugin
    function getERC20SpendLimitInfo(address account, address sessionKey, address token)
        external
        view
        returns (SpendLimitInfo memory)
    {
        (, SessionKeyId keyId) = _loadSessionKey(account, sessionKey);
        ContractData storage tokenContractData = _contractDataOf(account, keyId, token);
        return SpendLimitInfo({
            hasLimit: tokenContractData.isERC20WithSpendLimit,
            limit: tokenContractData.erc20SpendLimit.limitAmount,
            limitUsed: tokenContractData.erc20SpendLimit.limitUsed,
            refreshInterval: tokenContractData.erc20SpendLimitTimeInfo.refreshInterval,
            lastUsedTime: tokenContractData.erc20SpendLimitTimeInfo.lastUsed
        });
    }

    /// @inheritdoc ISessionKeyPlugin
    function getRequiredPaymaster(address account, address sessionKey) external view returns (address) {
        SessionKeyId id = _sessionKeyIdOf(account, sessionKey);
        _assertKeyExists(id, sessionKey);
        SessionKeyData storage sessionKeyData = _sessionKeyDataOf(account, id);
        return sessionKeyData.hasRequiredPaymaster ? sessionKeyData.requiredPaymaster : address(0);
    }

    /// @inheritdoc ISessionKeyPlugin
    function getGasSpendLimit(address account, address sessionKey)
        external
        view
        override
        returns (SpendLimitInfo memory, bool)
    {
        (SessionKeyData storage sessionKeyData,) = _loadSessionKey(account, sessionKey);

        bool hasLimit = sessionKeyData.hasGasLimit;
        bool shouldReset = sessionKeyData.gasLimitResetThisBundle;

        SpendLimitInfo memory info;
        if (hasLimit) {
            info.hasLimit = true;
            info.limit = sessionKeyData.gasLimit.limitAmount;
            info.limitUsed = sessionKeyData.gasLimit.limitUsed;
            info.refreshInterval = sessionKeyData.gasLimitTimeInfo.refreshInterval;
            info.lastUsedTime = sessionKeyData.gasLimitTimeInfo.lastUsed;
        }
        // If the limit is bypassed, report false for hasLimit and zeros for the other fields.
        // These are the default values for SpendLimitInfo, so we don't need to set them explicitly.
        return (info, shouldReset);
    }
}
