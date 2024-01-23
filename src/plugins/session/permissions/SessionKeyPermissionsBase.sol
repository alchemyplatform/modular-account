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

import {PluginStorageLib, StoragePointer} from "../../../libraries/PluginStorageLib.sol";
import {ISessionKeyPlugin} from "../ISessionKeyPlugin.sol";

abstract contract SessionKeyPermissionsBase is ISessionKeyPlugin {
    type SessionKeyId is bytes32;

    // Implementation-internal structs not exposed by the external interface.

    // Holds permission data unique to each session key on an account.
    struct SessionKeyData {
        // Contract access control type.
        ContractAccessControlType contractAccessControlType;
        // Key time range: limits when a key may be used.
        uint48 validAfter;
        uint48 validUntil;
        // Boolean flags for optional rules.
        bool hasRequiredPaymaster;
        bool hasGasLimit;
        bool nativeTokenSpendLimitBypassed; // By default, spend limits are enforced and the limit is zero.
        // Flag for resetting gas limit last used timestamp during the execution phase.
        bool gasLimitResetThisBundle;
        // Time info for gas and native token spend limits.
        SpendLimitTimeInfo gasLimitTimeInfo;
        SpendLimitTimeInfo nativeTokenSpendLimitTimeInfo;
        // Required paymaster rule
        address requiredPaymaster;
        // Limit amounts and limit usages for gas and native token spend limits.
        SpendLimit gasLimit;
        SpendLimit nativeTokenSpendLimit;
    }

    // Holds permission data for an address associated with a session key and an account.
    struct ContractData {
        // Whether or not this address is on the access control list.
        bool isOnList;
        // Whether or not to check selectors for this address, per the current access control type's rules.
        bool checkSelectors;
        // Whether or not this address is a known ERC-20 contract with a spend limit.
        bool isERC20WithSpendLimit;
        // Spend limit configuration data for ERC-20 contracts.
        SpendLimitTimeInfo erc20SpendLimitTimeInfo;
        SpendLimit erc20SpendLimit;
    }

    // Holds permission data for a function selector associated with a session key, an account,
    // and a contract address.
    struct FunctionData {
        // Whether or not this selector is on the access control list.
        bool isOnList;
    }

    // Spending limit info structs.
    // Split into two structs to allow custom storage arrangements.

    // Holds time info for spend limits.
    struct SpendLimitTimeInfo {
        uint48 lastUsed;
        uint48 refreshInterval;
    }

    // Holds spend limit data.
    struct SpendLimit {
        uint256 limitAmount;
        uint256 limitUsed;
    }

    // Prefixes:
    bytes4 internal constant SESSION_KEY_ID_PREFIX = bytes4(keccak256("SessionKeyId"));
    bytes4 internal constant SESSION_KEY_DATA_PREFIX = bytes4(keccak256("SessionKeyData"));
    bytes4 internal constant CONTRACT_DATA_PREFIX = bytes4(keccak256("ContractData"));
    bytes4 internal constant FUNCTION_DATA_PREFIX = bytes4(keccak256("FunctionData"));

    // KEY DERIVATION
    // All of these following keys begin with the associated address,
    // the prefix, and a uint224 batch index of zero.

    // All PluginStorageLib keys are, at a minimum, 96 bytes long.
    // The first word (32 bytes) is the associated address.
    // The second word (32 bytes) is the prefix and batch index concatenated.
    // Any subsequent words are the key data.
    // Note: `||` refers to the concat operator

    // SessionKeyId storage key (96 bytes)
    // 12 padding zeros || associated address || SESSION_KEY_ID_PREFIX || batch index || 12 padding zero bytes
    // || sessionKey

    // SessionKeyData (96 bytes)
    // 12 padding zeros || associated address || SESSION_KEY_DATA_PREFIX || batch index || sessionKeyId

    // ContractData (128 bytes)
    // 12 padding zeros || associated address || CONTRACT_DATA_PREFIX || batch index || sessionKeyId
    // || 12 padding zero bytes || contractAddress

    // FunctionData (128 bytes)
    // 12 padding zeros || associated address || FUNCTION_DATA_PREFIX || batch index || sessionKeyId || selector
    // || 8 padding zero bytes || contractAddress

    // Storage fields
    mapping(address => uint256) internal _keyIdCounter;

    // Internal Functions

    function _sessionKeyIdOf(address associated, address sessionKey) internal view returns (SessionKeyId keyId) {
        uint256 prefixAndBatchIndex = uint256(bytes32(SESSION_KEY_ID_PREFIX));
        bytes memory associatedStorageKey =
            PluginStorageLib.allocateAssociatedStorageKey(associated, prefixAndBatchIndex, 1);
        StoragePointer ptr =
            PluginStorageLib.associatedStorageLookup(associatedStorageKey, bytes32(uint256(uint160(sessionKey))));
        assembly ("memory-safe") {
            keyId := sload(ptr)
        }
    }

    /// @dev Helper function that loads the session key id and asserts it is registered.
    function _loadSessionKeyId(address associated, address sessionKey)
        internal
        view
        returns (SessionKeyId keyId)
    {
        SessionKeyId id = _sessionKeyIdOf(associated, sessionKey);
        if (SessionKeyId.unwrap(id) == bytes32(0)) {
            revert InvalidSessionKey(sessionKey);
        }
        return id;
    }

    function _updateSessionKeyId(address associated, address sessionKey, SessionKeyId newId) internal {
        uint256 prefixAndBatchIndex = uint256(bytes32(SESSION_KEY_ID_PREFIX));
        bytes memory associatedStorageKey =
            PluginStorageLib.allocateAssociatedStorageKey(associated, prefixAndBatchIndex, 1);
        StoragePointer ptr =
            PluginStorageLib.associatedStorageLookup(associatedStorageKey, bytes32(uint256(uint160(sessionKey))));
        assembly ("memory-safe") {
            sstore(ptr, newId)
        }
    }

    function _sessionKeyDataOf(address associated, SessionKeyId id)
        internal
        pure
        returns (SessionKeyData storage sessionKeyData)
    {
        uint256 prefixAndBatchIndex = uint256(bytes32(SESSION_KEY_DATA_PREFIX));
        bytes memory associatedStorageKey =
            PluginStorageLib.allocateAssociatedStorageKey(associated, prefixAndBatchIndex, 1);

        bytes32 sessionKeyDataKey = SessionKeyId.unwrap(id);
        return _toSessionKeyData(PluginStorageLib.associatedStorageLookup(associatedStorageKey, sessionKeyDataKey));
    }

    /// @dev Helper function that loads the session key id, asserts it is registered, and returns the session key
    /// data and the key id.
    function _loadSessionKeyData(address associated, address sessionKey)
        internal
        view
        returns (SessionKeyData storage sessionKeyData, SessionKeyId keyId)
    {
        SessionKeyId id = _loadSessionKeyId(associated, sessionKey);
        return (_sessionKeyDataOf(associated, id), id);
    }

    function _contractDataOf(address associated, SessionKeyId id, address contractAddress)
        internal
        pure
        returns (ContractData storage contractData)
    {
        uint256 prefixAndBatchIndex = uint256(bytes32(CONTRACT_DATA_PREFIX));
        bytes memory associatedStorageKey =
            PluginStorageLib.allocateAssociatedStorageKey(associated, prefixAndBatchIndex, 2);

        bytes32 contractDataKey1 = SessionKeyId.unwrap(id);
        bytes32 contractDataKey2 = bytes32(uint256(uint160(contractAddress)));
        return _toContractData(
            PluginStorageLib.associatedStorageLookup(associatedStorageKey, contractDataKey1, contractDataKey2)
        );
    }

    function _functionDataOf(address associated, SessionKeyId id, address contractAddress, bytes4 selector)
        internal
        pure
        returns (FunctionData storage functionData)
    {
        uint256 prefixAndBatchIndex = uint256(bytes32(FUNCTION_DATA_PREFIX));
        bytes memory associatedStorageKey =
            PluginStorageLib.allocateAssociatedStorageKey(associated, prefixAndBatchIndex, 2);

        bytes32 functionDataKey1 = SessionKeyId.unwrap(id);
        bytes32 functionDataKey2 = bytes32(selector) | bytes32(uint256(uint160(contractAddress)));
        return _toFunctionData(
            PluginStorageLib.associatedStorageLookup(associatedStorageKey, functionDataKey1, functionDataKey2)
        );
    }

    // Storage pointer interpretation

    function _toSessionKeyData(StoragePointer ptr) internal pure returns (SessionKeyData storage sessionKeyData) {
        assembly ("memory-safe") {
            sessionKeyData.slot := ptr
        }
    }

    function _toContractData(StoragePointer ptr) internal pure returns (ContractData storage contractData) {
        assembly ("memory-safe") {
            contractData.slot := ptr
        }
    }

    function _toFunctionData(StoragePointer ptr) internal pure returns (FunctionData storage functionData) {
        assembly ("memory-safe") {
            functionData.slot := ptr
        }
    }
}
