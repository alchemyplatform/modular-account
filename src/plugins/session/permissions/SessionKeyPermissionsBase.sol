// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {ISessionKeyPermissionsPlugin} from "./ISessionKeyPermissionsPlugin.sol";

import {PluginStorageLib, StoragePointer} from "../../../libraries/PluginStorageLib.sol";

abstract contract SessionKeyPermissionsBase is ISessionKeyPermissionsPlugin {
    type SessionKeyId is bytes32;

    struct SessionKeyData {
        // Contract access control type
        ContractAccessControlType contractAccessControlType;
        // Key time range: limits when a key may be used.
        uint48 validAfter;
        uint48 validUntil;
        bool hasRequiredPaymaster;
        bool hasGasLimit;
        bool gasLimitResetThisBundle;
        // Native token spend limits
        bool nativeTokenSpendLimitBypassed; // By default, spend limits ARE enforced and the limit is zero.
        SpendLimitTimeInfo gasLimitTimeInfo;
        SpendLimitTimeInfo nativeTokenSpendLimitTimeInfo;
        // Required paymaster rule
        address requiredPaymaster;
        SpendLimit gasLimit;
        SpendLimit nativeTokenSpendLimit;
    }

    /// @dev These structs are not held in an Associated Enumerable set, so the elements must be emitted from
    /// events to use offchain.
    struct ContractData {
        bool isOnList;
        bool checkSelectors;
        bool isERC20WithSpendLimit;
        SpendLimitTimeInfo erc20SpendLimitTimeInfo;
        SpendLimit erc20SpendLimit;
    }

    struct FunctionData {
        bool isOnList;
    }

    // Spending limit info structs.
    // Split into two structs to allow custom storage arrangements.

    struct SpendLimitTimeInfo {
        uint48 lastUsed;
        uint48 refreshInterval;
    }

    struct SpendLimit {
        uint256 limitAmount;
        uint256 limitUsed;
    }

    // Prefixes:
    bytes4 internal constant SESSION_KEY_ID_PREFIX = bytes4(0x1a01dae4); // bytes4(keccak256("SessionKeyId"))
    bytes4 internal constant SESSION_KEY_DATA_PREFIX = bytes4(0x16bff296); // bytes4(keccak256("SessionKeyData"))
    bytes4 internal constant CONTRACT_DATA_PREFIX = bytes4(0x634c29f5); // bytes4(keccak256("ContractData"))
    bytes4 internal constant FUNCTION_DATA_PREFIX = bytes4(0xd50536f0); // bytes4(keccak256("FunctionData"))

    // KEY DERIVATION
    // All of these following keys begin with the associated address,
    // the prefix, and a uint224 batch index of zero.

    // All PluginStorageLib keys are, at a minimum, 96 bytes long.
    // The first word (32 bytes) is the associated address.
    // The second word (32 bytes) is the prefix and batch index concatenated.
    // Any subsequent words are the key data.

    // SessionKeyId storage key (96 bytes)
    // 12 padding zeros || associated address || SESSION_KEY_ID_PREFIX || batch index || 12 padding zero bytes
    // || sessionKey

    // SessionKeyData (96 bytes)
    // 12 padding zeros || associated address || SESSION_KEY_DATA_PREFIX || batch index || sessionKeyId

    // ContractData (128 bytes)
    // 12 padding zeros || associated address || CONTRACT_DATA_PREFIX || batch index || sessionKeyId
    // || contractAddress  || 12 padding zero bytes

    // FunctionData (128 bytes)
    // 12 padding zeros || associated address || FUNCTION_DATA_PREFIX || batch index || sessionKeyId || selector
    // || 8 padding zero bytes || contractAddress

    // Storage fields
    mapping(address => uint256) internal _keyIdCounter;

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

    function _assertRegistered(SessionKeyId id, address sessionKey) internal pure {
        if (SessionKeyId.unwrap(id) == bytes32(0)) {
            revert KeyNotRegistered(sessionKey);
        }
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
    function _loadSessionKey(address associated, address sessionKey)
        internal
        view
        returns (SessionKeyData storage sessionKeyData, SessionKeyId keyId)
    {
        SessionKeyId id = _sessionKeyIdOf(associated, sessionKey);
        _assertRegistered(id, sessionKey);
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
        bytes32 contractDataKey2 = bytes32(bytes20(contractAddress));
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
