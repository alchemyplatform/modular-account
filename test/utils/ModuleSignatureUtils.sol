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

pragma solidity ^0.8.26;

import {Vm} from "forge-std/Vm.sol";

import {
    DIRECT_CALL_VALIDATION_ENTITYID,
    RESERVED_VALIDATION_DATA_INDEX
} from "@erc6900/reference-implementation/helpers/Constants.sol";
import {ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {
    ValidationConfig,
    ValidationConfigLib
} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {ValidationLocator, ValidationLocatorLib} from "../../src/libraries/ValidationLocatorLib.sol";

/// @dev Utilities for encoding signatures for modular account validation. Used for encoding user op, runtime, and
/// 1271 signatures.
contract ModuleSignatureUtils {
    using ModuleEntityLib for ModuleEntity;

    enum ValidationType {
        SELECTOR_ASSOCIATED,
        GLOBAL
    }

    struct PreValidationHookData {
        uint8 index;
        bytes validationData;
    }

    uint8 public constant SELECTOR_ASSOCIATED_VALIDATION = 0;
    ValidationType public constant SELECTOR_ASSOCIATED_V = ValidationType.SELECTOR_ASSOCIATED;
    uint8 public constant GLOBAL_VALIDATION = 1;
    ValidationType public constant GLOBAL_V = ValidationType.GLOBAL;

    uint8 public constant HAS_DEFERRED_ACTION_BIT = 2;

    uint8 public constant EOA_TYPE_SIGNATURE = 0;

    string internal constant _DEFERRED_ACTION_CONTENTS_TYPE =
        "DeferredAction(uint256 nonce,uint48 deadline,uint168 validationLocator,bytes call)";
    bytes32 private constant _DEFERRED_ACTION_TYPEHASH =
        keccak256(abi.encodePacked(_DEFERRED_ACTION_CONTENTS_TYPE));

    bytes32 internal constant _REPLAY_SAFE_HASH_TYPEHASH = keccak256("ReplaySafeHash(bytes32 hash)");

    bytes32 internal constant _ACCOUNT_DOMAIN_SEPARATOR =
        keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
    bytes32 internal constant _MODULE_DOMAIN_SEPARATOR =
        keccak256("EIP712Domain(uint256 chainId,address verifyingContract,bytes32 salt)");

    function _encodeSignature(PreValidationHookData[] memory preValidationHookData, bytes memory validationData)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory sig = _packPreHookDatas(preValidationHookData);

        sig = abi.encodePacked(sig, _packFinalSignature(validationData));

        return sig;
    }

    function _encodeSignature(bytes memory validationData) internal pure returns (bytes memory) {
        return _packFinalSignature(validationData);
    }

    // helper function to encode a signature, according to the per-hook and per-validation data format.
    function _encodeSignature(
        ModuleEntity validationFunction,
        uint8 globalOrNot,
        PreValidationHookData[] memory preValidationHookData,
        bytes memory validationData
    ) internal pure returns (bytes memory) {
        // Construct the per-hook data and validation data first, then prefix with the validation locator.

        bytes memory sig = _encodeSignature(preValidationHookData, validationData);

        (address module, uint32 entityId) = validationFunction.unpack();

        if (entityId == DIRECT_CALL_VALIDATION_ENTITYID) {
            sig =
                ValidationLocatorLib.packSignatureDirectCall(module, globalOrNot == GLOBAL_VALIDATION, false, sig);
        } else {
            sig = ValidationLocatorLib.packSignature(entityId, globalOrNot == GLOBAL_VALIDATION, false, sig);
        }

        return sig;
    }

    // overload for the case where there are no pre validation hooks
    function _encodeSignature(ModuleEntity validationFunction, uint8 globalOrNot, bytes memory validationData)
        internal
        pure
        returns (bytes memory)
    {
        PreValidationHookData[] memory emptyPreValidationHookData = new PreValidationHookData[](0);
        return _encodeSignature(validationFunction, globalOrNot, emptyPreValidationHookData, validationData);
    }

    function _encode1271Signature(ModuleEntity validationFunction, bytes memory validationData)
        internal
        pure
        returns (bytes memory)
    {
        return _encode1271Signature(validationFunction, new PreValidationHookData[](0), validationData);
    }

    function _encode1271Signature(
        ModuleEntity validationFunction,
        PreValidationHookData[] memory perHookDatas,
        bytes memory validationData
    ) internal pure returns (bytes memory) {
        bytes memory sig = _packPreHookDatas(perHookDatas);

        sig = abi.encodePacked(sig, _packFinalSignature(validationData));

        (address module, uint32 entityId) = validationFunction.unpack();

        if (entityId == DIRECT_CALL_VALIDATION_ENTITYID) {
            sig = ValidationLocatorLib.packSignatureDirectCall(module, false, false, sig);
        } else {
            sig = ValidationLocatorLib.packSignature(entityId, false, false, sig);
        }

        return sig;
    }

    // helper function to pack pre validation hook datas, according to the sparse calldata segment spec.
    function _packPreHookDatas(PreValidationHookData[] memory preValidationHookData)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory res = "";

        for (uint256 i = 0; i < preValidationHookData.length; ++i) {
            res = abi.encodePacked(
                res,
                _packSignatureWithIndex(preValidationHookData[i].index, preValidationHookData[i].validationData)
            );
        }

        return res;
    }

    function _generatePreHooksDatasArray(bytes[] memory orderedHookDatas)
        internal
        pure
        returns (PreValidationHookData[] memory)
    {
        // Count the number of non-empty hook data segments
        uint256 count = 0;
        for (uint256 i = 0; i < orderedHookDatas.length; ++i) {
            if (orderedHookDatas[i].length > 0) {
                count++;
            }
        }

        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](count);

        uint256 j = 0;
        for (uint256 i = 0; i < orderedHookDatas.length; ++i) {
            if (orderedHookDatas[i].length > 0) {
                preValidationHookData[j] =
                    PreValidationHookData({index: uint8(i), validationData: orderedHookDatas[i]});
                j++;
            }
        }

        return preValidationHookData;
    }

    // helper function to pack validation data with an index, according to the sparse calldata segment spec.
    function _packSignatureWithIndex(uint8 index, bytes memory validationData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(index, uint32(validationData.length), validationData);
    }

    function _packFinalSignature(bytes memory sig) internal pure returns (bytes memory) {
        return abi.encodePacked(RESERVED_VALIDATION_DATA_INDEX, sig);
    }

    function _signRawHash(Vm vm, uint256 signingKey, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signingKey, hash);

        return abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v);
    }

    function _getModuleReplaySafeHash(address account, address validationModule, bytes32 digest)
        internal
        view
        returns (bytes32)
    {
        bytes32 domainSeparator =
            keccak256(abi.encode(_MODULE_DOMAIN_SEPARATOR, block.chainid, validationModule, account));

        return
            MessageHashUtils.toTypedDataHash({domainSeparator: domainSeparator, structHash: _hashStruct(digest)});
    }

    function _getSMAReplaySafeHash(address account, bytes32 digest) internal view returns (bytes32) {
        return MessageHashUtils.toTypedDataHash({
            domainSeparator: _computeDomainSeparator(account),
            structHash: _hashStruct(digest)
        });
    }

    function _encodeNonce(
        ModuleEntity validationFunction,
        bool isGlobal,
        bool hasDeferredAction,
        uint64 linearNonce
    ) internal pure returns (uint256) {
        (address module, uint32 entityId) = validationFunction.unpack();

        if (entityId == DIRECT_CALL_VALIDATION_ENTITYID) {
            return ValidationLocatorLib.packNonceDirectCall(module, isGlobal, hasDeferredAction) | linearNonce;
        } else {
            return ValidationLocatorLib.packNonce(entityId, isGlobal, hasDeferredAction) | linearNonce;
        }
    }

    function _encodeNonce(ModuleEntity validationFunction, bool isGlobal, uint64 linearNonce)
        internal
        pure
        returns (uint256)
    {
        return _encodeNonce(validationFunction, isGlobal, false, linearNonce);
    }

    function _encodeNonce(ModuleEntity validationFunction, ValidationType validationType, uint64 linearNonce)
        internal
        pure
        returns (uint256)
    {
        return _encodeNonce(validationFunction, validationType == ValidationType.GLOBAL, false, linearNonce);
    }

    function _encodeNonceDefAction(
        ModuleEntity validationFunction,
        ValidationType validationType,
        uint64 linearNonce
    ) internal pure returns (uint256) {
        return _encodeNonce(validationFunction, validationType == ValidationType.GLOBAL, true, linearNonce);
    }

    // Deferred validation helpers

    // Internal Helpers

    function _encodeDeferredInstallUOSignature(
        bytes memory packedDeferredInstallData,
        bytes memory deferredValidationInstallSig,
        bytes memory uoValidationSig
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            uint32(packedDeferredInstallData.length),
            packedDeferredInstallData,
            uint32(deferredValidationInstallSig.length),
            deferredValidationInstallSig,
            uoValidationSig
        );
    }

    function _packDeferredInstallData(
        uint256 nonce,
        uint48 deadline,
        ValidationConfig validationFunction,
        bytes memory call
    ) internal pure returns (bytes memory) {
        bytes memory deferredInstallData = abi.encodePacked(nonce, deadline, validationFunction, call);

        return deferredInstallData;
    }

    function _getDeferredInstallStruct(
        ModularAccount account,
        uint256 nonce,
        uint48 deadline,
        ValidationConfig validationFunction,
        bytes memory selfCall
    ) internal view returns (bytes32) {
        // Assumes this is not using the direct call path, and that isGlobal is true.
        ValidationLocator locator = ValidationLocatorLib.pack({
            _entityId: ValidationConfigLib.entityId(validationFunction),
            _isGlobal: true,
            _hasDeferredAction: true
        });

        bytes32 domainSeparator = _computeDomainSeparator(address(account));

        bytes32 selfCallHash = keccak256(selfCall);

        return MessageHashUtils.toTypedDataHash({
            domainSeparator: domainSeparator,
            structHash: keccak256(abi.encode(_DEFERRED_ACTION_TYPEHASH, nonce, deadline, locator, selfCallHash))
        });
    }

    // EIP-712 helpers for acount
    function _computeDomainSeparator(address account) internal view returns (bytes32) {
        return keccak256(abi.encode(_ACCOUNT_DOMAIN_SEPARATOR, block.chainid, account));
    }

    // EIP-712 helpers for acount
    function _hashStruct(bytes32 hash) internal pure virtual returns (bytes32) {
        return keccak256(abi.encode(_REPLAY_SAFE_HASH_TYPEHASH, hash));
    }
}
