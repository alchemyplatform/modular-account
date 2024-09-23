// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {ModuleEntity} from "../../src/libraries/ModuleEntityLib.sol";

/// @dev Utilities for encoding signatures for modular account validation. Used for encoding user op, runtime, and
/// 1271 signatures.
contract ModuleSignatureUtils {
    struct PreValidationHookData {
        uint8 index;
        bytes validationData;
    }

    uint8 public constant SELECTOR_ASSOCIATED_VALIDATION = 0;
    uint8 public constant GLOBAL_VALIDATION = 1;

    // helper function to encode a 1271 signature, according to the per-hook and per-validation data format.
    function _encode1271Signature(
        ModuleEntity validationFunction,
        PreValidationHookData[] memory preValidationHookData,
        bytes memory validationData
    ) internal pure returns (bytes memory) {
        bytes memory sig = abi.encodePacked(validationFunction);

        sig = abi.encodePacked(sig, _packPreHookDatas(preValidationHookData));

        sig = abi.encodePacked(sig, _packValidationResWithIndex(255, validationData));

        return sig;
    }

    // helper function to encode a signature, according to the per-hook and per-validation data format.
    function _encodeSignature(
        ModuleEntity validationFunction,
        uint8 globalOrNot,
        PreValidationHookData[] memory preValidationHookData,
        bytes memory validationData
    ) internal pure returns (bytes memory) {
        bytes memory sig = abi.encodePacked(validationFunction, globalOrNot);

        sig = abi.encodePacked(sig, _packPreHookDatas(preValidationHookData));

        sig = abi.encodePacked(sig, _packValidationResWithIndex(255, validationData));

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

    // overload for the case where there are no pre validation hooks
    function _encode1271Signature(ModuleEntity validationFunction, bytes memory validationData)
        internal
        pure
        returns (bytes memory)
    {
        PreValidationHookData[] memory emptyPreValidationHookData = new PreValidationHookData[](0);
        return _encode1271Signature(validationFunction, emptyPreValidationHookData, validationData);
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
                _packValidationResWithIndex(
                    preValidationHookData[i].index, preValidationHookData[i].validationData
                )
            );
        }

        return res;
    }

    // helper function to pack validation data with an index, according to the sparse calldata segment spec.
    function _packValidationResWithIndex(uint8 index, bytes memory validationData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(uint32(validationData.length + 1), index, validationData);
    }
}
