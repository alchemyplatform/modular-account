// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Vm} from "forge-std/src/Vm.sol";

import {RESERVED_VALIDATION_DATA_INDEX} from "@erc6900/reference-implementation/helpers/Constants.sol";
import {ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfig} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {SemiModularAccountBytecode} from "../../src/account/SemiModularAccountBytecode.sol";
import {ECDSAValidationModule} from "../../src/modules/validation/ECDSAValidationModule.sol";

/// @dev Utilities for encoding signatures for modular account validation. Used for encoding user op, runtime, and
/// 1271 signatures.
contract ModuleSignatureUtils {
    using ModuleEntityLib for ModuleEntity;

    struct PreValidationHookData {
        uint8 index;
        bytes validationData;
    }

    uint8 public constant SELECTOR_ASSOCIATED_VALIDATION = 0;
    uint8 public constant GLOBAL_VALIDATION = 1;
    uint8 public constant EOA_TYPE_SIGNATURE = 0;

    bytes32 private constant _DEFERRED_ACTION_TYPEHASH =
        keccak256("DeferredAction(uint256 nonce,uint48 deadline,bytes25 validationFunction,bytes call)");

    // helper function to encode a 1271 signature, according to the per-hook and per-validation data format.
    function _encode1271Signature(
        ModuleEntity validationFunction,
        PreValidationHookData[] memory preValidationHookData,
        bytes memory validationData
    ) internal pure returns (bytes memory) {
        bytes memory sig = abi.encodePacked(validationFunction);

        sig = abi.encodePacked(sig, _packPreHookDatas(preValidationHookData));

        sig = abi.encodePacked(sig, _packFinalSignature(validationData));

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

        sig = abi.encodePacked(sig, _packFinalSignature(validationData));

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

    function _getECDSAReplaySafeHash(
        ModularAccount account,
        ECDSAValidationModule validationModule,
        bytes32 typedDataHash
    ) internal view returns (bytes32) {
        return validationModule.replaySafeHash(address(account), typedDataHash);
    }

    function _getSMAReplaySafeHash(ModularAccount account, bytes32 typedDataHash)
        internal
        view
        returns (bytes32)
    {
        if (address(account).code.length > 0) {
            return SemiModularAccountBytecode(payable(account)).replaySafeHash(typedDataHash);
        } else {
            // precompute it as the SMA is not yet deployed
            // for SMA, the domain separator used for the deferred validation installation is the same as the one
            // used to compute the replay safe hash.
            return MessageHashUtils.toTypedDataHash({
                domainSeparator: _computeDomainSeparator(account),
                structHash: _hashStructReplaySafeHash(typedDataHash)
            });
        }
    }

    // Deferred validation helpers

    // Internal Helpers

    function _encodeDeferredInstallUOSignature(
        ModuleEntity installAuthorizingValidation,
        uint8 globalOrNot,
        bytes memory packedDeferredInstallData,
        bytes memory deferredValidationInstallSig,
        bytes memory uoValidationSig
    ) internal pure returns (bytes memory) {
        uint8 outerValidationFlags = 2 | globalOrNot;

        return abi.encodePacked(
            installAuthorizingValidation,
            outerValidationFlags,
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

    function _getDeferredInstallHash(
        ModularAccount account,
        uint256 nonce,
        uint48 deadline,
        ValidationConfig validationFunction,
        bytes memory selfCall
    ) internal view returns (bytes32) {
        bytes32 domainSeparator = _computeDomainSeparator(account);

        bytes32 selfCallHash = keccak256(selfCall);

        bytes32 structHash =
            keccak256(abi.encode(_DEFERRED_ACTION_TYPEHASH, nonce, deadline, validationFunction, selfCallHash));

        bytes32 typedDataHash = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

        return typedDataHash;
    }

    // EIP-712 helpers

    function _computeDomainSeparator(ModularAccount account) internal view returns (bytes32) {
        bytes32 domainSeparatorTypehash = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
        return keccak256(abi.encode(domainSeparatorTypehash, block.chainid, address(account)));
    }

    function _hashStructReplaySafeHash(bytes32 hash) internal pure returns (bytes32) {
        bytes32 replaySafeTypehash = keccak256("ReplaySafeHash(bytes32 hash)"); // const 0x.. in contract
        return keccak256(abi.encode(replaySafeTypehash, hash));
    }
}
