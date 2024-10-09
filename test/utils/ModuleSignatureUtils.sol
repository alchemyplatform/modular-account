// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {SemiModularAccountBytecode} from "../../src/account/SemiModularAccountBytecode.sol";

import {RESERVED_VALIDATION_DATA_INDEX} from "../../src/helpers/Constants.sol";
import {ModuleEntity, ModuleEntityLib} from "../../src/libraries/ModuleEntityLib.sol";
import {ValidationConfig, ValidationConfigLib} from "../../src/libraries/ValidationConfigLib.sol";
import {ECDSAValidationModule} from "../../src/modules/validation/ECDSAValidationModule.sol";

import {Vm} from "forge-std/src/Vm.sol";

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

    bytes32 private constant _INSTALL_VALIDATION_TYPEHASH = keccak256(
        "InstallValidation(bytes25 validationConfig,bytes4[] selectors,bytes installData,bytes[] hooks,"
        "uint256 nonce,uint48 deadline)"
    );

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

    // Deferred validation helpers

    // Internal Helpers
    function _buildFullDeferredInstallSig(
        Vm vm,
        uint256 ownerKey,
        bool isSMATest,
        ModularAccount account,
        ModuleEntity outerECDSAValidation,
        ModuleEntity deferredValidation,
        bytes memory deferredValidationInstallData,
        bytes memory deferredValidationSig,
        uint256 nonce,
        uint48 deadline
    ) internal view returns (bytes memory) {
        uint8 outerECDSAValidationFlags = 3;

        ValidationConfig deferredConfig = ValidationConfigLib.pack({
            _validationFunction: deferredValidation,
            _isGlobal: true,
            _isSignatureValidation: false,
            _isUserOpValidation: true
        });

        bytes memory deferredInstallData = abi.encode(
            deferredConfig, new bytes4[](0), deferredValidationInstallData, new bytes[](0), nonce, deadline
        );

        bytes memory deferredInstallSig = _getDeferredInstallSig(
            vm,
            ownerKey,
            isSMATest,
            account,
            outerECDSAValidation,
            deferredConfig,
            deferredValidationInstallData,
            nonce,
            deadline
        );

        bytes memory innerUoValidationSig = _packFinalSignature(deferredValidationSig);

        bytes memory encodedDeferredInstall = abi.encodePacked(
            outerECDSAValidation,
            outerECDSAValidationFlags,
            uint32(deferredInstallData.length),
            deferredInstallData,
            uint32(deferredInstallSig.length),
            deferredInstallSig,
            innerUoValidationSig
        );

        return encodedDeferredInstall;
    }

    function _getReplaySafeHash(
        bool isSMATest,
        ModularAccount account,
        ModuleEntity outerECDSAValidation,
        ValidationConfig deferredConfig,
        bytes memory deferredValidationInstallData,
        uint256 nonce,
        uint48 deadline
    ) internal view returns (bytes32) {
        bytes32 domainSeparator;

        // Needed for initCode txs
        if (address(account).code.length > 0) {
            domainSeparator = account.domainSeparator();
        } else {
            domainSeparator = _computeDomainSeparatorNotDeployed(account);
        }

        bytes32 structHash = keccak256(
            abi.encode(
                _INSTALL_VALIDATION_TYPEHASH,
                deferredConfig,
                new bytes4[](0),
                deferredValidationInstallData,
                new bytes[](0),
                nonce,
                deadline
            )
        );
        bytes32 typedDataHash = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

        (address outerECDSAValidationAddr,) = outerECDSAValidation.unpack();

        bytes32 replaySafeHash = isSMATest
            ? _getSmaReplaySafeHash(account, typedDataHash)
            : ECDSAValidationModule(outerECDSAValidationAddr).replaySafeHash(address(account), typedDataHash);

        return replaySafeHash;
    }

    function _computeDomainSeparatorNotDeployed(ModularAccount account) internal view returns (bytes32) {
        bytes32 domainSeparatorTypehash = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;
        return keccak256(abi.encode(domainSeparatorTypehash, block.chainid, address(account)));
    }

    function _getSmaReplaySafeHash(ModularAccount account, bytes32 typedDataHash)
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
                domainSeparator: _computeDomainSeparatorNotDeployed(account),
                structHash: _hashStructReplaySafeHash(typedDataHash)
            });
        }
    }

    function _getDeferredInstallSig(
        Vm vm,
        uint256 ownerKey,
        bool isSMATest,
        ModularAccount account,
        ModuleEntity outerECDSAValidation,
        ValidationConfig deferredConfig,
        bytes memory deferredValidationInstallData,
        uint256 nonce,
        uint48 deadline
    ) internal view returns (bytes memory) {
        bytes32 replaySafeHash = _getReplaySafeHash(
            isSMATest,
            account,
            outerECDSAValidation,
            deferredConfig,
            deferredValidationInstallData,
            nonce,
            deadline
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, replaySafeHash);

        bytes memory rawDeferredInstallSig = abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v);

        bytes memory deferredInstallSig = _packFinalSignature(rawDeferredInstallSig);
        return deferredInstallSig;
    }

    function _hashStructReplaySafeHash(bytes32 hash) internal pure returns (bytes32) {
        bytes32 replaySafeTypehash = keccak256("ReplaySafeHash(bytes32 hash)"); // const 0x.. in contract
        bytes32 res;
        assembly ("memory-safe") {
            mstore(0x00, replaySafeTypehash)
            mstore(0x20, hash)
            res := keccak256(0, 0x40)
        }
        return res;
    }
}
