// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Vm} from "forge-std/src/Vm.sol";

import {RESERVED_VALIDATION_DATA_INDEX} from "@erc6900/reference-implementation/helpers/Constants.sol";
import {ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfig} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {ERC7739ReplaySafeWrapperLib} from "../../src/libraries/ERC7739ReplaySafeWrapperLib.sol";

/// @dev Utilities for encoding signatures for modular account validation. Used for encoding user op, runtime, and
/// 1271 signatures.
contract ModuleSignatureUtils {
    using ModuleEntityLib for ModuleEntity;
    using ERC7739ReplaySafeWrapperLib for address;

    struct PreValidationHookData {
        uint8 index;
        bytes validationData;
    }

    uint8 public constant SELECTOR_ASSOCIATED_VALIDATION = 0;
    uint8 public constant GLOBAL_VALIDATION = 1;
    uint8 public constant EOA_TYPE_SIGNATURE = 0;

    bytes32 private constant _DEFERRED_ACTION_TYPEHASH =
        keccak256("DeferredAction(uint256 nonce,uint48 deadline,bytes25 validationFunction,bytes call)");

    // 712 for a Mock App
    string internal constant _MOCK_APP_CONTENTS_TYPE = "Message(string message)"; // len 23
    bytes32 internal constant _MOCK_APP_DOMAIN = 0x71062c282d40422f744945d587dbf4ecfd4f9cfad1d35d62c944373009d96162;

    string internal constant _DEFERRED_ACTION_CONTENTS_TYPE =
        "DeferredAction(uint256 nonce,uint48 deadline,bytes25 validationFunction,bytes call)";

    function _getMockApp712Contents(bytes32 _digest)
        internal
        pure
        returns (bytes32 mockAppStructHash, bytes32 mockAppDigest)
    {
        mockAppStructHash = keccak256(abi.encode(keccak256(abi.encodePacked(_MOCK_APP_CONTENTS_TYPE)), _digest));
        mockAppDigest = keccak256(abi.encodePacked(bytes2(hex"1901"), _MOCK_APP_DOMAIN, mockAppStructHash));
    }

    function generate1271DigestForModule(
        address account,
        address module,
        bytes32 mockAppDigest,
        bytes calldata sig
    ) external view returns (bytes32 digest) {
        (digest,) = account.validateERC7739SigFormatForModule(module, mockAppDigest, sig);
    }

    function generate1271DigestForAccount(address account, bytes32 mockAppDigest, bytes calldata sig)
        external
        view
        returns (bytes32 digest)
    {
        (digest,) = account.validateERC7739SigFormatForAccount(mockAppDigest, sig);
    }

    function _encode1271Signature(ModuleEntity validationFunction, bytes memory validationData, bytes32 structHash)
        internal
        pure
        returns (bytes memory)
    {
        return _encode1271Signature(
            validationFunction,
            new PreValidationHookData[](0),
            validationData,
            _MOCK_APP_DOMAIN,
            structHash,
            _MOCK_APP_CONTENTS_TYPE
        );
    }

    function _encode1271Signature(
        ModuleEntity validationFunction,
        PreValidationHookData[] memory preValidationHookData,
        bytes memory validationData,
        bytes32 mockAppStructHash
    ) internal pure returns (bytes memory) {
        return _encode1271Signature(
            validationFunction,
            preValidationHookData,
            validationData,
            _MOCK_APP_DOMAIN,
            mockAppStructHash,
            _MOCK_APP_CONTENTS_TYPE
        );
    }

    // helper function to encode a 1271 signature, according to the per-hook and per-validation data format.
    function _encode1271Signature(
        ModuleEntity validationFunction,
        PreValidationHookData[] memory preValidationHookData,
        bytes memory validationData,
        bytes32 appDomain,
        bytes32 appContents,
        string memory contentsType
    ) internal pure returns (bytes memory) {
        bytes memory sig = abi.encodePacked(validationFunction);

        sig = abi.encodePacked(sig, _packPreHookDatas(preValidationHookData));

        sig = abi.encodePacked(sig, _packFinal1271Signature(validationData, appDomain, appContents, contentsType));

        return sig;
    }

    // From
    // github/Vectorized/solady/blob/4676345386dab5728e2da9a6540f6cd308a9f4d5/src/accounts/ERC1271.sol#L157-L158
    // The signature will be `r ‖ s ‖ v ‖
    // APP_DOMAIN_SEPARATOR ‖ contents ‖ contentsType ‖ uint16(contentsType.length)`,
    function _packFinal1271Signature(
        bytes memory sig,
        bytes32 appDomain,
        bytes32 appStructHash,
        string memory contentsType
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            RESERVED_VALIDATION_DATA_INDEX,
            sig,
            appDomain,
            appStructHash,
            contentsType,
            uint16(bytes(contentsType).length)
        );
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
    function _encode1271Signature(
        ModuleEntity validationFunction,
        bytes memory validationData,
        bytes32 domainSeparator,
        bytes32 contents,
        string memory contentsType
    ) internal pure returns (bytes memory) {
        PreValidationHookData[] memory emptyPreValidationHookData = new PreValidationHookData[](0);
        return _encode1271Signature(
            validationFunction, emptyPreValidationHookData, validationData, domainSeparator, contents, contentsType
        );
    }

    // Helper function for webauthn plugin. This provides a 1271 sig for a ReplaySafeWrapper, instead of the
    // ERC7739 sig
    function _encode1271Signature(ModuleEntity validationFunction, bytes memory validationData)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory sig = abi.encodePacked(validationFunction);

        sig = abi.encodePacked(sig, _packPreHookDatas(new PreValidationHookData[](0)));

        sig = abi.encodePacked(sig, _packFinalSignature(validationData));

        return sig;
    }

    function _encode1271Signature(
        ModuleEntity validationFunction,
        PreValidationHookData[] memory perHookDatas,
        bytes memory validationData
    ) internal pure returns (bytes memory) {
        bytes memory sig = abi.encodePacked(validationFunction);

        sig = abi.encodePacked(sig, _packPreHookDatas(perHookDatas));

        sig = abi.encodePacked(sig, _packFinalSignature(validationData));

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

    function _getModuleReplaySafeHash(
        address account,
        address validationModule,
        bytes32 domainSeparator,
        bytes32 appStructHash,
        bytes32 digest,
        string memory contentsType
    ) internal view returns (bytes32) {
        bytes memory sig =
            abi.encodePacked(domainSeparator, appStructHash, contentsType, uint16(bytes(contentsType).length));
        return this.generate1271DigestForModule(account, validationModule, digest, sig);
    }

    function _getSMAReplaySafeHash(
        address account,
        bytes32 domainSeparator,
        bytes32 appStructHash,
        bytes32 digest,
        string memory contentsType
    ) internal view returns (bytes32) {
        bytes memory sig =
            abi.encodePacked(domainSeparator, appStructHash, contentsType, uint16(bytes(contentsType).length));
        return this.generate1271DigestForAccount(account, digest, sig);
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

    function _getDeferredInstallStructAndHash(
        ModularAccount account,
        uint256 nonce,
        uint48 deadline,
        ValidationConfig validationFunction,
        bytes memory selfCall
    ) internal view returns (bytes32 structHash, bytes32 typedDataHash, bytes32 domainSeparator) {
        domainSeparator = _computeDomainSeparator(address(account));

        bytes32 selfCallHash = keccak256(selfCall);

        structHash =
            keccak256(abi.encode(_DEFERRED_ACTION_TYPEHASH, nonce, deadline, validationFunction, selfCallHash));

        typedDataHash = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
    }

    // EIP-712 helpers

    function _computeDomainSeparator(address account) internal view returns (bytes32) {
        return keccak256(
            abi.encode(ERC7739ReplaySafeWrapperLib._DOMAIN_SEPARATOR_TYPEHASH_ACCOUNT, block.chainid, account)
        );
    }
}
