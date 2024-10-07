// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {DIRECT_CALL_VALIDATION_ENTITYID} from "@erc6900/reference-implementation/helpers/Constants.sol";
import {ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {FALLBACK_VALIDATION} from "../helpers/Constants.sol";
import {SignatureType} from "../helpers/SignatureType.sol";
import {ERC7739ReplaySafeWrapperLib} from "../libraries/ERC7739ReplaySafeWrapperLib.sol";
import {RTCallBuffer, SigCallBuffer, UOCallBuffer} from "../libraries/ExecutionLib.sol";
import {SemiModularKnownSelectorsLib} from "../libraries/SemiModularKnownSelectorsLib.sol";
import {ModularAccountBase} from "./ModularAccountBase.sol";

abstract contract SemiModularAccountBase is ModularAccountBase {
    using MessageHashUtils for bytes32;
    using ModuleEntityLib for ModuleEntity;
    using ERC7739ReplaySafeWrapperLib for address;

    struct SemiModularAccountStorage {
        address fallbackSigner;
        bool fallbackSignerDisabled;
    }

    // keccak256("ERC6900.SemiModularAccount.Storage")
    uint256 internal constant _SEMI_MODULAR_ACCOUNT_STORAGE_SLOT =
        0x5b9dc9aa943f8fa2653ceceda5e3798f0686455280432166ba472eca0bc17a32;

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    event FallbackSignerUpdated(address indexed newFallbackSigner, bool isDisabled);

    error FallbackSignerMismatch();
    error FallbackSignerDisabled();
    error InitializerDisabled();
    error InvalidSignatureType();

    constructor(IEntryPoint anEntryPoint) ModularAccountBase(anEntryPoint) {}

    /// @notice Updates the fallback signer data in storage.
    /// @param fallbackSigner The new signer to set.
    /// @param isDisabled Whether to disable fallback signing entirely.
    function updateFallbackSignerData(address fallbackSigner, bool isDisabled) external wrapNativeFunction {
        SemiModularAccountStorage storage _storage = _getSemiModularAccountStorage();

        _storage.fallbackSigner = fallbackSigner;
        _storage.fallbackSignerDisabled = isDisabled;

        emit FallbackSignerUpdated(fallbackSigner, isDisabled);
    }

    /// @notice Returns the fallback signer data in storage.
    /// @return The fallback signer and a boolean, true if the fallback signer validation is disabled, false if it
    /// is enabled.
    function getFallbackSignerData() external view returns (address, bool) {
        SemiModularAccountStorage storage _storage = _getSemiModularAccountStorage();
        return (_retrieveFallbackSignerUnchecked(_storage), _storage.fallbackSignerDisabled);
    }

    function _execUserOpValidation(
        ModuleEntity userOpValidationFunction,
        bytes32 userOpHash,
        bytes calldata signatureSegment,
        UOCallBuffer callBuffer
    ) internal override returns (uint256) {
        if (userOpValidationFunction.eq(FALLBACK_VALIDATION)) {
            address fallbackSigner = _getFallbackSigner();

            if (_checkSignature(fallbackSigner, userOpHash.toEthSignedMessageHash(), signatureSegment)) {
                return _SIG_VALIDATION_PASSED;
            }
            return _SIG_VALIDATION_FAILED;
        }

        return super._execUserOpValidation(userOpValidationFunction, userOpHash, signatureSegment, callBuffer);
    }

    function _execRuntimeValidation(
        ModuleEntity runtimeValidationFunction,
        RTCallBuffer callBuffer,
        bytes calldata authorization
    ) internal override {
        if (runtimeValidationFunction.eq(FALLBACK_VALIDATION)) {
            address fallbackSigner = _getFallbackSigner();

            if (msg.sender != fallbackSigner) {
                revert FallbackSignerMismatch();
            }
        } else {
            super._execRuntimeValidation(runtimeValidationFunction, callBuffer, authorization);
        }
    }

    function _exec1271Validation(
        SigCallBuffer buffer,
        bytes32 hash,
        ModuleEntity sigValidation,
        bytes calldata signature
    ) internal view override returns (bytes4) {
        if (sigValidation.eq(FALLBACK_VALIDATION)) {
            address fallbackSigner = _getFallbackSigner();

            (bytes32 digest, bytes calldata innerSignature) =
                address(this).validateERC7739SigFormatForAccount(hash, signature);
            if (_checkSignature(fallbackSigner, digest, innerSignature)) {
                return _1271_MAGIC_VALUE;
            }
            return _1271_INVALID;
        }
        return super._exec1271Validation(buffer, hash, sigValidation, signature);
    }

    function _checkSignature(address owner, bytes32 digest, bytes calldata sig) internal view returns (bool) {
        if (sig.length < 1) {
            revert InvalidSignatureType();
        }
        SignatureType sigType = SignatureType(uint8(bytes1(sig)));
        sig = sig[1:];
        if (sigType == SignatureType.EOA) {
            (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig);
            if (err == ECDSA.RecoverError.NoError && recovered == owner) {
                return true;
            }
            return false;
        } else if (sigType == SignatureType.CONTRACT_OWNER) {
            return SignatureChecker.isValidERC1271SignatureNow(owner, digest, sig);
        }
        revert InvalidSignatureType();
    }

    function _globalValidationAllowed(bytes4 selector) internal view override returns (bool) {
        return selector == this.updateFallbackSignerData.selector || super._globalValidationAllowed(selector);
    }

    function _isValidationGlobal(ModuleEntity validationFunction) internal view override returns (bool) {
        if (validationFunction.eq(FALLBACK_VALIDATION) || super._isValidationGlobal(validationFunction)) {
            return true;
        }

        // At this point, the validation is not the fallback, and it's not an installed global validation.
        SemiModularAccountStorage storage smaStorage = _getSemiModularAccountStorage();

        // Before checking direct-call validation, we return false if fallback validation is disabled.
        if (smaStorage.fallbackSignerDisabled) {
            return false;
        }

        // Retrieve the fallback signer.
        address fallbackSigner = _retrieveFallbackSignerUnchecked(smaStorage);

        // Compute the direct call validation key.
        ModuleEntity fallbackDirectCallValidation =
            ModuleEntityLib.pack(fallbackSigner, DIRECT_CALL_VALIDATION_ENTITYID);

        // Return true if the validation function passed is the fallback direct call validation key, and the sender
        // is the fallback signer. This enforces that context is a
        return validationFunction.eq(fallbackDirectCallValidation) && msg.sender == fallbackSigner;
    }

    function _getFallbackSigner() internal view returns (address) {
        SemiModularAccountStorage storage _storage = _getSemiModularAccountStorage();

        if (_storage.fallbackSignerDisabled) {
            revert FallbackSignerDisabled();
        }

        // This can return zero.
        return _retrieveFallbackSignerUnchecked(_storage);
    }

    /// @dev SMA implementations must implement their own fallback signer getter.
    ///
    /// NOTE: The passed storage pointer may point to a struct with a zero address signer. It's up
    /// to inheritors to determine what to do with that information. No assumptions about storage
    /// state are safe to make besides layout.
    function _retrieveFallbackSignerUnchecked(SemiModularAccountStorage storage _storage)
        internal
        view
        virtual
        returns (address)
    {
        return _storage.fallbackSigner;
    }

    function _getSemiModularAccountStorage() internal pure returns (SemiModularAccountStorage storage) {
        SemiModularAccountStorage storage _storage;
        assembly ("memory-safe") {
            _storage.slot := _SEMI_MODULAR_ACCOUNT_STORAGE_SLOT
        }
        return _storage;
    }

    // Overrides ModuleManagerInternals
    function _isNativeFunction(bytes4 selector) internal pure override returns (bool) {
        return SemiModularKnownSelectorsLib.isNativeFunction(selector);
    }

    // Conditionally skip allocation of call buffers.
    function _validationIsNative(ModuleEntity validationFunction) internal pure virtual override returns (bool) {
        return validationFunction.eq(FALLBACK_VALIDATION);
    }
}
