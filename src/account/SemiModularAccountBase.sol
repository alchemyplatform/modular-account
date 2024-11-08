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
import {RTCallBuffer, SigCallBuffer, UOCallBuffer} from "../libraries/ExecutionLib.sol";
import {ModularAccountBase} from "./ModularAccountBase.sol";

/// @title Semi-Modular Account Base
/// @author Alchemy
/// @notice Abstract base contract for the Alchemy Semi-Modular Account variants. Includes fallback signer
/// functionality.
/// @dev Inherits ModularAccountBase. Overrides certain functionality from ModularAccountBase, and exposes an
/// internal virtual getter for the fallback signer.
abstract contract SemiModularAccountBase is ModularAccountBase {
    using MessageHashUtils for bytes32;
    using ModuleEntityLib for ModuleEntity;

    struct SemiModularAccountStorage {
        address fallbackSigner;
        bool fallbackSignerDisabled;
    }

    // keccak256("ReplaySafeHash(bytes32 hash)")
    bytes32 private constant _REPLAY_SAFE_HASH_TYPEHASH =
        0x294a8735843d4afb4f017c76faf3b7731def145ed0025fc9b1d5ce30adf113ff;

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

            // If called during validateUserOp, this implies that we're doing a deferred validation installation.
            // In this case, as the hash is already replay-safe, we don't need to wrap it.
            if (msg.sig != this.validateUserOp.selector) {
                hash = _replaySafeHash(hash);
            }

            if (_checkSignature(fallbackSigner, hash, signature)) {
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

    // overrides ModularAccountView
    function _isNativeFunction(uint32 selector) internal view override returns (bool) {
        return super._isNativeFunction(selector) || selector == uint32(this.updateFallbackSignerData.selector)
            || selector == uint32(this.getFallbackSignerData.selector);
    }

    /// @notice Returns the replay-safe hash generated from the passed typed data hash for 1271 validation.
    /// @param hash The typed data hash to wrap in a replay-safe hash.
    /// @return The replay-safe hash, to be used for 1271 signature generation.
    ///
    /// @dev Generates a replay-safe hash to wrap a standard typed data hash. This prevents replay attacks by
    /// enforcing the domain separator, which includes this contract's address and the chainId. This is only
    /// relevant for 1271 validation because UserOp validation relies on the UO hash and the Entrypoint has
    /// safeguards.
    ///
    /// NOTE: Like in signature-based validation modules, the returned hash should be used to generate signatures,
    /// but the original hash should be passed to the external-facing function for 1271 validation.
    function _replaySafeHash(bytes32 hash) internal view returns (bytes32) {
        return MessageHashUtils.toTypedDataHash({
            domainSeparator: _domainSeparator(),
            structHash: _hashStructReplaySafeHash(hash)
        });
    }

    function _getSemiModularAccountStorage() internal pure returns (SemiModularAccountStorage storage) {
        SemiModularAccountStorage storage _storage;
        assembly ("memory-safe") {
            _storage.slot := _SEMI_MODULAR_ACCOUNT_STORAGE_SLOT
        }
        return _storage;
    }

    // Conditionally skip allocation of call buffers.
    function _validationIsNative(ModuleEntity validationFunction) internal pure virtual override returns (bool) {
        return validationFunction.eq(FALLBACK_VALIDATION);
    }

    /// @notice Adds a EIP-712 replay safe hash wrapper to the digest
    /// @param hash The hash to wrap in a replay-safe hash
    /// @return The replay-safe hash
    function _hashStructReplaySafeHash(bytes32 hash) internal pure virtual returns (bytes32) {
        bytes32 res;
        assembly ("memory-safe") {
            mstore(0x00, _REPLAY_SAFE_HASH_TYPEHASH)
            mstore(0x20, hash)
            res := keccak256(0, 0x40)
        }
        return res;
    }
}
