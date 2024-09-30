// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {IModularAccount, ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {FALLBACK_VALIDATION} from "../helpers/Constants.sol";
import {ModuleEntityLib} from "../libraries/ModuleEntityLib.sol";
import {ModularAccountBase} from "./ModularAccountBase.sol";

abstract contract SemiModularAccountBase is ModularAccountBase {
    using MessageHashUtils for bytes32;
    using ModuleEntityLib for ModuleEntity;

    struct SemiModularAccountStorage {
        address fallbackSigner;
        bool fallbackSignerDisabled;
    }

    // keccak256("ERC6900.SemiModularAccount.Storage")
    uint256 internal constant _SEMI_MODULAR_ACCOUNT_STORAGE_SLOT =
        0x5b9dc9aa943f8fa2653ceceda5e3798f0686455280432166ba472eca0bc17a32;

    // keccak256("ReplaySafeHash(bytes32 hash)")
    bytes32 private constant _REPLAY_SAFE_HASH_TYPEHASH =
        0x294a8735843d4afb4f017c76faf3b7731def145ed0025fc9b1d5ce30adf113ff;

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    event FallbackSignerSet(address indexed previousFallbackSigner, address indexed newFallbackSigner);
    event FallbackSignerDisabledSet(bool prevDisabled, bool newDisabled);

    error FallbackSignerMismatch();
    error FallbackSignerDisabled();
    error InitializerDisabled();

    constructor(IEntryPoint anEntryPoint) ModularAccountBase(anEntryPoint) {}

    /// @notice Updates the fallback signer address in storage.
    /// @param fallbackSigner The new signer to set.
    function updateFallbackSigner(address fallbackSigner) external wrapNativeFunction {
        SemiModularAccountStorage storage _storage = _getSemiModularAccountStorage();
        emit FallbackSignerSet(_storage.fallbackSigner, fallbackSigner);

        _storage.fallbackSigner = fallbackSigner;
    }

    /// @notice Sets whether the fallback signer validation should be enabled or disabled.
    /// @dev Due to being initially zero, we need to store "disabled" rather than "enabled" in storage.
    /// @param isDisabled True to disable fallback signer validation, false to enable it.
    function setFallbackSignerDisabled(bool isDisabled) external wrapNativeFunction {
        SemiModularAccountStorage storage _storage = _getSemiModularAccountStorage();
        emit FallbackSignerDisabledSet(_storage.fallbackSignerDisabled, isDisabled);

        _storage.fallbackSignerDisabled = isDisabled;
    }

    /// @notice Returns whether the fallback signer validation is disabled.
    /// @return True if the fallback signer validation is disabled, false if it is enabled.
    function isFallbackSignerDisabled() external view returns (bool) {
        return _getSemiModularAccountStorage().fallbackSignerDisabled;
    }

    /// @notice Returns the fallback signer associated with this account, regardless if the fallback signer
    /// validation is enabled or not.
    /// @return The fallback signer address, either overriden in storage, or read from bytecode.
    function getFallbackSigner() external view returns (address) {
        return _retrieveFallbackSignerUnchecked(_getSemiModularAccountStorage());
    }

    /// @inheritdoc IModularAccount
    function accountId() external pure override returns (string memory) {
        return "alchemy.semi-modular-account.0.0.1";
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
    function replaySafeHash(bytes32 hash) public view virtual returns (bytes32) {
        return MessageHashUtils.toTypedDataHash({
            domainSeparator: domainSeparator(),
            structHash: _hashStructReplaySafeHash(hash)
        });
    }

    function _execUserOpValidation(
        ModuleEntity userOpValidationFunction,
        PackedUserOperation memory userOp,
        bytes32 userOpHash
    ) internal override returns (uint256) {
        if (userOpValidationFunction.eq(FALLBACK_VALIDATION)) {
            address fallbackSigner = _getFallbackSigner();

            if (
                SignatureChecker.isValidSignatureNow(
                    fallbackSigner, userOpHash.toEthSignedMessageHash(), userOp.signature
                )
            ) {
                return _SIG_VALIDATION_PASSED;
            }
            return _SIG_VALIDATION_FAILED;
        }

        return super._execUserOpValidation(userOpValidationFunction, userOp, userOpHash);
    }

    function _execRuntimeValidation(
        ModuleEntity runtimeValidationFunction,
        bytes calldata callData,
        bytes calldata authorization
    ) internal override {
        if (runtimeValidationFunction.eq(FALLBACK_VALIDATION)) {
            address fallbackSigner = _getFallbackSigner();

            if (msg.sender != fallbackSigner) {
                revert FallbackSignerMismatch();
            }
        } else {
            super._execRuntimeValidation(runtimeValidationFunction, callData, authorization);
        }
    }

    function _exec1271Validation(ModuleEntity sigValidation, bytes32 hash, bytes calldata signature)
        internal
        view
        override
        returns (bytes4)
    {
        if (sigValidation.eq(FALLBACK_VALIDATION)) {
            address fallbackSigner = _getFallbackSigner();

            if (SignatureChecker.isValidSignatureNow(fallbackSigner, replaySafeHash(hash), signature)) {
                return _1271_MAGIC_VALUE;
            }
            return _1271_INVALID;
        }
        return super._exec1271Validation(sigValidation, hash, signature);
    }

    function _globalValidationAllowed(bytes4 selector) internal view override returns (bool) {
        return selector == this.setFallbackSignerDisabled.selector
            || selector == this.updateFallbackSigner.selector || super._globalValidationAllowed(selector);
    }

    function _isValidationGlobal(ModuleEntity validationFunction) internal view override returns (bool) {
        return validationFunction.eq(FALLBACK_VALIDATION) || super._isValidationGlobal(validationFunction);
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
        returns (address) {
            return _storage.fallbackSigner;
        }

    function _getSemiModularAccountStorage() internal pure returns (SemiModularAccountStorage storage) {
        SemiModularAccountStorage storage _storage;
        assembly ("memory-safe") {
            _storage.slot := _SEMI_MODULAR_ACCOUNT_STORAGE_SLOT
        }
        return _storage;
    }

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
