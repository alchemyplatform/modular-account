// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {
    IModularAccount,
    ModuleEntity,
    ValidationConfig
} from "@erc-6900/reference-implementation/interfaces/IModularAccount.sol";

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {LibClone} from "solady/utils/LibClone.sol";

import {ModuleEntityLib} from "../helpers/ModuleEntityLib.sol";
import {ModularAccount} from "./ModularAccount.sol";

contract SemiModularAccount is ModularAccount {
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

    ModuleEntity internal constant _FALLBACK_VALIDATION = ModuleEntity.wrap(bytes24(type(uint192).max));

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    event FallbackSignerSet(address indexed previousFallbackSigner, address indexed newFallbackSigner);
    event FallbackSignerDisabledSet(bool prevDisabled, bool newDisabled);

    error FallbackSignerMismatch();
    error FallbackSignerDisabled();
    error InitializerDisabled();

    constructor(IEntryPoint anEntryPoint) ModularAccount(anEntryPoint) {}

    /// @notice Updates the fallback signer address in storage.
    /// @dev This function causes the fallback signer getter to ignore the bytecode signer if it is nonzero. It can
    /// also be used to revert back to the bytecode signer by setting to zero.
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

    /// Override reverts on initialization, effectively disabling the initializer.
    function initializeWithValidation(ValidationConfig, bytes4[] calldata, bytes calldata, bytes[] calldata)
        external
        pure
        override
    {
        revert InitializerDisabled();
    }

    /// @inheritdoc IModularAccount
    function accountId() external pure override returns (string memory) {
        return "alchemy.semi-modular-account.0.0.1";
    }

    function replaySafeHash(bytes32 hash) public view virtual returns (bytes32) {
        return
            MessageHashUtils.toTypedDataHash({domainSeparator: domainSeparator(), structHash: _hashStruct(hash)});
    }

    function _execUserOpValidation(
        ModuleEntity userOpValidationFunction,
        PackedUserOperation memory userOp,
        bytes32 userOpHash
    ) internal override returns (uint256) {
        if (userOpValidationFunction.eq(_FALLBACK_VALIDATION)) {
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
        if (runtimeValidationFunction.eq(_FALLBACK_VALIDATION)) {
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
        if (sigValidation.eq(_FALLBACK_VALIDATION)) {
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
        return validationFunction.eq(_FALLBACK_VALIDATION) || super._isValidationGlobal(validationFunction);
    }

    function _getFallbackSigner() internal view returns (address) {
        SemiModularAccountStorage storage _storage = _getSemiModularAccountStorage();

        if (_storage.fallbackSignerDisabled) {
            revert FallbackSignerDisabled();
        }

        return _retrieveFallbackSignerUnchecked(_storage);
    }

    function _retrieveFallbackSignerUnchecked(SemiModularAccountStorage storage _storage)
        internal
        view
        returns (address)
    {
        address storageFallbackSigner = _storage.fallbackSigner;
        if (storageFallbackSigner != address(0)) {
            return storageFallbackSigner;
        }

        bytes memory appendedData = LibClone.argsOnERC1967(address(this), 0, 20);

        return address(uint160(bytes20(appendedData)));
    }

    function _getSemiModularAccountStorage() internal pure returns (SemiModularAccountStorage storage) {
        SemiModularAccountStorage storage _storage;
        assembly ("memory-safe") {
            _storage.slot := _SEMI_MODULAR_ACCOUNT_STORAGE_SLOT
        }
        return _storage;
    }

    function _hashStruct(bytes32 hash) internal pure virtual returns (bytes32) {
        bytes32 res;
        assembly ("memory-safe") {
            mstore(0x00, _REPLAY_SAFE_HASH_TYPEHASH)
            mstore(0x20, hash)
            res := keccak256(0, 0x40)
        }
        return res;
    }
}
