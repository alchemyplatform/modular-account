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

pragma solidity ^0.8.28;

import {ModuleEntity, ValidationConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {FALLBACK_VALIDATION_ID, FALLBACK_VALIDATION_LOOKUP_KEY} from "../helpers/Constants.sol";
import {ExecutionInstallDelegate} from "../helpers/ExecutionInstallDelegate.sol";
import {SignatureType} from "../helpers/SignatureType.sol";
import {RTCallBuffer, SigCallBuffer, UOCallBuffer} from "../libraries/ExecutionLib.sol";
import {ValidationLocatorLib, ValidationLookupKey} from "../libraries/ValidationLocatorLib.sol";
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
    using ValidationConfigLib for ValidationConfig;

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
    error FallbackValidationInstallationNotAllowed();
    error FallbackSignerDisabled();
    error InvalidSignatureType();

    constructor(IEntryPoint entryPoint, ExecutionInstallDelegate executionInstallDelegate)
        ModularAccountBase(entryPoint, executionInstallDelegate)
    {}

    /// @notice Updates the fallback signer data in storage.
    /// @param fallbackSigner The new signer to set.
    /// @param isDisabled Whether to disable fallback signing entirely.
    function updateFallbackSignerData(address fallbackSigner, bool isDisabled) external wrapNativeFunction {
        SemiModularAccountStorage storage _storage = _getSemiModularAccountStorage();

        _storage.fallbackSigner = fallbackSigner;
        _storage.fallbackSignerDisabled = isDisabled;

        emit FallbackSignerUpdated(fallbackSigner, isDisabled);
    }

    function installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) external override wrapNativeFunction {
        // Previously, it was possible to "alias" the fallback validation by installing a module at the reserved
        // validation entity id 0. Not failing here could cause unexpected behavior, so this is checked to
        // explicitly revert and warn the caller that this operation would not do what is requested.
        //
        // Note that this state can still be reached by upgrading from MA to SMA, but should be handled with
        // initialization and de-init steps.
        if (validationConfig.entityId() == FALLBACK_VALIDATION_ID && validationConfig.module() != address(0)) {
            revert FallbackValidationInstallationNotAllowed();
        }
        _installValidation(validationConfig, selectors, installData, hooks);
    }

    /// @notice Returns the fallback signer data in storage.
    /// @return The fallback signer and a boolean, true if the fallback signer validation is disabled, false if it
    /// is enabled.
    function getFallbackSignerData() external view returns (address, bool) {
        SemiModularAccountStorage storage _storage = _getSemiModularAccountStorage();
        return (_retrieveFallbackSignerUnchecked(_storage), _storage.fallbackSignerDisabled);
    }

    function _execUserOpValidation(
        ValidationLookupKey validationLookupKey,
        bytes32 userOpHash,
        bytes calldata signatureSegment,
        UOCallBuffer callBuffer
    ) internal override returns (uint256) {
        if (validationLookupKey.eq(FALLBACK_VALIDATION_LOOKUP_KEY)) {
            address fallbackSigner = _getFallbackSigner();

            if (_checkSignature(fallbackSigner, userOpHash, signatureSegment)) {
                return _SIG_VALIDATION_PASSED;
            }
            return _SIG_VALIDATION_FAILED;
        }

        return super._execUserOpValidation(validationLookupKey, userOpHash, signatureSegment, callBuffer);
    }

    function _execRuntimeValidation(
        ValidationLookupKey validationLookupKey,
        RTCallBuffer callBuffer,
        bytes calldata authorization
    ) internal override {
        if (validationLookupKey.eq(FALLBACK_VALIDATION_LOOKUP_KEY)) {
            address fallbackSigner = _getFallbackSigner();

            if (msg.sender != fallbackSigner) {
                revert FallbackSignerMismatch();
            }
        } else {
            super._execRuntimeValidation(validationLookupKey, callBuffer, authorization);
        }
    }

    function _exec1271Validation(
        SigCallBuffer buffer,
        bytes32 hash,
        ValidationLookupKey validationLookupKey,
        bytes calldata signature
    ) internal view override returns (bytes4) {
        if (validationLookupKey.eq(FALLBACK_VALIDATION_LOOKUP_KEY)) {
            address fallbackSigner = _getFallbackSigner();

            if (_checkSignature(fallbackSigner, hash, signature)) {
                return _1271_MAGIC_VALUE;
            }
            return _1271_INVALID;
        }
        return super._exec1271Validation(buffer, hash, validationLookupKey, signature);
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

    function _isValidationGlobal(ValidationLookupKey validationFunction) internal view override returns (bool) {
        if (validationFunction.eq(FALLBACK_VALIDATION_LOOKUP_KEY) || super._isValidationGlobal(validationFunction))
        {
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
        ValidationLookupKey fallbackDirectCallValidation = ValidationLocatorLib.directCallLookupKey(fallbackSigner);

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

    // Conditionally skip allocation of call buffers.
    function _validationIsNative(ValidationLookupKey validationLookupKey)
        internal
        pure
        virtual
        override
        returns (bool)
    {
        return validationLookupKey.eq(FALLBACK_VALIDATION_LOOKUP_KEY);
    }

    /// @dev Overrides ModularAccountView.
    function _isNativeFunction(uint32 selector) internal pure virtual override returns (bool) {
        return super._isNativeFunction(selector) || selector == uint32(this.updateFallbackSignerData.selector)
            || selector == uint32(this.getFallbackSignerData.selector);
    }

    /// @dev Overrides ModularAccountView.
    function _isWrappedNativeFunction(uint32 selector) internal pure virtual override returns (bool) {
        return
            super._isWrappedNativeFunction(selector) || selector == uint32(this.updateFallbackSignerData.selector);
    }
}
