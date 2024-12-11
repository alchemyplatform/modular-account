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

import {DIRECT_CALL_VALIDATION_ENTITY_ID} from "@erc6900/reference-implementation/helpers/Constants.sol";
import {ModuleEntity, ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {
    ValidationConfig,
    ValidationConfigLib
} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";

import {ValidationStorage} from "../account/AccountStorage.sol";

// A type representing a validation lookup key and flags for validation options.
// The validation lookup key is a tagged union between a direct call validation address and a validation entity ID.
type ValidationLocator is uint168;
// Layout:
// Unused
// 0x0000000000000000000000__________________________________________
// Either the direct call validation's address, or the entity ID for non-direct-call validation.
// 0x______________________AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA__
// Validation options
// 0x______________________________________________________________BB

// ValidationOptions layout:
// 0b00000___ // Unused
// 0b_____A__ // is direct call validation (union tag)
// 0b______B_ // has deferred action
// 0b_______C // is global validation

// A type representing only the validation lookup key, with validation options masked out except for the
// direct call validation flag.
type ValidationLookupKey is uint168;

using ValidationLocatorLib for ValidationLocator global;
using ValidationLocatorLib for ValidationLookupKey global;

library ValidationLocatorLib {
    using ValidationConfigLib for ValidationConfig;

    uint8 internal constant _VALIDATION_TYPE_GLOBAL = 1;
    uint8 internal constant _HAS_DEFERRED_ACTION = 2;
    uint8 internal constant _IS_DIRECT_CALL_VALIDATION = 4;

    function moduleEntity(ValidationLookupKey _lookupKey, ValidationStorage storage validationStorage)
        internal
        view
        returns (ModuleEntity result)
    {
        if (_lookupKey.isDirectCallValidation()) {
            result = ModuleEntityLib.pack(_lookupKey.directCallAddress(), DIRECT_CALL_VALIDATION_ENTITY_ID);
        } else {
            result = ModuleEntityLib.pack(validationStorage.module, _lookupKey.entityId());
        }
    }

    // User op nonce, 4337 mandated layout:
    // 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA________________ // Parallel Nonce Key
    // 0x________________________________________________BBBBBBBBBBBBBBBB // Sequential Nonce Key

    // User op nonce, Alchemy MA usage:
    // With non-direct call validation
    // 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA__________________________ // Parallel Nonce Key
    // 0x______________________________________BBBBBBBB__________________ // Validation Entity ID
    // 0x______________________________________________CC________________ // Options byte
    // 0x________________________________________________BBBBBBBBBBBBBBBB // Sequential Nonce Key

    // With direct call validation
    // 0xAAAAAA__________________________________________________________ // Parallel Nonce Key
    // 0x______BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB__________________ // Caller address of direct-call
    // validation
    // 0x______________________________________________CC________________ // Options byte
    // 0x________________________________________________BBBBBBBBBBBBBBBB // Sequential Nonce Key
    function loadFromNonce(uint256 nonce) internal pure returns (ValidationLocator result) {
        assembly ("memory-safe") {
            nonce := shr(64, nonce)
            let validationType := and(nonce, _IS_DIRECT_CALL_VALIDATION)

            switch validationType
            case 0 {
                // If not using direct call validation, the validation locator contains a 4-byte entity ID
                // Mask it to the lower 5 bytes
                result := and(nonce, 0xFFFFFFFFFF)
            }
            default {
                // If using direct call validation, the validation locator contains a 20-byte address
                // Mask it to the lower 21 bytes
                result := and(nonce, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            }
        }
    }

    // executeRuntimeValidation authorization layout, and isValidSignature signature layout
    // [1-byte options][4-byte validation id OR 20-byte address of direct call validation][remainder]

    // With non-direct call validation
    // 0xAA______________ // Validation Type
    // 0x__BBBBBBBB______ // Validation Entity ID
    // 0x__________CCC... // Remainder

    // With direct call validation
    // 0xAA______________________________________________ // Validation Type
    // 0x__BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB______ // Caller address of direct-call validation
    // 0x__________________________________________CCC... // Remainder
    function loadFromSignature(bytes calldata signature)
        internal
        pure
        returns (ValidationLocator result, bytes calldata remainder)
    {
        assembly ("memory-safe") {
            // Regular validation requires at least 5 bytes. Direct call validation requires at least 21 bytes,
            // checked later.
            if lt(signature.length, 5) { revert(0, 0) }

            result := calldataload(signature.offset)

            let validationOptions := shr(248, result)

            switch and(validationOptions, _IS_DIRECT_CALL_VALIDATION)
            case 0 {
                // If not using direct call validation, the validation locator contains a 32-byte entity ID

                // Result contains:
                // 0xAA______________________________________________________________ // Validation Type
                // 0x__BBBBBBBB______________________________________________________ // Validation Entity ID
                // 0x__________CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC // Remainder bits and/or
                // zeros

                // We need to clear the upper byte by shifting left 1 bytes (8 bits), then shift right 28 bytes
                // (224 bits), leaving only the entity ID.
                result := shr(224, shl(8, result))
                // Next, we need to set the validation type, which is 0 in this branch
                result := or(shl(8, result), validationOptions)

                // Advance the remainder by 5 bytes
                remainder.offset := add(signature.offset, 5)
                remainder.length := sub(signature.length, 5)
            }
            default {
                // Direct call validation requires at least 21 bytes
                if lt(signature.length, 21) { revert(0, 0) }

                // If using direct call validation, the validation locator contains a 20-byte address
                // Result contains:
                // 0xAA______________________________________________________________ // Validation Type
                // 0x__BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB______________________ // Caller address of
                // direct-call validation
                // 0x__________________________________________CCCCCCCCCCCCCCCCCCCCCC // Remainder bits and/or
                // zeros

                // So we need to clear the upper byte by shifting left 1 bytes (8 bits), then shift right 12
                // bytes (96 bits) to get the address.
                result := shr(96, shl(8, result))
                // Next, we need to set the validation type
                result := or(shl(8, result), validationOptions)

                // Advance the remainder by 21 bytes
                remainder.offset := add(signature.offset, 21)
                remainder.length := sub(signature.length, 21)
            }
        }
    }

    // Only safe to call if the lookup has been asserted to be a direct call validation.
    function directCallAddress(ValidationLookupKey _lookupKey) internal pure returns (address result) {
        assembly ("memory-safe") {
            result := and(shr(8, _lookupKey), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
        }
    }

    // Only safe to call if the lookup has been asserted to be a non-direct call validation.
    function entityId(ValidationLookupKey _lookupKey) internal pure returns (uint32 result) {
        assembly ("memory-safe") {
            result := and(shr(8, _lookupKey), 0xFFFFFFFF)
        }
    }

    function isGlobal(ValidationLocator locator) internal pure returns (bool) {
        return (ValidationLocator.unwrap(locator) & _VALIDATION_TYPE_GLOBAL) != 0;
    }

    function hasDeferredAction(ValidationLocator locator) internal pure returns (bool) {
        return (ValidationLocator.unwrap(locator) & _HAS_DEFERRED_ACTION) != 0;
    }

    function isDirectCallValidation(ValidationLookupKey _lookupKey) internal pure returns (bool) {
        return (ValidationLookupKey.unwrap(_lookupKey) & _IS_DIRECT_CALL_VALIDATION) != 0;
    }

    function configToLookupKey(ValidationConfig validationConfig)
        internal
        pure
        returns (ValidationLookupKey result)
    {
        if (validationConfig.entityId() == DIRECT_CALL_VALIDATION_ENTITY_ID) {
            result = ValidationLookupKey.wrap(
                uint168(uint160(validationConfig.module())) << 8 | _IS_DIRECT_CALL_VALIDATION
            );
        } else {
            result = ValidationLookupKey.wrap(uint168(uint160(validationConfig.entityId())) << 8);
        }
    }

    function moduleEntityToLookupKey(ModuleEntity _moduleEntity)
        internal
        pure
        returns (ValidationLookupKey result)
    {
        (address module, uint32 _entityId) = ModuleEntityLib.unpack(_moduleEntity);
        if (_entityId == DIRECT_CALL_VALIDATION_ENTITY_ID) {
            result = ValidationLookupKey.wrap(uint168(uint160(module)) << 8 | _IS_DIRECT_CALL_VALIDATION);
        } else {
            result = ValidationLookupKey.wrap(uint168(uint160(_entityId)) << 8);
        }
    }

    function directCallLookupKey(address directCallValidation)
        internal
        pure
        returns (ValidationLookupKey result)
    {
        result = ValidationLookupKey.wrap(uint168(uint160(directCallValidation)) << 8 | _IS_DIRECT_CALL_VALIDATION);
    }

    function lookupKey(ValidationLocator locator) internal pure returns (ValidationLookupKey result) {
        assembly ("memory-safe") {
            result := and(locator, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF04)
        }
    }

    // Packing functions. These should not be used in the account, but in scripts and tests.

    function pack(uint32 _entityId, bool _isGlobal, bool _hasDeferredAction)
        internal
        pure
        returns (ValidationLocator)
    {
        uint168 result = uint168(_entityId) << 8;
        if (_isGlobal) {
            result |= _VALIDATION_TYPE_GLOBAL;
        }
        if (_hasDeferredAction) {
            result |= _HAS_DEFERRED_ACTION;
        }

        return ValidationLocator.wrap(result);
    }

    function packDirectCall(address directCallValidation, bool _isGlobal, bool _hasDeferredAction)
        internal
        pure
        returns (ValidationLocator)
    {
        uint168 result = uint168(uint160(directCallValidation)) << 8 | _IS_DIRECT_CALL_VALIDATION;
        if (_isGlobal) {
            result |= _VALIDATION_TYPE_GLOBAL;
        }
        if (_hasDeferredAction) {
            result |= _HAS_DEFERRED_ACTION;
        }

        return ValidationLocator.wrap(result);
    }

    function packNonce(uint32 validationEntityId, bool _isGlobal, bool _hasDeferredAction)
        internal
        pure
        returns (uint256 result)
    {
        result = uint256(validationEntityId) << 8;
        if (_isGlobal) {
            result |= _VALIDATION_TYPE_GLOBAL;
        }
        if (_hasDeferredAction) {
            result |= _HAS_DEFERRED_ACTION;
        }
        // Finally, shift left to make space for the sequential nonce key
        result <<= 64;
    }

    function packNonceDirectCall(address directCallValidation, bool _isGlobal, bool _hasDeferredAction)
        internal
        pure
        returns (uint256 result)
    {
        result = uint256(uint160(directCallValidation)) << 8 | _IS_DIRECT_CALL_VALIDATION;
        if (_isGlobal) {
            result |= _VALIDATION_TYPE_GLOBAL;
        }
        if (_hasDeferredAction) {
            result |= _HAS_DEFERRED_ACTION;
        }
        // Finally, shift left to make space for the sequential nonce key
        result <<= 64;
    }

    function packSignature(uint32 validationEntityId, bool _isGlobal, bytes memory signature)
        internal
        pure
        returns (bytes memory result)
    {
        uint8 options = 0;
        if (_isGlobal) {
            options |= _VALIDATION_TYPE_GLOBAL;
        }

        return bytes.concat(abi.encodePacked(options, uint32(validationEntityId)), signature);
    }

    function packSignatureDirectCall(
        address directCallValidation,
        bool _isGlobal,
        bool _hasDeferredAction,
        bytes memory signature
    ) internal pure returns (bytes memory result) {
        uint8 options = _IS_DIRECT_CALL_VALIDATION;
        if (_isGlobal) {
            options |= _VALIDATION_TYPE_GLOBAL;
        }
        if (_hasDeferredAction) {
            options |= _HAS_DEFERRED_ACTION;
        }

        return bytes.concat(abi.encodePacked(options, uint160(directCallValidation)), signature);
    }

    // Converts a module entity to a locator.
    function packFromModuleEntity(ModuleEntity _moduleEntity, bool _isGlobal, bool _hasDeferredAction)
        internal
        pure
        returns (ValidationLocator)
    {
        uint168 result;

        (address module, uint32 _entityId) = ModuleEntityLib.unpack(_moduleEntity);
        if (_entityId == DIRECT_CALL_VALIDATION_ENTITY_ID) {
            result = uint168(uint160(module)) << 8 | _IS_DIRECT_CALL_VALIDATION;
        } else {
            result = uint168(_entityId) << 8;
        }

        if (_isGlobal) {
            result |= _VALIDATION_TYPE_GLOBAL;
        }

        if (_hasDeferredAction) {
            result |= _HAS_DEFERRED_ACTION;
        }

        return ValidationLocator.wrap(result);
    }

    // Operators

    function eq(ValidationLookupKey a, ValidationLookupKey b) internal pure returns (bool) {
        return ValidationLookupKey.unwrap(a) == ValidationLookupKey.unwrap(b);
    }
}
