// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {ModuleEntity, ModuleEntityLib} from "./ModuleEntityLib.sol";
import {ValidationConfig, ValidationConfigLib} from "./ValidationConfigLib.sol";

import {DIRECT_CALL_VALIDATION_ENTITYID} from "../helpers/Constants.sol";

type ValidationLocator is uint168;

uint8 constant VALIDATION_TYPE_GLOBAL = 1;
uint8 constant IS_DEFERRED_VALIDATION_INSTALL = 2;
uint8 constant IS_DIRECT_CALL_VALIDATION = 4;

library ValidationLocatorLib {
    using ValidationConfigLib for ValidationConfig;

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
            let validationType := and(nonce, IS_DIRECT_CALL_VALIDATION)
            // Yul doesn't support if/else, so we use `break` statements to do a branch
            for {} 1 {} {
                // If using direct call validation, the validation locator contains a 20-byte address
                if validationType {
                    result := or(and(nonce, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF), validationType)
                    break
                }
                // If not using direct call validation, the validation locator contains a 32-byte entity ID
                result := or(and(nonce, 0xFFFFFFFFFF), validationType)
                break
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
        uint8 options = uint8(signature[0]) & IS_DIRECT_CALL_VALIDATION;

        // address(4).staticcall(abi.encodePacked(options));

        assembly ("memory-safe") {
            result := calldataload(signature.offset)

            switch options
            case 0 {
                // If not using direct call validation, the validation locator contains a 32-byte entity ID

                // Regular validation requires at least 5 bytes
                if lt(signature.length, 5) { revert(0, 0) }

                // Result contains:
                // 0xAA______________________________________________________________ // Validation Type
                // 0x__BBBBBBBB______________________________________________________ // Validation Entity ID
                // 0x__________CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC // Remainder bits and/or zeros

                // So we need to clear the upper byte by shifting left 1 bytes (8 bits), then shift right 26 bytes
                // (208 bits) and to get the entity ID
                result := shr(224, shl(8, result))
                // Next, we need to set the validation type, which is 0 in this branch
                result := shl(8, result)
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

                // So we need to clear the upper byte by shifting left 1 bytes (8 bits), then shift right 10
                // bytes (80 bits) and to get the address
                result := shr(96, shl(8, result))
                // Next, we need to set the validation type
                result := or(shl(8, result), options)
                // Advance the remainder by 21 bytes
                remainder.offset := add(signature.offset, 21)
                remainder.length := sub(signature.length, 21)
            }
        }

        // address(4).staticcall(abi.encodePacked(result));
    }

    function getFromValidationConfig(ValidationConfig validationConfig)
        internal
        pure
        returns (ValidationLocator result)
    {
        if (validationConfig.entityId() == DIRECT_CALL_VALIDATION_ENTITYID) {
            result = ValidationLocator.wrap(
                uint168(uint160(validationConfig.module())) << 8 | IS_DIRECT_CALL_VALIDATION
            );
        } else {
            result = ValidationLocator.wrap(uint168(uint160(validationConfig.entityId())) << 8);
        }
    }

    function getFromModuleEntity(ModuleEntity _moduleEntity) internal pure returns (ValidationLocator result) {
        (address module, uint32 entityId) = ModuleEntityLib.unpack(_moduleEntity);
        if (entityId == DIRECT_CALL_VALIDATION_ENTITYID) {
            result = ValidationLocator.wrap(uint168(uint160(module)) << 8 | IS_DIRECT_CALL_VALIDATION);
        } else {
            result = ValidationLocator.wrap(uint168(uint160(entityId)) << 8);
        }
    }

    function moduleEntity(ValidationLocator locator, address module) internal pure returns (ModuleEntity result) {
        if (ValidationLocator.unwrap(locator) & IS_DIRECT_CALL_VALIDATION != 0) {
            result = ModuleEntityLib.pack(module, DIRECT_CALL_VALIDATION_ENTITYID);
        } else {
            uint32 entityId = uint32(ValidationLocator.unwrap(locator) >> 8);
            result = ModuleEntityLib.pack(module, entityId);
        }
    }
}

using ValidationLocatorLib for ValidationLocator global;
