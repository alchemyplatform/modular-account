// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {ModuleEntity, ValidationConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

// Validation flags layout:
// 0b00000___ // unused
// 0b_____A__ // isGlobal
// 0b______B_ // isSignatureValidation
// 0b_______C // isUserOpValidation
type ValidationFlags is uint8;

// Validation config is a packed representation of a validation function and flags for its configuration.
// Layout:
// 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA________________________ // Address
// 0x________________________________________BBBBBBBB________________ // Entity ID
// 0x________________________________________________CC______________ // validation flags
// 0x__________________________________________________00000000000000 // unused

// Validation flags layout:
// 0b00000___ // unused
// 0b_____A__ // isGlobal
// 0b______B_ // isSignatureValidation
// 0b_______C // isUserOpValidation

library ValidationConfigLib {
    // is user op validation flag stored in last bit of the 25th byte
    bytes32 internal constant _VALIDATION_FLAG_IS_USER_OP = bytes32(uint256(1) << 56);
    // is signature validation flag stored in second to last bit of the 25th byte
    bytes32 internal constant _VALIDATION_FLAG_IS_SIGNATURE = bytes32(uint256(1) << 57);
    // is global flag stored in the third to last bit of the 25th byte
    bytes32 internal constant _VALIDATION_FLAG_IS_GLOBAL = bytes32(uint256(1) << 58);

    function pack(
        ModuleEntity _validationFunction,
        bool _isGlobal,
        bool _isSignatureValidation,
        bool _isUserOpValidation
    ) internal pure returns (ValidationConfig) {
        return ValidationConfig.wrap(
            bytes25(
                bytes25(ModuleEntity.unwrap(_validationFunction))
                    | bytes25(bytes32(_isGlobal ? _VALIDATION_FLAG_IS_GLOBAL : bytes32(0)))
                    | bytes25(bytes32(_isSignatureValidation ? _VALIDATION_FLAG_IS_SIGNATURE : bytes32(0)))
                    | bytes25(bytes32(_isUserOpValidation ? _VALIDATION_FLAG_IS_USER_OP : bytes32(0)))
            )
        );
    }

    function pack(
        address _module,
        uint32 _entityId,
        bool _isGlobal,
        bool _isSignatureValidation,
        bool _isUserOpValidation
    ) internal pure returns (ValidationConfig) {
        return ValidationConfig.wrap(
            bytes25(
                // module address stored in the first 20 bytes
                bytes25(bytes20(_module))
                // entityId stored in the 21st - 24th byte
                | bytes25(bytes24(uint192(_entityId)))
                    | bytes25(bytes32(_isGlobal ? _VALIDATION_FLAG_IS_GLOBAL : bytes32(0)))
                    | bytes25(bytes32(_isSignatureValidation ? _VALIDATION_FLAG_IS_SIGNATURE : bytes32(0)))
                    | bytes25(bytes32(_isUserOpValidation ? _VALIDATION_FLAG_IS_USER_OP : bytes32(0)))
            )
        );
    }

    function unpackUnderlying(ValidationConfig config)
        internal
        pure
        returns (address _module, uint32 _entityId, ValidationFlags flags)
    {
        bytes25 configBytes = ValidationConfig.unwrap(config);
        _module = address(bytes20(configBytes));
        _entityId = uint32(bytes4(configBytes << 160));
        flags = ValidationFlags.wrap(uint8(configBytes[24]));
    }

    function unpack(ValidationConfig config)
        internal
        pure
        returns (ModuleEntity _validationFunction, ValidationFlags flags)
    {
        bytes25 configBytes = ValidationConfig.unwrap(config);
        _validationFunction = ModuleEntity.wrap(bytes24(configBytes));
        flags = ValidationFlags.wrap(uint8(configBytes[24]));
    }

    function module(ValidationConfig config) internal pure returns (address) {
        return address(bytes20(ValidationConfig.unwrap(config)));
    }

    function entityId(ValidationConfig config) internal pure returns (uint32) {
        return uint32(bytes4(ValidationConfig.unwrap(config) << 160));
    }

    function moduleEntity(ValidationConfig config) internal pure returns (ModuleEntity) {
        return ModuleEntity.wrap(bytes24(ValidationConfig.unwrap(config)));
    }

    function isGlobal(ValidationConfig config) internal pure returns (bool) {
        return ValidationConfig.unwrap(config) & _VALIDATION_FLAG_IS_GLOBAL != 0;
    }

    function isGlobal(ValidationFlags flags) internal pure returns (bool) {
        return ValidationFlags.unwrap(flags) & 0x04 != 0;
    }

    function isSignatureValidation(ValidationConfig config) internal pure returns (bool) {
        return ValidationConfig.unwrap(config) & _VALIDATION_FLAG_IS_SIGNATURE != 0;
    }

    function isSignatureValidation(ValidationFlags flags) internal pure returns (bool) {
        return ValidationFlags.unwrap(flags) & 0x02 != 0;
    }

    function isUserOpValidation(ValidationConfig config) internal pure returns (bool) {
        return ValidationConfig.unwrap(config) & _VALIDATION_FLAG_IS_USER_OP != 0;
    }

    function isUserOpValidation(ValidationFlags flags) internal pure returns (bool) {
        return ValidationFlags.unwrap(flags) & 0x01 != 0;
    }
}
