// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";

import {DIRECT_CALL_VALIDATION_ENTITYID} from "@erc6900/reference-implementation/helpers/Constants.sol";
import {ModuleEntity, ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {
    ValidationConfig,
    ValidationConfigLib
} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";

import {
    ValidationLocator,
    ValidationLocatorLib,
    ValidationLookupKey
} from "../../src/libraries/ValidationLocatorLib.sol";

contract ValidationLocatorLibTest is Test {
    function testFuzz_loadFromNonce_regular(uint32 entityId, bool isGlobal, bool isDeferredAction) public pure {
        uint256 nonce = ValidationLocatorLib.packNonce(entityId, isGlobal, isDeferredAction);

        ValidationLocator result = ValidationLocatorLib.loadFromNonce(nonce);

        ValidationLocator expected = ValidationLocatorLib.pack(entityId, isGlobal, isDeferredAction);

        assertEq(ValidationLocator.unwrap(result), ValidationLocator.unwrap(expected));
    }

    function testFuzz_loadFromNonce_directCall(address directCallValidation, bool isGlobal, bool isDeferredAction)
        public
        pure
    {
        uint256 nonce = ValidationLocatorLib.packNonceDirectCall(directCallValidation, isGlobal, isDeferredAction);

        ValidationLocator result = ValidationLocatorLib.loadFromNonce(nonce);

        ValidationLocator expected =
            ValidationLocatorLib.packDirectCall(directCallValidation, isGlobal, isDeferredAction);

        assertEq(ValidationLocator.unwrap(result), ValidationLocator.unwrap(expected));
    }

    function testFuzz_loadFromSignature_regular(
        uint32 entityId,
        bool isGlobal,
        bool isDeferredAction,
        bytes memory signature
    ) public view {
        bytes memory finalSignature =
            ValidationLocatorLib.packSignature(entityId, isGlobal, isDeferredAction, signature);

        (ValidationLocator result, bytes memory remainder) = this.loadFromSignature(finalSignature);

        ValidationLocator expected = ValidationLocatorLib.pack(entityId, isGlobal, isDeferredAction);

        assertEq(ValidationLocator.unwrap(result), ValidationLocator.unwrap(expected));
        assertEq(remainder, signature);
    }

    function testFuzz_loadFromSignature_directCall(
        address directCallValidation,
        bool isGlobal,
        bool isDeferredAction,
        bytes memory signature
    ) public view {
        bytes memory finalSignature = ValidationLocatorLib.packSignatureDirectCall(
            directCallValidation, isGlobal, isDeferredAction, signature
        );

        (ValidationLocator result, bytes memory remainder) = this.loadFromSignature(finalSignature);

        ValidationLocator expected =
            ValidationLocatorLib.packDirectCall(directCallValidation, isGlobal, isDeferredAction);

        assertEq(ValidationLocator.unwrap(result), ValidationLocator.unwrap(expected));
        assertEq(remainder, signature);
    }

    function testFuzz_validationLookupKey_regular(uint32 entityId, bool isGlobal, bool isDeferredAction)
        public
        pure
    {
        ValidationLocator locator = ValidationLocatorLib.pack(entityId, isGlobal, isDeferredAction);

        ValidationLookupKey result = locator.lookupKey();

        ValidationLookupKey expected = ValidationLocatorLib.pack(entityId, false, false).lookupKey();

        assertEq(ValidationLookupKey.unwrap(result), ValidationLookupKey.unwrap(expected));
    }

    function testFuzz_validationLookupKey_directCall(
        address directCallValidation,
        bool isGlobal,
        bool isDeferredAction
    ) public pure {
        ValidationLocator locator =
            ValidationLocatorLib.packDirectCall(directCallValidation, isGlobal, isDeferredAction);

        ValidationLookupKey result = locator.lookupKey();

        ValidationLookupKey expected =
            ValidationLocatorLib.packDirectCall(directCallValidation, false, false).lookupKey();

        assertEq(ValidationLookupKey.unwrap(result), ValidationLookupKey.unwrap(expected));
    }

    function testFuzz_configToLookup(
        ModuleEntity validationEntity,
        bool isGlobal,
        bool isSignatureValidation,
        bool isUserOpValidation
    ) public pure {
        (address module, uint32 entityId) = ModuleEntityLib.unpack(validationEntity);

        ValidationConfig input =
            ValidationConfigLib.pack(validationEntity, isGlobal, isSignatureValidation, isUserOpValidation);

        ValidationLookupKey result = ValidationLocatorLib.configToLookup(input);

        ValidationLookupKey expected;

        if (entityId == DIRECT_CALL_VALIDATION_ENTITYID) {
            expected = ValidationLocatorLib.packDirectCall(module, false, false).lookupKey();
        } else {
            expected = ValidationLocatorLib.pack(entityId, false, false).lookupKey();
        }

        assertEq(ValidationLookupKey.unwrap(result), ValidationLookupKey.unwrap(expected));
    }

    function testFuzz_moduleEntityToLookup(ModuleEntity validationEntity) public pure {
        (address module, uint32 entityId) = ModuleEntityLib.unpack(validationEntity);

        ValidationLookupKey result = ValidationLocatorLib.moduleEntityToLookup(validationEntity);

        ValidationLookupKey expected;

        if (entityId == DIRECT_CALL_VALIDATION_ENTITYID) {
            expected = ValidationLocatorLib.packDirectCall(module, false, false).lookupKey();
        } else {
            expected = ValidationLocatorLib.pack(entityId, false, false).lookupKey();
        }

        assertEq(ValidationLookupKey.unwrap(result), ValidationLookupKey.unwrap(expected));
    }

    // External function to convert to calldata
    function loadFromSignature(bytes calldata finalSignature)
        external
        pure
        returns (ValidationLocator, bytes memory)
    {
        (ValidationLocator res, bytes calldata remainder) = ValidationLocatorLib.loadFromSignature(finalSignature);
        return (res, remainder);
    }
}
