// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/src/Test.sol";

import {ModuleEntity, ModuleEntityLib} from "../../src/libraries/ModuleEntityLib.sol";
import {
    ValidationConfig, ValidationConfigLib, ValidationFlags
} from "../../src/libraries/ValidationConfigLib.sol";

contract ValidationConfigLibTest is Test {
    using ModuleEntityLib for ModuleEntity;
    using ValidationConfigLib for *;

    // Tests the packing and unpacking of a validation config with a randomized state

    function testFuzz_validationConfig_packingUnderlying(
        address module,
        uint32 entityId,
        bool isGlobal,
        bool isSignatureValidation,
        bool isUserOpValidation
    ) public pure {
        ValidationConfig validationConfig =
            ValidationConfigLib.pack(module, entityId, isGlobal, isSignatureValidation, isUserOpValidation);

        // Test unpacking underlying
        (address module2, uint32 entityId2, ValidationFlags flags2) = validationConfig.unpackUnderlying();

        assertEq(module, module2, "module mismatch");
        assertEq(entityId, entityId2, "entityId mismatch");
        assertEq(isGlobal, flags2.isGlobal(), "isGlobal mismatch");
        assertEq(isSignatureValidation, flags2.isSignatureValidation(), "isSignatureValidation mismatch");
        assertEq(isUserOpValidation, flags2.isUserOpValidation(), "isUserOpValidation mismatch");

        // Test unpacking to ModuleEntity

        ModuleEntity expectedModuleEntity = ModuleEntityLib.pack(module, entityId);

        (ModuleEntity validationFunction, ValidationFlags flags3) = validationConfig.unpack();

        assertEq(
            ModuleEntity.unwrap(validationFunction),
            ModuleEntity.unwrap(expectedModuleEntity),
            "validationFunction mismatch"
        );
        assertEq(isGlobal, flags3.isGlobal(), "isGlobal mismatch");
        assertEq(isSignatureValidation, flags3.isSignatureValidation(), "isSignatureValidation mismatch");
        assertEq(isUserOpValidation, flags3.isUserOpValidation(), "isUserOpValidation mismatch");

        // Test individual view functions

        assertEq(validationConfig.module(), module, "module mismatch");
        assertEq(validationConfig.entityId(), entityId, "entityId mismatch");
        assertEq(
            ModuleEntity.unwrap(validationConfig.moduleEntity()),
            ModuleEntity.unwrap(expectedModuleEntity),
            "moduleEntity mismatch"
        );
        assertEq(validationConfig.isGlobal(), isGlobal, "isGlobal mismatch");
        assertEq(validationConfig.isSignatureValidation(), isSignatureValidation, "isSignatureValidation mismatch");
        assertEq(validationConfig.isUserOpValidation(), isUserOpValidation, "isUserOpValidation mismatch");
    }

    function testFuzz_validationConfig_packingModuleEntity(
        ModuleEntity validationFunction,
        bool isGlobal,
        bool isSignatureValidation,
        bool isUserOpValidation
    ) public pure {
        ValidationConfig validationConfig =
            ValidationConfigLib.pack(validationFunction, isGlobal, isSignatureValidation, isUserOpValidation);

        // Test unpacking underlying

        (address expectedModule, uint32 expectedEntityId) = validationFunction.unpack();

        (address module, uint32 entityId, ValidationFlags flags2) = validationConfig.unpackUnderlying();

        assertEq(expectedModule, module, "module mismatch");
        assertEq(expectedEntityId, entityId, "entityId mismatch");
        assertEq(isGlobal, flags2.isGlobal(), "isGlobal mismatch");
        assertEq(isSignatureValidation, flags2.isSignatureValidation(), "isSignatureValidation mismatch");
        assertEq(isUserOpValidation, flags2.isUserOpValidation(), "isUserOpValidation mismatch");

        // Test unpacking to ModuleEntity

        (ModuleEntity validationFunction2, ValidationFlags flags3) = validationConfig.unpack();

        assertEq(
            ModuleEntity.unwrap(validationFunction),
            ModuleEntity.unwrap(validationFunction2),
            "validationFunction mismatch"
        );
        assertEq(isGlobal, flags3.isGlobal(), "isGlobal mismatch");
        assertEq(isSignatureValidation, flags3.isSignatureValidation(), "isSignatureValidation mismatch");
        assertEq(isUserOpValidation, flags3.isUserOpValidation(), "isUserOpValidation mismatch");

        // Test individual view functions

        assertEq(validationConfig.module(), expectedModule, "module mismatch");
        assertEq(validationConfig.entityId(), expectedEntityId, "entityId mismatch");
        assertEq(
            ModuleEntity.unwrap(validationConfig.moduleEntity()),
            ModuleEntity.unwrap(validationFunction),
            "validationFunction mismatch"
        );
        assertEq(validationConfig.isGlobal(), isGlobal, "isGlobal mismatch");
        assertEq(validationConfig.isSignatureValidation(), isSignatureValidation, "isSignatureValidation mismatch");
        assertEq(validationConfig.isUserOpValidation(), isUserOpValidation, "isUserOpValidation mismatch");
    }
}
