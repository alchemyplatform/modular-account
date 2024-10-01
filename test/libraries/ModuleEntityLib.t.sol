// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/src/Test.sol";

import {ModuleEntity, ModuleEntityLib} from "../../src/libraries/ModuleEntityLib.sol";

contract ModuleEntityLibTest is Test {
    using ModuleEntityLib for ModuleEntity;

    function testFuzz_moduleEntity_packing(address addr, uint32 entityId) public pure {
        // console.log("addr: ", addr);
        // console.log("entityId: ", vm.toString(entityId));
        ModuleEntity fr = ModuleEntityLib.pack(addr, entityId);
        // console.log("packed: ", vm.toString(ModuleEntity.unwrap(fr)));
        (address addr2, uint32 entityId2) = ModuleEntityLib.unpack(fr);
        // console.log("addr2: ", addr2);
        // console.log("entityId2: ", vm.toString(entityId2));
        assertEq(addr, addr2);
        assertEq(entityId, entityId2);
    }

    function testFuzz_moduleEntity_operators(ModuleEntity a, ModuleEntity b) public pure {
        assertTrue(a.eq(a));
        assertTrue(b.eq(b));

        if (ModuleEntity.unwrap(a) == ModuleEntity.unwrap(b)) {
            assertTrue(a.eq(b));
            assertTrue(b.eq(a));
            assertFalse(a.notEq(b));
            assertFalse(b.notEq(a));
        } else {
            assertTrue(a.notEq(b));
            assertTrue(b.notEq(a));
            assertFalse(a.eq(b));
            assertFalse(b.eq(a));
        }
    }
}
