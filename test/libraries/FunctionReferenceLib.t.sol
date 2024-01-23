// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {Test} from "forge-std/Test.sol";

import {FunctionReferenceLib} from "../../src/helpers/FunctionReferenceLib.sol";
import {FunctionReference} from "../../src/interfaces/IPluginManager.sol";

contract FunctionReferenceLibTest is Test {
    using FunctionReferenceLib for FunctionReference;

    function testFuzz_functionReference_packing(address addr, uint8 functionId) public {
        // console.log("addr: ", addr);
        // console.log("functionId: ", vm.toString(functionId));
        FunctionReference fr = FunctionReferenceLib.pack(addr, functionId);
        // console.log("packed: ", vm.toString(FunctionReference.unwrap(fr)));
        (address addr2, uint8 functionId2) = FunctionReferenceLib.unpack(fr);
        // console.log("addr2: ", addr2);
        // console.log("functionId2: ", vm.toString(functionId2));
        assertEq(addr, addr2);
        assertEq(functionId, functionId2);
    }

    function testFuzz_functionReference_operators(FunctionReference a, FunctionReference b) public {
        assertTrue(a.eq(a));
        assertTrue(b.eq(b));

        if (FunctionReference.unwrap(a) == FunctionReference.unwrap(b)) {
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
