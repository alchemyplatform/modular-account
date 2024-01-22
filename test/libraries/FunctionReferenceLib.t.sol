// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {Test} from "forge-std/Test.sol";
import {FunctionReference, FunctionReferenceLib} from "../../src/libraries/FunctionReferenceLib.sol";

contract FunctionReferenceLibTest is Test {
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
        assertTrue(a == a);
        assertTrue(b == b);

        if (FunctionReference.unwrap(a) == FunctionReference.unwrap(b)) {
            assertTrue(a == b);
            assertTrue(b == a);
            assertFalse(a != b);
            assertFalse(b != a);
        } else {
            assertTrue(a != b);
            assertTrue(b != a);
            assertFalse(a == b);
            assertFalse(b == a);
        }
    }
}
