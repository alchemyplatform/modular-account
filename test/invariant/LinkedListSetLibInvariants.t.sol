// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";

import {LinkedListSetHandler} from "./handlers/LinkedListSetHandler.sol";

contract LinkedListSetLibInvariantsTest is Test {
    LinkedListSetHandler public handler;

    function setUp() public {
        handler = new LinkedListSetHandler();

        bytes4[] memory selectors = new bytes4[](8);
        selectors[0] = handler.add.selector;
        selectors[1] = handler.removeIterate.selector;
        selectors[2] = handler.removeRandKeyIterate.selector;
        selectors[3] = handler.clear.selector;
        selectors[4] = handler.removeKnownPrevKey.selector;
        selectors[5] = handler.removeRandKnownPrevKey.selector;
        selectors[6] = handler.addFlagKnown.selector;
        selectors[7] = handler.addFlagRandom.selector;

        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function invariant_shouldContain() public {
        bytes32[] memory vals = handler.referenceEnumerate();

        if (vals.length == 0) {
            assertTrue(handler.referenceIsEmpty());
            assertTrue(handler.libIsEmpty());
        } else {
            assertFalse(handler.referenceIsEmpty());
            assertFalse(handler.libIsEmpty());
            for (uint256 i = 0; i < vals.length; i++) {
                bytes30 val = bytes30(vals[i]);
                assertTrue(handler.libContains(val));
                assertTrue(handler.referenceContains(val));
            }
        }
    }

    // Doesn't test for no duplicates yet
    function invariant_getAllEquivalence() public {
        bytes32[] memory referenceEnumerate = handler.referenceEnumerate();
        bytes32[] memory libEnumerate = handler.libEnumerate();

        assertTrue(referenceEnumerate.length == libEnumerate.length);

        for (uint256 i = 0; i < referenceEnumerate.length; i++) {
            assertTrue(_contains(libEnumerate, referenceEnumerate[i]));
        }

        for (uint256 i = 0; i < libEnumerate.length; i++) {
            assertTrue(_contains(referenceEnumerate, libEnumerate[i]));
        }
    }

    function invariant_flagValidity() public {
        (bytes32[] memory keys, uint16[] memory metaFlags) = handler.referenceGetFlags();

        for (uint256 i = 0; i < keys.length; i++) {
            bytes30 key = bytes30(keys[i]);
            uint16 metaFlag = metaFlags[i];
            assertEq(handler.libGetFlags(key), metaFlag);
        }
    }

    function _contains(bytes32[] memory arr, bytes32 val) internal pure returns (bool) {
        for (uint256 i = 0; i < arr.length; i++) {
            if (arr[i] == val) {
                return true;
            }
        }
        return false;
    }
}
