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

import {Test} from "forge-std/Test.sol";

import {LinkedListSetHandler} from "./handlers/LinkedListSetHandler.sol";

contract LinkedListSetLibInvariantsTest is Test {
    LinkedListSetHandler public handler;

    function setUp() public {
        handler = new LinkedListSetHandler();

        bytes4[] memory selectors = new bytes4[](6);
        selectors[0] = handler.add.selector;
        selectors[1] = handler.removeIterate.selector;
        selectors[2] = handler.removeRandKeyIterate.selector;
        selectors[3] = handler.clear.selector;
        selectors[4] = handler.removeKnownPrevKey.selector;
        selectors[5] = handler.removeRandKnownPrevKey.selector;

        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function invariant_shouldContain() public view {
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
    function invariant_getAllEquivalence() public view {
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

    function _contains(bytes32[] memory arr, bytes32 val) internal pure returns (bool) {
        for (uint256 i = 0; i < arr.length; i++) {
            if (arr[i] == val) {
                return true;
            }
        }
        return false;
    }
}
