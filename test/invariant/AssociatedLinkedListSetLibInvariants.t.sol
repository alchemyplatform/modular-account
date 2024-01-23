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

pragma solidity ^0.8.22;

import {Test} from "forge-std/Test.sol";

import {AssociatedLinkedListSetHandler} from "./handlers/AssociatedLinkedListSetHandler.sol";

contract AssociatedLinkedListSetLibInvariantsTest is Test {
    AssociatedLinkedListSetHandler public handler;

    // Only use these constants for testing. Enforces uniqueness across ID and associated address,
    // Without reducing invariant call depth too much.
    address public constant ASSOCIATED_1 = address(uint160(bytes20(keccak256("ASSOCIATED_1"))));
    address public constant ASSOCIATED_2 = address(uint160(bytes20(keccak256("ASSOCIATED_2"))));
    uint64 public constant ID_1 = 42;
    uint64 public constant ID_2 = 115557777;

    function setUp() public {
        handler = new AssociatedLinkedListSetHandler();

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
        _shouldContain(ASSOCIATED_1, ID_1);
        _shouldContain(ASSOCIATED_1, ID_2);
        _shouldContain(ASSOCIATED_2, ID_1);
        _shouldContain(ASSOCIATED_2, ID_2);
    }

    // Doesn't test for no duplicates yet
    function invariant_getAllEquivalence() public {
        _getAllEquivalence(ASSOCIATED_1, ID_1);
        _getAllEquivalence(ASSOCIATED_1, ID_2);
        _getAllEquivalence(ASSOCIATED_2, ID_1);
        _getAllEquivalence(ASSOCIATED_2, ID_2);
    }

    function invariant_flagValidity() public {
        _flagValidityCheck(ASSOCIATED_1, ID_1);
        _flagValidityCheck(ASSOCIATED_1, ID_2);
        _flagValidityCheck(ASSOCIATED_2, ID_1);
        _flagValidityCheck(ASSOCIATED_2, ID_2);
    }

    function _shouldContain(address associated, uint64 id) internal {
        bytes32[] memory vals = handler.referenceEnumerate(associated, id);

        if (vals.length == 0) {
            assertTrue(handler.referenceIsEmpty(associated, id));
            assertTrue(handler.associatedIsEmpty(associated, id));
        } else {
            assertFalse(handler.referenceIsEmpty(associated, id));
            assertFalse(handler.associatedIsEmpty(associated, id));
            for (uint256 i = 0; i < vals.length; i++) {
                bytes30 val = bytes30(vals[i]);
                assertTrue(handler.associatedContains(associated, id, val));
                assertTrue(handler.referenceContains(associated, id, val));
            }
        }
    }

    function _flagValidityCheck(address associated, uint64 id) internal {
        (bytes32[] memory keys, uint16[] memory metaFlags) = handler.referenceGetFlags(associated, id);

        for (uint256 i = 0; i < keys.length; i++) {
            bytes30 key = bytes30(keys[i]);
            uint16 metaFlag = metaFlags[i];
            assertEq(handler.associatedGetFlags(associated, id, key), metaFlag);
        }
    }

    function _getAllEquivalence(address associated, uint64 id) internal {
        bytes32[] memory referenceEnumerate = handler.referenceEnumerate(associated, id);
        bytes32[] memory associatedEnumerate = handler.associatedEnumerate(associated, id);

        assertTrue(referenceEnumerate.length == associatedEnumerate.length);

        for (uint256 i = 0; i < referenceEnumerate.length; i++) {
            assertTrue(_contains(associatedEnumerate, referenceEnumerate[i]));
        }

        for (uint256 i = 0; i < associatedEnumerate.length; i++) {
            assertTrue(_contains(referenceEnumerate, associatedEnumerate[i]));
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
