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
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with this program.  If not, see
// <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.22;

import {Test} from "forge-std/Test.sol";

import {SetValue} from "../../src/libraries/Constants.sol";
import {CountableLinkedListSetLib} from "../../src/libraries/CountableLinkedListSetLib.sol";
import {LinkedListSet, LinkedListSetLib} from "../../src/libraries/LinkedListSetLib.sol";

contract CountableLinkedListSetLibTest is Test {
    using LinkedListSetLib for LinkedListSet;
    using CountableLinkedListSetLib for LinkedListSet;

    LinkedListSet internal _set;

    uint16 internal constant _MAX_COUNTER_VALUE = 255;

    // User-defined function for wrapping from bytes30 (uint240) to SetValue
    // Can define a custom one for addresses, uints, etc.
    function _getListValue(uint240 value) internal pure returns (SetValue) {
        return SetValue.wrap(bytes30(value));
    }

    function test_getCount() public {
        SetValue value = _getListValue(12);
        assertTrue(_set.tryAdd(value));
        assertEq(_set.getCount(value), 1);
        _set.tryEnableFlags(value, 0xFF00);
        assertEq(_set.getCount(value), 256);
    }

    function test_tryIncrement() public {
        SetValue value = _getListValue(12);
        assertEq(_set.getCount(value), 0);

        for (uint256 i = 0; i < _MAX_COUNTER_VALUE + 1; ++i) {
            assertTrue(_set.tryIncrement(value));
            assertEq(_set.getCount(value), i + 1);
        }

        assertFalse(_set.tryIncrement(value));
        assertEq(_set.getCount(value), 256);

        assertTrue(_set.contains(value));
        assertFalse(_set.tryAdd(value));
    }

    function test_tryDecrement() public {
        SetValue value = _getListValue(12);
        assertEq(_set.getCount(value), 0);
        assertFalse(_set.tryDecrement(value));

        for (uint256 i = 0; i < _MAX_COUNTER_VALUE + 1; ++i) {
            _set.tryIncrement(value);
        }

        for (uint256 i = _MAX_COUNTER_VALUE + 1; i > 0; --i) {
            assertTrue(_set.tryDecrement(value));
            assertEq(_set.getCount(value), i - 1);
        }

        assertFalse(_set.tryDecrement(value));
        assertEq(_set.getCount(value), 0);

        assertFalse(_set.contains(value));
        assertFalse(_set.tryRemove(value));
    }
}
