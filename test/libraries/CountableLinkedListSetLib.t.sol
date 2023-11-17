// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";

import {CountableLinkedListSetLib} from "../../src/libraries/CountableLinkedListSetLib.sol";
import {LinkedListSet, LinkedListSetLib} from "../../src/libraries/LinkedListSetLib.sol";
import {SetValue} from "../../src/libraries/LinkedListSetUtils.sol";

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
