// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {LinkedListSet, LinkedListSetLib} from "./LinkedListSetLib.sol";
import {SetValue} from "./LinkedListSetUtils.sol";

/// @title Countable Linked List Set Library
/// @author Alchemy
/// @notice This library adds the ability to count the number of occurrences of a value in a linked list set.
library CountableLinkedListSetLib {
    using LinkedListSetLib for LinkedListSet;

    /// @dev The counter is stored in the upper 8 bits of the the flag bytes, so the maximum value of the counter
    /// is 255. This means each value can be included a maximum of 256 times in the set, as the counter is 0 when
    /// the value is first added.
    uint16 internal constant _MAX_COUNTER_VALUE = 255;

    /// @notice Increment an existing value in the set, or add it if it doesn't exist.
    /// @dev The counter is stored in the upper 8 bits of the the flag bytes. Because this library repurposes a
    /// portion of the flag bytes to store the counter, it's important to not use the upper 8 bits to store flags.
    /// Any existing flags on the upper 8 bits will be interpreted as part of the counter.
    /// @param set The set to increment (or add) the value in.
    /// @param value The value to increment (or add).
    /// @return True if the value was incremented or added, false otherwise.
    function tryIncrement(LinkedListSet storage set, SetValue value) internal returns (bool) {
        if (!set.contains(value)) {
            return set.tryAdd(value);
        }
        uint16 flags = set.getFlags(value);
        // Use the upper 8 bits of the (16-bit) flag for the counter.
        uint16 counter = flags >> 8;
        if (counter == _MAX_COUNTER_VALUE) {
            return false;
        }
        unchecked {
            ++counter;
        }
        return set.trySetFlags(value, (counter << 8) | (flags & 0xFF));
    }

    /// @notice Decrement an existing value in the set, or remove it if the count has reached 0.
    /// @dev The counter is stored in the upper 8 bits of the the flag bytes. Because this library repurposes a
    /// portion of the flag bytes to store the counter, it's important to not use the upper 8 bits to store flags.
    /// Any existing flags on the upper 8 bits will be interpreted as part of the counter.
    /// @param set The set to decrement (or remove) the value in.
    /// @param value The value to decrement (or remove).
    /// @return True if the value was decremented or removed, false otherwise.
    function tryDecrement(LinkedListSet storage set, SetValue value) internal returns (bool) {
        if (!set.contains(value)) {
            return false;
        }
        uint16 flags = set.getFlags(value);
        // Use the upper 8 bits of the (16-bit) flag for the counter.
        uint16 counter = flags >> 8;
        if (counter == 0) {
            return set.tryRemove(value);
        }
        unchecked {
            --counter;
        }
        return set.trySetFlags(value, (counter << 8) | (flags & 0xFF));
    }

    /// @notice Get the number of occurrences of a value in the set.
    /// @dev The counter is stored in the upper 8 bits of the the flag bytes. Because this library repurposes a
    /// portion of the flag bytes to store the counter, it's important to not use the upper 8 bits to store flags.
    /// Any existing flags on the upper 8 bits will be interpreted as part of the counter.
    /// @return The number of occurrences of the value in the set.
    function getCount(LinkedListSet storage set, SetValue value) internal view returns (uint256) {
        if (!set.contains(value)) {
            return 0;
        }
        unchecked {
            return (set.getFlags(value) >> 8) + 1;
        }
    }
}
