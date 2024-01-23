// This file is part of Modular Account.
//
// Copyright 2024 Alchemy Insights, Inc.
//
// SPDX-License-Identifier: MIT
//
// See LICENSE-MIT file for more information

pragma solidity ^0.8.22;

import {SetValue, SENTINEL_VALUE, HAS_NEXT_FLAG} from "./Constants.sol";

struct LinkedListSet {
    // Byte Layout
    // | value | 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA____ |
    // | meta  | 0x____________________________________________________________BBBB |

    // Bit-layout of the meta bytes (2 bytes)
    // | user flags | 11111111 11111100 |
    // | has next   | 00000000 00000010 |
    // | sentinel   | 00000000 00000001 |

    // Key excludes the meta bytes, except for the sentinel value, which is 0x1
    mapping(bytes32 => bytes32) map;
}

/// @title Linked List Set Library
/// @author Alchemy
/// @notice This library provides a set of functions for managing enumerable sets of bytes30 values.
library LinkedListSetLib {
    // INTERNAL METHODS

    /// @notice Add a value to a set.
    /// @param set The set to add the value to.
    /// @param value The value to add.
    /// @return True if the value was added, false if the value cannot be added (already exists or is zero).
    function tryAdd(LinkedListSet storage set, SetValue value) internal returns (bool) {
        mapping(bytes32 => bytes32) storage map = set.map;
        bytes32 unwrappedKey = SetValue.unwrap(value);
        if (unwrappedKey == bytes32(0) || map[unwrappedKey] != bytes32(0)) return false;

        bytes32 prev = map[SENTINEL_VALUE];
        if (prev == bytes32(0) || isSentinel(prev)) {
            // Set is empty
            map[SENTINEL_VALUE] = unwrappedKey;
            map[unwrappedKey] = SENTINEL_VALUE;
        } else {
            // set is not empty
            map[SENTINEL_VALUE] = unwrappedKey | HAS_NEXT_FLAG;
            map[unwrappedKey] = prev;
        }

        return true;
    }

    /// @notice Remove a value from a set.
    /// @dev This is an O(n) operation, where n is the number of elements in the set.
    /// @param set The set to remove the value from.
    /// @param value The value to remove.
    /// @return True if the value was removed, false if the value does not exist.
    function tryRemove(LinkedListSet storage set, SetValue value) internal returns (bool) {
        mapping(bytes32 => bytes32) storage map = set.map;
        bytes32 unwrappedKey = SetValue.unwrap(value);

        bytes32 nextValue = map[unwrappedKey];
        if (unwrappedKey == bytes32(0) || nextValue == bytes32(0)) return false;

        bytes32 prevKey = SENTINEL_VALUE;
        bytes32 currentVal;
        do {
            currentVal = map[prevKey];
            bytes32 currentKey = clearFlags(currentVal);
            if (currentKey == unwrappedKey) {
                // Set the previous value's next value to the next value,
                // and the flags to the current value's flags.
                // and the next value's `hasNext` flag to determine whether or not the next value is (or points to)
                // the sentinel value.
                map[prevKey] = clearFlags(nextValue) | getUserFlags(currentVal) | (nextValue & HAS_NEXT_FLAG);
                map[currentKey] = bytes32(0);

                return true;
            }
            prevKey = currentKey;
        } while (!isSentinel(currentVal) && currentVal != bytes32(0));
        return false;
    }

    /// @notice Remove a value from a set, given the previous value in the set.
    /// @dev This is an O(1) operation but requires additional knowledge.
    /// @param set The set to remove the value from.
    /// @param value The value to remove.
    /// @param prev The previous value in the set.
    /// @return True if the value was removed, false if the value does not exist.
    function tryRemoveKnown(LinkedListSet storage set, SetValue value, bytes32 prev) internal returns (bool) {
        mapping(bytes32 => bytes32) storage map = set.map;
        bytes32 unwrappedKey = SetValue.unwrap(value);

        // Clear the flag bits of prev
        prev = clearFlags(prev);

        if (prev == bytes32(0) || unwrappedKey == bytes32(0)) {
            return false;
        }

        // assert that the previous value's next value is the value to be removed
        bytes32 currentValue = map[prev];
        if (clearFlags(currentValue) != unwrappedKey) {
            return false;
        }

        bytes32 next = map[unwrappedKey];
        if (next == bytes32(0)) {
            // The set didn't actually contain the value
            return false;
        }

        map[prev] = clearUserFlags(next) | getUserFlags(currentValue);
        map[unwrappedKey] = bytes32(0);
        return true;
    }

    /// @notice Remove all values from a set.
    /// @dev This is an O(n) operation, where n is the number of elements in the set.
    /// @param set The set to remove the values from.
    function clear(LinkedListSet storage set) internal {
        mapping(bytes32 => bytes32) storage map = set.map;
        bytes32 cursor = SENTINEL_VALUE;

        do {
            bytes32 next = clearFlags(map[cursor]);
            map[cursor] = bytes32(0);
            cursor = next;
        } while (!isSentinel(cursor) && cursor != bytes32(0));
    }

    /// @notice Set the flags on a value in the set.
    /// @dev The user flags can only be set on the upper 14 bits, because the lower two are reserved for the
    /// sentinel and has next bit.
    /// @param set The set containing the value.
    /// @param value The value to set the flags on.
    /// @param flags The flags to set.
    /// @return True if the set contains the value and the operation succeeds, false otherwise.
    function trySetFlags(LinkedListSet storage set, SetValue value, uint16 flags) internal returns (bool) {
        mapping(bytes32 => bytes32) storage map = set.map;
        bytes32 unwrappedKey = SetValue.unwrap(value);

        // Ignore the lower 2 bits.
        flags &= 0xFFFC;

        // If the set doesn't actually contain the value, return false;
        bytes32 next = map[unwrappedKey];
        if (next == bytes32(0)) {
            return false;
        }

        // Set the flags
        map[unwrappedKey] = clearUserFlags(next) | bytes32(uint256(flags));

        return true;
    }

    /// @notice Set the given flags on a value in the set, preserving the values of other flags.
    /// @dev The user flags can only be set on the upper 14 bits, because the lower two are reserved for the
    /// sentinel and has next bit.
    /// Short-circuits if the flags are already enabled, returning true.
    /// @param set The set containing the value.
    /// @param value The value to enable the flags on.
    /// @param flags The flags to enable.
    /// @return True if the operation succeeds or short-circuits due to the flags already being enabled. False
    /// otherwise.
    function tryEnableFlags(LinkedListSet storage set, SetValue value, uint16 flags) internal returns (bool) {
        flags &= 0xFFFC; // Allow short-circuit if lower bits are accidentally set
        uint16 currFlags = getFlags(set, value);
        if (currFlags & flags == flags) return true; // flags are already enabled
        return trySetFlags(set, value, currFlags | flags);
    }

    /// @notice Clear the given flags on a value in the set, preserving the values of other flags.
    /// @notice If the value is not in the set, this function will still return true.
    /// @dev The user flags can only be set on the upper 14 bits, because the lower two are reserved for the
    /// sentinel and has next bit.
    /// Short-circuits if the flags are already disabled, or if set does not contain the value. Short-circuits
    /// return true.
    /// @param set The set containing the value.
    /// @param value The value to disable the flags on.
    /// @param flags The flags to disable.
    /// @return True if the operation succeeds, or short-circuits due to the flags already being disabled or if the
    /// set does not contain the value. False otherwise.
    function tryDisableFlags(LinkedListSet storage set, SetValue value, uint16 flags) internal returns (bool) {
        flags &= 0xFFFC; // Allow short-circuit if lower bits are accidentally set
        uint16 currFlags = getFlags(set, value);
        if (currFlags & flags == 0) return true; // flags are already disabled
        return trySetFlags(set, value, currFlags & ~flags);
    }

    /// @notice Check if a set contains a value.
    /// @dev This method does not clear the upper bits of `value`, that is expected to be done as part of casting
    /// to the correct type. If this function is provided the sentinel value by using the upper bits, this function
    /// may returns `true`.
    /// @param set The set to check.
    /// @param value The value to check for.
    /// @return True if the set contains the value, false otherwise.
    function contains(LinkedListSet storage set, SetValue value) internal view returns (bool) {
        mapping(bytes32 => bytes32) storage map = set.map;
        return map[SetValue.unwrap(value)] != bytes32(0);
    }

    /// @notice Check if a set is empty.
    /// @param set The set to check.
    /// @return True if the set is empty, false otherwise.
    function isEmpty(LinkedListSet storage set) internal view returns (bool) {
        mapping(bytes32 => bytes32) storage map = set.map;
        bytes32 val = map[SENTINEL_VALUE];
        return val == bytes32(0) || isSentinel(val); // either the sentinel is unset, or points to itself
    }

    /// @notice Get the flags on a value in the set.
    /// @dev The reserved lower 2 bits will not be returned, as those are reserved for the sentinel and has next
    /// bit.
    /// @param set The set containing the value.
    /// @param value The value to get the flags from.
    /// @return The flags set on the value.
    function getFlags(LinkedListSet storage set, SetValue value) internal view returns (uint16) {
        mapping(bytes32 => bytes32) storage map = set.map;
        bytes32 unwrappedKey = SetValue.unwrap(value);

        return uint16(uint256(map[unwrappedKey]) & 0xFFFC);
    }

    /// @notice Check if the flags on a value are enabled.
    /// @dev The reserved lower 2 bits will be ignored, as those are reserved for the sentinel and has next bit.
    /// @param set The set containing the value.
    /// @param value The value to check the flags on.
    /// @param flags The flags to check.
    /// @return True if all of the flags are enabled, false otherwise.
    function flagsEnabled(LinkedListSet storage set, SetValue value, uint16 flags) internal view returns (bool) {
        flags &= 0xFFFC;
        return getFlags(set, value) & flags == flags;
    }

    /// @notice Check if the flags on a value are disabled.
    /// @dev The reserved lower 2 bits will be ignored, as those are reserved for the sentinel and has next bit.
    /// @param set The set containing the value.
    /// @param value The value to check the flags on.
    /// @param flags The flags to check.
    /// @return True if all of the flags are disabled, false otherwise.
    function flagsDisabled(LinkedListSet storage set, SetValue value, uint16 flags) internal view returns (bool) {
        flags &= 0xFFFC;
        return ~(getFlags(set, value)) & flags == flags;
    }

    /// @notice Get all elements in a set.
    /// @dev This is an O(n) operation, where n is the number of elements in the set.
    /// @param set The set to get the elements of.
    /// @return ret An array of all elements in the set.
    function getAll(LinkedListSet storage set) internal view returns (SetValue[] memory ret) {
        mapping(bytes32 => bytes32) storage map = set.map;
        uint256 size;
        bytes32 cursor = map[SENTINEL_VALUE];

        // Dynamically allocate the returned array as we iterate through the set, since we don't know the size
        // beforehand.
        // This is accomplished by first writing to memory after the free memory pointer,
        // then updating the free memory pointer to cover the newly-allocated data.
        // To the compiler, writes to memory after the free memory pointer are considered "memory safe".
        // See https://docs.soliditylang.org/en/v0.8.22/assembly.html#memory-safety
        // Stack variable lifting done when compiling with via-ir will only ever place variables into memory
        // locations below the current free memory pointer, so it is safe to compile this library with via-ir.
        // See https://docs.soliditylang.org/en/v0.8.22/yul.html#memoryguard
        assembly ("memory-safe") {
            // It is critical that no other memory allocations occur between:
            // -  loading the value of the free memory pointer into `ret`
            // -  updating the free memory pointer to point to the newly-allocated data, which is done after all
            // the values have been written.
            ret := mload(0x40)
        }

        while (!isSentinel(cursor) && cursor != bytes32(0)) {
            unchecked {
                ++size;
            }
            bytes32 cleared = clearFlags(cursor);
            // Place the item into the return array manually. Since the size was just incremented, it will point to
            // the next location to write to.
            assembly ("memory-safe") {
                mstore(add(ret, mul(size, 0x20)), cleared)
            }
            if (hasNext(cursor)) {
                cursor = map[cleared];
            } else {
                cursor = bytes32(0);
            }
        }

        assembly ("memory-safe") {
            // Update the free memory pointer with the now-known length of the array.
            mstore(0x40, add(ret, mul(add(size, 1), 0x20)))
            // Set the length of the array.
            mstore(ret, size)
        }
    }

    function isSentinel(bytes32 value) internal pure returns (bool ret) {
        assembly ("memory-safe") {
            ret := and(value, 1)
        }
    }

    function hasNext(bytes32 value) internal pure returns (bool) {
        return value & HAS_NEXT_FLAG != 0;
    }

    function clearFlags(bytes32 val) internal pure returns (bytes32) {
        return val & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0001;
    }

    /// @dev Preserves the lower two bits
    function clearUserFlags(bytes32 val) internal pure returns (bytes32) {
        return val & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0003;
    }

    function getUserFlags(bytes32 val) internal pure returns (bytes32) {
        return val & bytes32(uint256(0xFFFC));
    }
}
