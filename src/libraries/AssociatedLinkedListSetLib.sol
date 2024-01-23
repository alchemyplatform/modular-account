// This file is part of Modular Account.
//
// Copyright 2024 Alchemy Insights, Inc.
//
// SPDX-License-Identifier: MIT
//
// See LICENSE-MIT file for more information

pragma solidity ^0.8.22;

import {SetValue, SENTINEL_VALUE, HAS_NEXT_FLAG} from "./Constants.sol";

/// @dev Type representing the set, which is just a storage slot placeholder like the solidity mapping type.
struct AssociatedLinkedListSet {
    bytes32 placeholder;
}

/// @title Associated Linked List Set Library
/// @author Alchemy
/// @notice Provides a set data structure that is enumerable and held in address-associated storage (per the
/// ERC-4337 spec)
library AssociatedLinkedListSetLib {
    // Mapping Entry Byte Layout
    // | value | 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA____ |
    // | meta  | 0x____________________________________________________________BBBB |

    // Bit-layout of the meta bytes (2 bytes)
    // | user flags | 11111111 11111100 |
    // | has next   | 00000000 00000010 |
    // | sentinel   | 00000000 00000001 |

    // Mapping keys exclude the upper 15 bits of the meta bytes, which allows keys to be either a value or the
    // sentinel.

    // This cannot be evaluated at compile time because of its use in inline assembly.
    bytes4 internal constant _ASSOCIATED_STORAGE_PREFIX = 0xf938c976; // bytes4(keccak256("AssociatedLinkedListSet"))

    // A custom type representing the index of a storage slot
    type StoragePointer is bytes32;

    // A custom type representing a pointer to a location in memory beyond the current free memory pointer.
    // Holds a fixed-size buffer similar to "bytes memory", but without a length field.
    // Care must be taken when using these, as they may be overwritten if ANY memory is allocated after allocating
    // a TempBytesMemory.
    type TempBytesMemory is bytes32;

    // INTERNAL METHODS

    /// @notice Adds a value to a set.
    /// @param set The set to add the value to.
    /// @param associated The address the set is associated with.
    /// @param value The value to add.
    /// @return True if the value was added, false if the value cannot be added (already exists or is zero).
    function tryAdd(AssociatedLinkedListSet storage set, address associated, SetValue value)
        internal
        returns (bool)
    {
        bytes32 unwrappedKey = bytes32(SetValue.unwrap(value));
        if (unwrappedKey == bytes32(0)) {
            // Cannot add the zero value
            return false;
        }

        TempBytesMemory keyBuffer = _allocateTempKeyBuffer(set, associated);

        StoragePointer valueSlot = _mapLookup(keyBuffer, unwrappedKey);
        if (_load(valueSlot) != bytes32(0)) {
            // Entry already exists
            return false;
        }

        // Load the head of the set
        StoragePointer sentinelSlot = _mapLookup(keyBuffer, SENTINEL_VALUE);
        bytes32 prev = _load(sentinelSlot);
        if (prev == bytes32(0) || isSentinel(prev)) {
            // set is empty, need to do:
            // map[SENTINEL_VALUE] = unwrappedKey;
            // map[unwrappedKey] = SENTINEL_VALUE;
            _store(sentinelSlot, unwrappedKey);
            _store(valueSlot, SENTINEL_VALUE);
        } else {
            // set is not empty, need to do:
            // map[SENTINEL_VALUE] = unwrappedKey | HAS_NEXT_FLAG;
            // map[unwrappedKey] = prev;
            _store(sentinelSlot, unwrappedKey | HAS_NEXT_FLAG);
            _store(valueSlot, prev);
        }

        return true;
    }

    /// @notice Removes a value from a set.
    /// @dev This is an O(n) operation, where n is the number of elements in the set.
    /// @param set The set to remove the value from
    /// @param associated The address the set is associated with
    /// @param value The value to remove
    /// @return True if the value was removed, false if the value does not exist
    function tryRemove(AssociatedLinkedListSet storage set, address associated, SetValue value)
        internal
        returns (bool)
    {
        bytes32 unwrappedKey = bytes32(SetValue.unwrap(value));
        TempBytesMemory keyBuffer = _allocateTempKeyBuffer(set, associated);

        StoragePointer valueSlot = _mapLookup(keyBuffer, unwrappedKey);
        bytes32 nextValue = _load(valueSlot);
        if (unwrappedKey == bytes32(0) || nextValue == bytes32(0)) {
            // Entry does not exist
            return false;
        }

        bytes32 prevKey = SENTINEL_VALUE;
        bytes32 currentVal;
        do {
            // Load the current entry
            StoragePointer prevSlot = _mapLookup(keyBuffer, prevKey);
            currentVal = _load(prevSlot);
            bytes32 currentKey = clearFlags(currentVal);
            if (currentKey == unwrappedKey) {
                // Found the entry
                // Set the previous value's next value to the next value,
                // and the flags to the current value's flags.
                // and the next value's `hasNext` flag to determine whether or not the next value is (or points to)
                // the sentinel value.

                // Need to do:
                // map[prevKey] = clearFlags(nextValue) | getUserFlags(currentVal) | (nextValue & HAS_NEXT_FLAG);
                // map[currentKey] = bytes32(0);

                _store(prevSlot, clearFlags(nextValue) | getUserFlags(currentVal) | (nextValue & HAS_NEXT_FLAG));
                _store(valueSlot, bytes32(0));

                return true;
            }
            prevKey = currentKey;
        } while (!isSentinel(currentVal) && currentVal != bytes32(0));
        return false;
    }

    /// @notice Removes a value from a set, given the previous value in the set.
    /// @dev This is an O(1) operation but requires additional knowledge.
    /// @param set The set to remove the value from
    /// @param associated The address the set is associated with
    /// @param value The value to remove
    /// @param prev The previous value in the set
    /// @return True if the value was removed, false if the value does not exist
    function tryRemoveKnown(AssociatedLinkedListSet storage set, address associated, SetValue value, bytes32 prev)
        internal
        returns (bool)
    {
        bytes32 unwrappedKey = bytes32(SetValue.unwrap(value));
        TempBytesMemory keyBuffer = _allocateTempKeyBuffer(set, associated);

        prev = clearFlags(prev);

        if (prev == bytes32(0) || unwrappedKey == bytes32(0)) {
            return false;
        }

        // assert that the previous key's next value is the value to be removed
        StoragePointer prevSlot = _mapLookup(keyBuffer, prev);
        bytes32 currentValue = _load(prevSlot);
        if (clearFlags(currentValue) != unwrappedKey) {
            return false;
        }

        StoragePointer valueSlot = _mapLookup(keyBuffer, unwrappedKey);
        bytes32 next = _load(valueSlot);
        if (next == bytes32(0)) {
            // The set didn't actually contain the value
            return false;
        }

        // Need to do:
        // map[prev] = clearUserFlags(next) | getUserFlags(currentValue);
        // map[unwrappedKey] = bytes32(0);
        _store(prevSlot, clearUserFlags(next) | getUserFlags(currentValue));
        _store(valueSlot, bytes32(0));

        return true;
    }

    /// @notice Removes all values from a set.
    /// @dev This is an O(n) operation, where n is the number of elements in the set.
    /// @param set The set to remove the values from
    /// @param associated The address the set is associated with
    function clear(AssociatedLinkedListSet storage set, address associated) internal {
        TempBytesMemory keyBuffer = _allocateTempKeyBuffer(set, associated);

        bytes32 cursor = SENTINEL_VALUE;

        do {
            StoragePointer cursorSlot = _mapLookup(keyBuffer, cursor);
            bytes32 next = clearFlags(_load(cursorSlot));
            _store(cursorSlot, bytes32(0));
            cursor = next;
        } while (!isSentinel(cursor) && cursor != bytes32(0));
    }

    /// @notice Set the flags on a value in the set.
    /// @dev The user flags can only be set on the upper 14 bits, because the lower two are reserved for the
    /// sentinel and has next bit.
    /// @param set The set containing the value.
    /// @param associated The address the set is associated with.
    /// @param value The value to set the flags on.
    /// @param flags The flags to set.
    /// @return True if the set contains the value and the operation succeeds, false otherwise.
    function trySetFlags(AssociatedLinkedListSet storage set, address associated, SetValue value, uint16 flags)
        internal
        returns (bool)
    {
        bytes32 unwrappedKey = SetValue.unwrap(value);
        TempBytesMemory keyBuffer = _allocateTempKeyBuffer(set, associated);

        // Ignore the lower 2 bits.
        flags &= 0xFFFC;

        // If the set doesn't actually contain the value, return false;
        StoragePointer valueSlot = _mapLookup(keyBuffer, unwrappedKey);
        bytes32 next = _load(valueSlot);
        if (next == bytes32(0)) {
            return false;
        }

        // Set the flags
        _store(valueSlot, clearUserFlags(next) | bytes32(uint256(flags)));

        return true;
    }

    /// @notice Set the given flags on a value in the set, preserving the values of other flags.
    /// @dev The user flags can only be set on the upper 14 bits, because the lower two are reserved for the
    /// sentinel and has next bit.
    /// Short-circuits if the flags are already enabled, returning true.
    /// @param set The set containing the value.
    /// @param associated The address the set is associated with.
    /// @param value The value to enable the flags on.
    /// @param flags The flags to enable.
    /// @return True if the operation succeeds or short-circuits due to the flags already being enabled. False
    /// otherwise.
    function tryEnableFlags(AssociatedLinkedListSet storage set, address associated, SetValue value, uint16 flags)
        internal
        returns (bool)
    {
        flags &= 0xFFFC; // Allow short-circuit if lower bits are accidentally set
        uint16 currFlags = getFlags(set, associated, value);
        if (currFlags & flags == flags) return true; // flags are already enabled
        return trySetFlags(set, associated, value, currFlags | flags);
    }

    /// @notice Clear the given flags on a value in the set, preserving the values of other flags.
    /// @notice If the value is not in the set, this function will still return true.
    /// @dev The user flags can only be set on the upper 14 bits, because the lower two are reserved for the
    /// sentinel and has next bit.
    /// Short-circuits if the flags are already disabled, or if set does not contain the value. Short-circuits
    /// return true.
    /// @param set The set containing the value.
    /// @param associated The address the set is associated with.
    /// @param value The value to disable the flags on.
    /// @param flags The flags to disable.
    /// @return True if the operation succeeds, or short-circuits due to the flags already being disabled or if the
    /// set does not contain the value. False otherwise.
    function tryDisableFlags(AssociatedLinkedListSet storage set, address associated, SetValue value, uint16 flags)
        internal
        returns (bool)
    {
        flags &= 0xFFFC; // Allow short-circuit if lower bits are accidentally set
        uint16 currFlags = getFlags(set, associated, value);
        if (currFlags & flags == 0) return true; // flags are already disabled
        return trySetFlags(set, associated, value, currFlags & ~flags);
    }

    /// @notice Checks if a set contains a value
    /// @dev This method does not clear the upper bits of `value`, that is expected to be done as part of casting
    /// to the correct type. If this function is provided the sentinel value by using the upper bits, this function
    /// may returns `true`.
    /// @param set The set to check
    /// @param associated The address the set is associated with
    /// @param value The value to check for
    /// @return True if the set contains the value, false otherwise
    function contains(AssociatedLinkedListSet storage set, address associated, SetValue value)
        internal
        view
        returns (bool)
    {
        bytes32 unwrappedKey = bytes32(SetValue.unwrap(value));
        TempBytesMemory keyBuffer = _allocateTempKeyBuffer(set, associated);

        StoragePointer slot = _mapLookup(keyBuffer, unwrappedKey);
        return _load(slot) != bytes32(0);
    }

    /// @notice Checks if a set is empty
    /// @param set The set to check
    /// @param associated The address the set is associated with
    /// @return True if the set is empty, false otherwise
    function isEmpty(AssociatedLinkedListSet storage set, address associated) internal view returns (bool) {
        TempBytesMemory keyBuffer = _allocateTempKeyBuffer(set, associated);

        StoragePointer sentinelSlot = _mapLookup(keyBuffer, SENTINEL_VALUE);
        bytes32 val = _load(sentinelSlot);
        return val == bytes32(0) || isSentinel(val); // either the sentinel is unset, or points to itself
    }

    /// @notice Get the flags on a value in the set.
    /// @dev The reserved lower 2 bits will not be returned, as those are reserved for the sentinel and has next
    /// bit.
    /// @param set The set containing the value.
    /// @param associated The address the set is associated with.
    /// @param value The value to get the flags from.
    /// @return The flags set on the value.
    function getFlags(AssociatedLinkedListSet storage set, address associated, SetValue value)
        internal
        view
        returns (uint16)
    {
        bytes32 unwrappedKey = SetValue.unwrap(value);
        TempBytesMemory keyBuffer = _allocateTempKeyBuffer(set, associated);
        return uint16(uint256(_load(_mapLookup(keyBuffer, unwrappedKey))) & 0xFFFC);
    }

    /// @notice Check if the flags on a value are enabled.
    /// @dev The reserved lower 2 bits will be ignored, as those are reserved for the sentinel and has next bit.
    /// @param set The set containing the value.
    /// @param associated The address the set is associated with.
    /// @param value The value to check the flags on.
    /// @param flags The flags to check.
    /// @return True if all of the flags are enabled, false otherwise.
    function flagsEnabled(AssociatedLinkedListSet storage set, address associated, SetValue value, uint16 flags)
        internal
        view
        returns (bool)
    {
        flags &= 0xFFFC;
        return getFlags(set, associated, value) & flags == flags;
    }

    /// @notice Check if the flags on a value are disabled.
    /// @dev The reserved lower 2 bits will be ignored, as those are reserved for the sentinel and has next bit.
    /// @param set The set containing the value.
    /// @param associated The address the set is associated with.
    /// @param value The value to check the flags on.
    /// @param flags The flags to check.
    /// @return True if all of the flags are disabled, false otherwise.
    function flagsDisabled(AssociatedLinkedListSet storage set, address associated, SetValue value, uint16 flags)
        internal
        view
        returns (bool)
    {
        flags &= 0xFFFC;
        return ~(getFlags(set, associated, value)) & flags == flags;
    }

    /// @notice Gets all elements in a set.
    /// @dev This is an O(n) operation, where n is the number of elements in the set.
    /// @param set The set to get the elements of.
    /// @return ret An array of all elements in the set.
    function getAll(AssociatedLinkedListSet storage set, address associated)
        internal
        view
        returns (SetValue[] memory ret)
    {
        TempBytesMemory keyBuffer = _allocateTempKeyBuffer(set, associated);
        uint256 size;
        bytes32 cursor = _load(_mapLookup(keyBuffer, SENTINEL_VALUE));

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
            // Add an extra offset of 4 words to account for the length of the keyBuffer, since it will be used
            // for each lookup. If this value were written back to the free memory pointer, it would effectively
            // convert the keyBuffer into a "bytes memory" type. However, we don't actually write to the free
            // memory pointer until after all we've also allocated the entire return array.
            ret := add(ret, 0x80)
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
                cursor = _load(_mapLookup(keyBuffer, cleared));
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

    // PRIVATE METHODS

    /// @notice Given an allocated key buffer, returns the storage slot for a given key
    function _mapLookup(TempBytesMemory keyBuffer, bytes32 value) private pure returns (StoragePointer slot) {
        assembly ("memory-safe") {
            // Store the value in the last word.
            mstore(add(keyBuffer, 0x60), value)
            slot := keccak256(keyBuffer, 0x80)
        }
    }

    /// @notice Allocates a key buffer for a given ID and associated address into scratch space memory.
    /// @dev The returned buffer must not be used if any additional memory is allocated after calling this
    /// function.
    /// @param set The set to allocate the key buffer for.
    /// @param associated The address the set is associated with.
    /// @return key A key buffer that can be used to lookup values in the set
    function _allocateTempKeyBuffer(AssociatedLinkedListSet storage set, address associated)
        private
        pure
        returns (TempBytesMemory key)
    {
        // Key derivation for an entry
        // Note: `||` refers to the concat operator
        // associated addr (left-padded) || prefix || uint224(0) batchIndex || set storage slot || entry
        // Word 1:
        // | zeros              | 0x000000000000000000000000________________________________________ |
        // | address            | 0x________________________AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA |
        // Word 2:
        // | prefix             | 0xPPPPPPPP________________________________________________________ |
        // | batch index (zero) | 0x________00000000000000000000000000000000000000000000000000000000 |
        // Word 3:
        // | set storage slot  | 0xSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS |
        // Word 4:
        // | entry value        | 0xVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV____ |
        // | entry meta         | 0x____________________________________________________________MMMM |

        // The batch index is for consistency with PluginStorageLib, and the prefix in front of it is
        // to prevent any potential crafted collisions where the batch index may be equal to storage slot
        // of the ALLS. The prefix is set to the upper bits of the batch index to make it infeasible to
        // reach from just incrementing the value.

        // This segment is memory-safe because it only uses the scratch space memory after the value of the free
        // memory pointer.
        // See https://docs.soliditylang.org/en/v0.8.22/assembly.html#memory-safety
        assembly ("memory-safe") {
            // Clean upper bits of arguments
            associated := and(associated, 0xffffffffffffffffffffffffffffffffffffffff)

            // Use memory past-the-free-memory-pointer without updating it, as this is just scratch space
            key := mload(0x40)
            // Store the associated address in the first word, left-padded with zeroes
            mstore(key, associated)
            // Store the prefix and a batch index of 0
            mstore(add(key, 0x20), _ASSOCIATED_STORAGE_PREFIX)
            // Store the list's storage slot in the third word
            mstore(add(key, 0x40), set.slot)
            // Leaves the last word open for the value entry
        }

        return key;
    }

    /// @dev Loads a value from storage
    function _load(StoragePointer ptr) private view returns (bytes32 val) {
        assembly ("memory-safe") {
            val := sload(ptr)
        }
    }

    /// @dev Writes a value into storage
    function _store(StoragePointer ptr, bytes32 val) private {
        assembly ("memory-safe") {
            sstore(ptr, val)
        }
    }
}
