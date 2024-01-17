// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {CommonBase} from "forge-std/Base.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {StdUtils} from "forge-std/StdUtils.sol";

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {LinkedListSetLib, LinkedListSet as EnumerableSetType} from "../../../src/libraries/LinkedListSetLib.sol";
import {SetValue} from "../../../src/libraries/Constants.sol";

/// @notice A handler contract for differential invariant testing LinkedListSetLib
///         This contract maps logic for adding, removeing, clearing, and inspecting a list
///         to a reference implementation using EnumerableSet.Bytes32Set, which the invariant
///         fuzzer can then use to test the library.
contract LinkedListSetHandler is CommonBase, StdCheats, StdUtils {
    using LinkedListSetLib for EnumerableSetType;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableMap for EnumerableMap.Bytes32ToUintMap;

    EnumerableSet.Bytes32Set internal referenceSet;
    EnumerableMap.Bytes32ToUintMap internal referenceMeta;

    EnumerableSetType internal libSet;

    error FailedToAdd(bytes30 value);
    error FailedToAddFlags(uint16 value);
    error FailedToGetFlags(uint16 expected, uint16 actual);
    error BadAddFlags(bytes30 value, uint16 flags);
    error FailedToRemove(bytes30 value);
    error ShouldNotRemove(bytes30 value);
    error ContainsNotExpected(bytes30 value);
    error DoesNotContain(bytes30 value);
    error LengthMismatch(uint256 expected, uint256 actual);
    error MetaDoesNotContain(bytes30 value);

    bytes32 internal constant SENTINEL_VALUE = bytes32(uint256(1));

    constructor() {}

    /// @notice Adds to both copies of the list - the library one and the reference one
    function add(bytes30 val) external {
        if (referenceSet.contains(bytes32(val)) || val == bytes30(0)) {
            return; // Silently do nothing
        }

        referenceSet.add(bytes32(val));

        bool success = libSet.tryAdd(SetValue.wrap(val));
        if (!success) {
            revert FailedToAdd(val);
        }
    }

    /// @notice Removes a key from both sets by its index in the reference implementation.
    ///         Uses the  O(n) iterating remove method.
    function removeIterate(uint256 indexToRemove) external {
        if (referenceSet.length() == 0) {
            return; // Silently do nothing
        }

        indexToRemove = bound(indexToRemove, 0, referenceSet.length() - 1);

        bytes30 value = bytes30(referenceSet.at(indexToRemove));

        // Assert the value was in the reference set and is now removed.
        if (!referenceSet.remove(bytes32(value))) {
            revert DoesNotContain(value);
        }

        // Remove the meta entry if it exists
        referenceMeta.remove(bytes32(value));

        if (!libSet.tryRemove(SetValue.wrap(value))) {
            revert FailedToRemove(value);
        }

        if (libSet.contains(SetValue.wrap(value))) {
            revert ContainsNotExpected(value);
        }
    }

    /// @notice Removes a key from both sets.
    ///         Accepts an arbitrary value to attempt to remove that may or may not be in the list.
    ///         Uses the  O(n) iterating remove method.
    function removeRandKeyIterate(bytes30 val) external {
        if (!referenceSet.contains(bytes32(val))) {
            if (libSet.contains(SetValue.wrap(val))) {
                revert ContainsNotExpected(val);
            }
            if (libSet.tryRemove(SetValue.wrap(val))) {
                revert ShouldNotRemove(val);
            }
            if (libSet.contains(SetValue.wrap(val))) {
                revert ContainsNotExpected(val);
            }
            return; // short-circuit after making assertions.
        }

        if (!referenceSet.remove(bytes32(val))) {
            revert DoesNotContain(val);
        }

        // Remove the meta entry if it exists
        referenceMeta.remove(bytes32(val));

        if (!libSet.tryRemove(SetValue.wrap(val))) {
            revert FailedToRemove(val);
        }

        if (libSet.contains(SetValue.wrap(val))) {
            revert ContainsNotExpected(val);
        }
    }

    /// @notice Removes a key by looking up it's predecessor via getAll before submitting the call
    /// Uses the O(1) remove method that has knowledge of the previous key.
    function removeKnownPrevKey(uint256 index) external {
        if (referenceSet.length() == 0) {
            return; // Silently do nothing
        }

        index = bound(index, 0, referenceSet.length() - 1);

        bytes30 value = bytes30(referenceSet.at(index));

        referenceSet.remove(bytes32(value));

        // Remove the meta entry if it exists
        referenceMeta.remove(bytes32(value));

        // Get the previous entry via getAll
        SetValue[] memory values = libSet.getAll();
        if (values.length == 0) {
            revert LengthMismatch(0, values.length);
        }

        bytes32 prev;
        for (uint256 i = 0; i < values.length; i++) {
            if (SetValue.unwrap(values[i]) == bytes30(value)) {
                if (i == 0) {
                    prev = SENTINEL_VALUE;
                } else {
                    prev = bytes32(SetValue.unwrap(values[i - 1]));
                }
                break;
            }
        }

        if (prev == bytes32(0)) {
            revert DoesNotContain(value);
        }

        if (!libSet.tryRemoveKnown(SetValue.wrap(value), prev)) {
            revert FailedToRemove(value);
        }

        if (libSet.contains(SetValue.wrap(value))) {
            revert ContainsNotExpected(value);
        }
    }

    /// @notice Removes a key using the O(1) remove method that has knowledge of the previous key.
    ///         Accepts an arbitrary value for the remove and for prev that may or may not be in the list.
    function removeRandKnownPrevKey(bytes30 val, bytes32 prev) external {
        if (!referenceSet.contains(bytes32(val))) {
            if (libSet.contains(SetValue.wrap(val))) {
                revert ContainsNotExpected(val);
            }
            if (libSet.tryRemoveKnown(SetValue.wrap(val), prev)) {
                revert ShouldNotRemove(val);
            }
            if (libSet.contains(SetValue.wrap(val))) {
                revert ContainsNotExpected(val);
            }
            return; // short-circuit after making assertions.
        }

        // Check to see in case it is actually the previous key
        SetValue[] memory values = libSet.getAll();
        if (values.length == 0) {
            revert LengthMismatch(0, values.length);
        }
        bytes32 realPrev;
        for (uint256 i = 0; i < values.length; i++) {
            if (SetValue.unwrap(values[i]) == bytes30(val)) {
                if (i == 0) {
                    realPrev = SENTINEL_VALUE;
                } else {
                    realPrev = bytes32(SetValue.unwrap(values[i - 1]));
                }
                break;
            }
        }

        // Clear the flags of prev to avoid any false test failures. This is ONLY safe to do if the library
        // function also performs this clear, otherwise it will result in untested edge cases.
        // This clearing is done after the prior check in the case where the value is not contained, to broaden the
        // test cases.
        prev = LinkedListSetLib.clearFlags(prev);

        if (realPrev != prev) {
            if (libSet.tryRemoveKnown(SetValue.wrap(val), prev)) {
                revert ShouldNotRemove(val);
            }
            return; // short-circuit after making assertions.
        } else {
            // Somehow, the invariant fuzzer actually generated a real prev value. Process the removal
            if (!referenceSet.remove(bytes32(val))) {
                revert DoesNotContain(val);
            }

            // Remove the meta entry if it exists
            referenceMeta.remove(bytes32(val));

            if (!libSet.tryRemoveKnown(SetValue.wrap(val), prev)) {
                revert FailedToRemove(val);
            }
            if (libSet.contains(SetValue.wrap(val))) {
                revert ContainsNotExpected(val);
            }
        }
    }

    /// @notice Clears both copies of the list - the library one and the reference one.
    function clear() external {
        while (referenceSet.length() > 0) {
            bytes30 value = bytes30(referenceSet.at(0));
            referenceSet.remove(bytes32(value));
            referenceMeta.remove(bytes32(value));
        }

        libSet.clear();
    }

    function addFlagKnown(uint256 indexToFlag, uint16 flags) external {
        if (referenceSet.length() == 0) {
            return; // Silently do nothing
        }

        flags &= 0xFFFC; // Clear the last two bits

        indexToFlag = bound(indexToFlag, 0, referenceSet.length() - 1);

        bytes30 value = bytes30(referenceSet.at(indexToFlag));

        if (!libSet.trySetFlags(SetValue.wrap(value), flags)) {
            revert FailedToAddFlags(flags);
        }

        uint16 returnedFlags = libSet.getFlags(SetValue.wrap(value));
        if (returnedFlags != flags) {
            revert FailedToGetFlags(flags, returnedFlags);
        }

        // Add this entry to the reference set.
        referenceMeta.set(bytes32(value), flags);
    }

    function addFlagRandom(bytes30 key, uint16 flags) external {
        flags &= 0xFFFC; // Clear the last two bits

        if (!referenceSet.contains(bytes32(key))) {
            if (libSet.trySetFlags(SetValue.wrap(key), flags)) {
                revert BadAddFlags(key, flags);
            }
        } else {
            // The value actually exists, add the flags correctly
            if (!libSet.trySetFlags(SetValue.wrap(key), flags)) {
                revert FailedToAddFlags(flags);
            }

            uint16 returnedFlags = libSet.getFlags(SetValue.wrap(key));
            if (returnedFlags != flags) {
                revert FailedToGetFlags(flags, returnedFlags);
            }

            // Add this entry to the reference set.
            referenceMeta.set(bytes32(key), flags);
        }
    }

    /// @notice Checks if the library set contains a value
    function libContains(bytes30 val) external view returns (bool) {
        return libSet.contains(SetValue.wrap(val));
    }

    /// @notice Checks if the reference set contains a value
    function referenceContains(bytes30 val) external view returns (bool) {
        return referenceSet.contains(bytes32(val));
    }

    /// @notice Checks if the library set is empty
    function libIsEmpty() external view returns (bool) {
        return libSet.isEmpty();
    }

    /// @notice Checks if the reference set is empty
    function referenceIsEmpty() external view returns (bool) {
        return referenceSet.length() == 0;
    }

    /// @notice Gets all contents of the reference set
    function referenceEnumerate() external view returns (bytes32[] memory ret) {
        ret = new bytes32[](referenceSet.length());
        for (uint256 i = 0; i < referenceSet.length(); i++) {
            ret[i] = referenceSet.at(i);
        }
    }

    /// @notice Gets all contents of the library set
    function libEnumerate() external view returns (bytes32[] memory ret) {
        SetValue[] memory values = libSet.getAll();
        // Unsafe cast lol
        assembly ("memory-safe") {
            ret := values
        }
    }

    function referenceGetFlags() external view returns (bytes32[] memory keys, uint16[] memory metas) {
        keys = new bytes32[](referenceMeta.length());
        metas = new uint16[](referenceMeta.length());

        for (uint256 i = 0; i < referenceMeta.length(); i++) {
            (bytes32 key, uint256 meta) = referenceMeta.at(i);
            keys[i] = key;
            metas[i] = uint16(meta);
        }
    }

    function libGetFlags(bytes30 key) external view returns (uint16 meta) {
        meta = libSet.getFlags(SetValue.wrap(key));
    }
}
