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

import {CommonBase} from "forge-std/Base.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {StdUtils} from "forge-std/StdUtils.sol";

import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {
    LinkedListSet as EnumerableSetType,
    LinkedListSetLib,
    SetValue
} from "../../../src/libraries/LinkedListSetLib.sol";

/// @notice A handler contract for differential invariant testing LinkedListSetLib
///         This contract maps logic for adding, removeing, clearing, and inspecting a list
///         to a reference implementation using EnumerableSet.Bytes32Set, which the invariant
///         fuzzer can then use to test the library.
contract LinkedListSetHandler is CommonBase, StdCheats, StdUtils {
    using LinkedListSetLib for EnumerableSetType;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableMap for EnumerableMap.Bytes32ToUintMap;

    EnumerableSet.Bytes32Set internal _referenceSet;
    EnumerableMap.Bytes32ToUintMap internal _referenceMeta;

    EnumerableSetType internal _libSet;

    error FailedToAdd(bytes31 value);
    error FailedToRemove(bytes31 value);
    error ShouldNotRemove(bytes31 value);
    error ContainsNotExpected(bytes31 value);
    error DoesNotContain(bytes31 value);
    error LengthMismatch(uint256 expected, uint256 actual);
    error MetaDoesNotContain(bytes31 value);

    bytes32 internal constant _SENTINEL_VALUE = bytes32(uint256(1));

    constructor() {}

    /// @notice Adds to both copies of the list - the library one and the reference one
    function add(bytes31 val) external {
        if (_referenceSet.contains(bytes32(val)) || val == bytes31(0)) {
            return; // Silently do nothing
        }

        _referenceSet.add(bytes32(val));

        bool success = _libSet.tryAdd(SetValue.wrap(val));
        if (!success) {
            revert FailedToAdd(val);
        }
    }

    /// @notice Removes a key from both sets by its index in the reference implementation.
    ///         Uses the  O(n) iterating remove method.
    function removeIterate(uint256 indexToRemove) external {
        if (_referenceSet.length() == 0) {
            return; // Silently do nothing
        }

        indexToRemove = bound(indexToRemove, 0, _referenceSet.length() - 1);

        bytes31 value = bytes31(_referenceSet.at(indexToRemove));

        // Assert the value was in the reference set and is now removed.
        if (!_referenceSet.remove(bytes32(value))) {
            revert DoesNotContain(value);
        }

        // Remove the meta entry if it exists
        _referenceMeta.remove(bytes32(value));

        if (!_libSet.tryRemove(SetValue.wrap(value))) {
            revert FailedToRemove(value);
        }

        if (_libSet.contains(SetValue.wrap(value))) {
            revert ContainsNotExpected(value);
        }
    }

    /// @notice Removes a key from both sets.
    ///         Accepts an arbitrary value to attempt to remove that may or may not be in the list.
    ///         Uses the  O(n) iterating remove method.
    function removeRandKeyIterate(bytes31 val) external {
        if (!_referenceSet.contains(bytes32(val))) {
            if (_libSet.contains(SetValue.wrap(val))) {
                revert ContainsNotExpected(val);
            }
            if (_libSet.tryRemove(SetValue.wrap(val))) {
                revert ShouldNotRemove(val);
            }
            if (_libSet.contains(SetValue.wrap(val))) {
                revert ContainsNotExpected(val);
            }
            return; // short-circuit after making assertions.
        }

        if (!_referenceSet.remove(bytes32(val))) {
            revert DoesNotContain(val);
        }

        // Remove the meta entry if it exists
        _referenceMeta.remove(bytes32(val));

        if (!_libSet.tryRemove(SetValue.wrap(val))) {
            revert FailedToRemove(val);
        }

        if (_libSet.contains(SetValue.wrap(val))) {
            revert ContainsNotExpected(val);
        }
    }

    /// @notice Removes a key by looking up it's predecessor via getAll before submitting the call
    /// Uses the O(1) remove method that has knowledge of the previous key.
    function removeKnownPrevKey(uint256 index) external {
        if (_referenceSet.length() == 0) {
            return; // Silently do nothing
        }

        index = bound(index, 0, _referenceSet.length() - 1);

        bytes31 value = bytes31(_referenceSet.at(index));

        _referenceSet.remove(bytes32(value));

        // Remove the meta entry if it exists
        _referenceMeta.remove(bytes32(value));

        // Get the previous entry via getAll
        SetValue[] memory values = _libSet.getAll();
        if (values.length == 0) {
            revert LengthMismatch(0, values.length);
        }

        bytes32 prev;
        for (uint256 i = 0; i < values.length; i++) {
            if (SetValue.unwrap(values[i]) == bytes31(value)) {
                if (i == 0) {
                    prev = _SENTINEL_VALUE;
                } else {
                    prev = bytes32(SetValue.unwrap(values[i - 1]));
                }
                break;
            }
        }

        if (prev == bytes32(0)) {
            revert DoesNotContain(value);
        }

        if (!_libSet.tryRemoveKnown(SetValue.wrap(value), prev)) {
            revert FailedToRemove(value);
        }

        if (_libSet.contains(SetValue.wrap(value))) {
            revert ContainsNotExpected(value);
        }
    }

    /// @notice Removes a key using the O(1) remove method that has knowledge of the previous key.
    ///         Accepts an arbitrary value for the remove and for prev that may or may not be in the list.
    function removeRandKnownPrevKey(bytes31 val, bytes32 prev) external {
        if (!_referenceSet.contains(bytes32(val))) {
            if (_libSet.contains(SetValue.wrap(val))) {
                revert ContainsNotExpected(val);
            }
            if (_libSet.tryRemoveKnown(SetValue.wrap(val), prev)) {
                revert ShouldNotRemove(val);
            }
            if (_libSet.contains(SetValue.wrap(val))) {
                revert ContainsNotExpected(val);
            }
            return; // short-circuit after making assertions.
        }

        // Check to see in case it is actually the previous key
        SetValue[] memory values = _libSet.getAll();
        if (values.length == 0) {
            revert LengthMismatch(0, values.length);
        }
        bytes32 realPrev;
        for (uint256 i = 0; i < values.length; i++) {
            if (SetValue.unwrap(values[i]) == bytes31(val)) {
                if (i == 0) {
                    realPrev = _SENTINEL_VALUE;
                } else {
                    realPrev = bytes32(SetValue.unwrap(values[i - 1]));
                }
                break;
            }
        }

        if (realPrev != prev) {
            if (_libSet.tryRemoveKnown(SetValue.wrap(val), prev)) {
                revert ShouldNotRemove(val);
            }
            return; // short-circuit after making assertions.
        } else {
            // Somehow, the invariant fuzzer actually generated a real prev value. Process the removal
            if (!_referenceSet.remove(bytes32(val))) {
                revert DoesNotContain(val);
            }

            // Remove the meta entry if it exists
            _referenceMeta.remove(bytes32(val));

            if (!_libSet.tryRemoveKnown(SetValue.wrap(val), prev)) {
                revert FailedToRemove(val);
            }
            if (_libSet.contains(SetValue.wrap(val))) {
                revert ContainsNotExpected(val);
            }
        }
    }

    /// @notice Clears both copies of the list - the library one and the reference one.
    function clear() external {
        while (_referenceSet.length() > 0) {
            bytes31 value = bytes31(_referenceSet.at(0));
            _referenceSet.remove(bytes32(value));
            _referenceMeta.remove(bytes32(value));
        }

        _libSet.clear();
    }

    /// @notice Checks if the library set contains a value
    function libContains(bytes31 val) external view returns (bool) {
        return _libSet.contains(SetValue.wrap(val));
    }

    /// @notice Checks if the reference set contains a value
    function referenceContains(bytes31 val) external view returns (bool) {
        return _referenceSet.contains(bytes32(val));
    }

    /// @notice Checks if the library set is empty
    function libIsEmpty() external view returns (bool) {
        return _libSet.isEmpty();
    }

    /// @notice Checks if the reference set is empty
    function referenceIsEmpty() external view returns (bool) {
        return _referenceSet.length() == 0;
    }

    /// @notice Gets all contents of the reference set
    function referenceEnumerate() external view returns (bytes32[] memory ret) {
        ret = new bytes32[](_referenceSet.length());
        for (uint256 i = 0; i < _referenceSet.length(); i++) {
            ret[i] = _referenceSet.at(i);
        }
    }

    /// @notice Gets all contents of the library set
    function libEnumerate() external view returns (bytes32[] memory ret) {
        SetValue[] memory values = _libSet.getAll();
        // Unsafe cast
        /// @solidity memory-safe-assembly
        assembly {
            ret := values
        }
    }
}
