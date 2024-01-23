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

import {CommonBase} from "forge-std/Base.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {StdUtils} from "forge-std/StdUtils.sol";

import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {
    AssociatedLinkedListSet,
    AssociatedLinkedListSetLib
} from "../../../src/libraries/AssociatedLinkedListSetLib.sol";
import {SetValue} from "../../../src/libraries/Constants.sol";

/// @notice A handler contract for differential invariant testing AssociatedLinkedListSetLib
///         This contract maps logic for adding, removeing, clearing, and inspecting a list
///         to a reference implementation using EnumerableSet.Bytes32Set, which the invariant
///         fuzzer can then use to test the library.
contract AssociatedLinkedListSetHandler is CommonBase, StdCheats, StdUtils {
    using AssociatedLinkedListSetLib for AssociatedLinkedListSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableMap for EnumerableMap.Bytes32ToUintMap;

    mapping(address => mapping(uint64 => EnumerableSet.Bytes32Set)) internal _referenceSets;
    mapping(address => mapping(uint64 => EnumerableMap.Bytes32ToUintMap)) internal _referenceMeta;

    error FailedToAdd(bytes30 value);
    error FailedToAddFlags(uint16 value);
    error FailedToGetFlags(uint16 expected, uint16 actual);
    error BadAddFlags(bytes30 value, uint16 flags);
    error FailedToRemove(bytes30 value);
    error ShouldNotRemove(bytes30 value);
    error ContainsNotExpected(bytes30 value);
    error DoesNotContain(bytes30 value);
    error LengthMismatch(uint256 expected, uint256 actual);

    address public constant ASSOCIATED_1 = address(uint160(bytes20(keccak256("ASSOCIATED_1"))));
    address public constant ASSOCIATED_2 = address(uint160(bytes20(keccak256("ASSOCIATED_2"))));

    AssociatedLinkedListSet public set1;
    AssociatedLinkedListSet public set2;

    uint64 public constant ID_1 = 42;
    uint64 public constant ID_2 = 115557777;

    bytes32 internal constant SENTINEL_VALUE = bytes32(uint256(1));

    constructor() {}

    /// @notice Adds to both copies of the list - the associated one and the reference one
    function add(bytes30 val, uint256 seedAddr, uint256 seedId) external {
        AssociatedLinkedListSet storage associatedSet = seedId % 2 == 0 ? set1 : set2;
        uint64 id = uint64(seedId % 2 == 0 ? ID_1 : ID_2);
        address associated = address(seedAddr % 2 == 0 ? ASSOCIATED_1 : ASSOCIATED_2);

        EnumerableSet.Bytes32Set storage referenceSet = _referenceSets[associated][id];
        if (referenceSet.contains(bytes32(val)) || val == bytes30(0)) {
            return; // Silently do nothing
        }

        referenceSet.add(bytes32(val));

        bool success = associatedSet.tryAdd(associated, SetValue.wrap(val));
        if (!success) {
            revert FailedToAdd(val);
        }
    }

    /// @notice Removes a key from both sets by its index in the reference implementation.
    ///         Uses the  O(n) iterating remove method.
    function removeIterate(uint256 indexToRemove, uint256 seedAddr, uint256 seedId) external {
        AssociatedLinkedListSet storage associatedSet = seedId % 2 == 0 ? set1 : set2;
        uint64 id = uint64(seedId % 2 == 0 ? ID_1 : ID_2);
        address associated = address(seedAddr % 2 == 0 ? ASSOCIATED_1 : ASSOCIATED_2);
        EnumerableSet.Bytes32Set storage referenceSet = _referenceSets[associated][id];
        EnumerableMap.Bytes32ToUintMap storage referenceMeta = _referenceMeta[associated][id];

        if (referenceSet.length() == 0) {
            return; // Silently do nothing
        }

        indexToRemove = bound(indexToRemove, 0, referenceSet.length() - 1);

        bytes30 value = bytes30(referenceSet.at(indexToRemove));

        referenceSet.remove(bytes32(value));

        // Remove the meta entry if it exists
        referenceMeta.remove(bytes32(value));

        if (!associatedSet.tryRemove(associated, SetValue.wrap(value))) {
            revert FailedToRemove(value);
        }

        if (associatedSet.contains(associated, SetValue.wrap(value))) {
            revert ContainsNotExpected(value);
        }
    }

    /// @notice Removes a key from both sets by its index in the reference implementation.
    ///         Accepts an arbitrary value to attempt to remove that may or may not be in the list.
    ///         Uses the  O(n) iterating remove method.
    function removeRandKeyIterate(bytes30 val, uint256 seedAddr, uint256 seedId) external {
        AssociatedLinkedListSet storage associatedSet = seedId % 2 == 0 ? set1 : set2;
        uint64 id = uint64(seedId % 2 == 0 ? ID_1 : ID_2);
        address associated = address(seedAddr % 2 == 0 ? ASSOCIATED_1 : ASSOCIATED_2);

        EnumerableSet.Bytes32Set storage referenceSet = _referenceSets[associated][id];
        EnumerableMap.Bytes32ToUintMap storage referenceMeta = _referenceMeta[associated][id];

        if (!referenceSet.contains(bytes32(val))) {
            if (associatedSet.contains(associated, SetValue.wrap(val))) {
                revert ContainsNotExpected(val);
            }
            if (associatedSet.tryRemove(associated, SetValue.wrap(val))) {
                revert ShouldNotRemove(val);
            }
            if (associatedSet.contains(associated, SetValue.wrap(val))) {
                revert ContainsNotExpected(val);
            }
            return; // short-circuit after making assertions.
        }

        referenceSet.remove(bytes32(val));

        // Remove the meta entry if it exists
        referenceMeta.remove(bytes32(val));

        if (!associatedSet.tryRemove(associated, SetValue.wrap(val))) {
            revert FailedToRemove(val);
        }

        if (associatedSet.contains(associated, SetValue.wrap(val))) {
            revert ContainsNotExpected(val);
        }
    }

    /// @notice Removes a key by looking up it's predecessor via getAll before submitting the call
    /// Uses the O(1) remove method that has knowledge of the previous key.
    function removeKnownPrevKey(uint256 index, uint256 seedAddr, uint256 seedId) external {
        AssociatedLinkedListSet storage associatedSet = seedId % 2 == 0 ? set1 : set2;
        uint64 id = uint64(seedId % 2 == 0 ? ID_1 : ID_2);
        address associated = address(seedAddr % 2 == 0 ? ASSOCIATED_1 : ASSOCIATED_2);

        EnumerableSet.Bytes32Set storage referenceSet = _referenceSets[associated][id];
        EnumerableMap.Bytes32ToUintMap storage referenceMeta = _referenceMeta[associated][id];

        if (referenceSet.length() == 0) {
            return; // Silently do nothing
        }

        index = bound(index, 0, referenceSet.length() - 1);

        bytes30 value = bytes30(referenceSet.at(index));

        referenceSet.remove(bytes32(value));

        // Remove the meta entry if it exists
        referenceMeta.remove(bytes32(value));

        // Get the previous entry via getAll
        SetValue[] memory values = associatedSet.getAll(associated);
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

        if (!associatedSet.tryRemoveKnown(associated, SetValue.wrap(value), prev)) {
            revert FailedToRemove(value);
        }

        if (associatedSet.contains(associated, SetValue.wrap(value))) {
            revert ContainsNotExpected(value);
        }
    }

    /// @notice Removes a key using the O(1) remove method that has knowledge of the previous key.
    ///         Accepts an arbitrary value for the remove and for prev that may or may not be in the list.
    function removeRandKnownPrevKey(bytes30 val, bytes32 prev, uint256 seedAddr, uint256 seedId) external {
        AssociatedLinkedListSet storage associatedSet = seedId % 2 == 0 ? set1 : set2;
        uint64 id = uint64(seedId % 2 == 0 ? ID_1 : ID_2);
        address associated = address(seedAddr % 2 == 0 ? ASSOCIATED_1 : ASSOCIATED_2);

        EnumerableSet.Bytes32Set storage referenceSet = _referenceSets[associated][id];
        EnumerableMap.Bytes32ToUintMap storage referenceMeta = _referenceMeta[associated][id];

        if (!referenceSet.contains(bytes32(val))) {
            if (associatedSet.contains(associated, SetValue.wrap(val))) {
                revert ContainsNotExpected(val);
            }
            if (associatedSet.tryRemoveKnown(associated, SetValue.wrap(val), prev)) {
                revert ShouldNotRemove(val);
            }
            if (associatedSet.contains(associated, SetValue.wrap(val))) {
                revert ContainsNotExpected(val);
            }
            return; // short-circuit after making assertions.
        }

        // Check to see in case it is actually the previous key
        SetValue[] memory values = associatedSet.getAll(associated);
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
        prev = AssociatedLinkedListSetLib.clearFlags(prev);

        if (realPrev != prev) {
            if (associatedSet.tryRemoveKnown(associated, SetValue.wrap(val), prev)) {
                revert ShouldNotRemove(val);
            }
            return; // short-circuit after making assertions.
        } else {
            // Somehow, the invariant fuzzer actually generated a real prev value. Process the removal
            referenceSet.remove(bytes32(val));

            // Remove the meta entry if it exists
            referenceMeta.remove(bytes32(val));

            if (!associatedSet.tryRemoveKnown(associated, SetValue.wrap(val), prev)) {
                revert FailedToRemove(val);
            }
            if (associatedSet.contains(associated, SetValue.wrap(val))) {
                revert ContainsNotExpected(val);
            }
        }
    }

    /// @notice Clears both copies of the list - the associated one and the reference one.
    function clear(uint256 seedAddr, uint256 seedId) external {
        AssociatedLinkedListSet storage associatedSet = seedId % 2 == 0 ? set1 : set2;
        uint64 id = uint64(seedId % 2 == 0 ? ID_1 : ID_2);
        address associated = address(seedAddr % 2 == 0 ? ASSOCIATED_1 : ASSOCIATED_2);

        EnumerableSet.Bytes32Set storage referenceSet = _referenceSets[associated][id];
        EnumerableMap.Bytes32ToUintMap storage referenceMeta = _referenceMeta[associated][id];

        while (referenceSet.length() > 0) {
            bytes30 value = bytes30(referenceSet.at(0));
            referenceSet.remove(bytes32(value));
            referenceMeta.remove(bytes32(value));
        }

        associatedSet.clear(associated);
    }

    function addFlagKnown(uint256 seedAddr, uint256 seedId, uint256 indexToFlag, uint16 flags) external {
        AssociatedLinkedListSet storage associatedSet = seedId % 2 == 0 ? set1 : set2;
        uint64 id = uint64(seedId % 2 == 0 ? ID_1 : ID_2);
        address associated = address(seedAddr % 2 == 0 ? ASSOCIATED_1 : ASSOCIATED_2);

        EnumerableSet.Bytes32Set storage referenceSet = _referenceSets[associated][id];
        EnumerableMap.Bytes32ToUintMap storage referenceMeta = _referenceMeta[associated][id];

        if (referenceSet.length() == 0) {
            return; // Silently do nothing
        }

        flags &= 0xFFFC; // Clear the last two bits

        indexToFlag = bound(indexToFlag, 0, referenceSet.length() - 1);

        bytes30 value = bytes30(referenceSet.at(indexToFlag));

        if (!associatedSet.trySetFlags(associated, SetValue.wrap(value), flags)) {
            revert FailedToAddFlags(flags);
        }

        uint16 returnedFlags = associatedSet.getFlags(associated, SetValue.wrap(value));
        if (returnedFlags != flags) {
            revert FailedToGetFlags(flags, returnedFlags);
        }

        // Add this entry to the reference set.
        referenceMeta.set(bytes32(value), flags);
    }

    function addFlagRandom(uint256 seedAddr, uint256 seedId, bytes30 key, uint16 flags) external {
        AssociatedLinkedListSet storage associatedSet = seedId % 2 == 0 ? set1 : set2;
        uint64 id = uint64(seedId % 2 == 0 ? ID_1 : ID_2);
        address associated = address(seedAddr % 2 == 0 ? ASSOCIATED_1 : ASSOCIATED_2);

        EnumerableSet.Bytes32Set storage referenceSet = _referenceSets[associated][id];
        EnumerableMap.Bytes32ToUintMap storage referenceMeta = _referenceMeta[associated][id];

        flags &= 0xFFFC; // Clear the last two bits

        if (!referenceSet.contains(bytes32(key))) {
            if (associatedSet.trySetFlags(associated, SetValue.wrap(key), flags)) {
                revert BadAddFlags(key, flags);
            }
        } else {
            // The value actually exists, add the flags correctly
            if (!associatedSet.trySetFlags(associated, SetValue.wrap(key), flags)) {
                revert FailedToAddFlags(flags);
            }

            uint16 returnedFlags = associatedSet.getFlags(associated, SetValue.wrap(key));
            if (returnedFlags != flags) {
                revert FailedToGetFlags(flags, returnedFlags);
            }

            // Add this entry to the reference set.
            referenceMeta.set(bytes32(key), flags);
        }
    }

    /// @notice Checks if the associated set contains a value
    function associatedContains(address associated, uint64 id, bytes30 val) external view returns (bool) {
        AssociatedLinkedListSet storage associatedSet = _mapIdToSet(id);

        return associatedSet.contains(associated, SetValue.wrap(val));
    }

    /// @notice Checks if the reference set contains a value
    function referenceContains(address associated, uint64 id, bytes30 val) external view returns (bool) {
        EnumerableSet.Bytes32Set storage referenceSet = _referenceSets[associated][id];
        return referenceSet.contains(bytes32(val));
    }

    /// @notice Checks if the associated set is empty
    function associatedIsEmpty(address associated, uint64 id) external view returns (bool) {
        AssociatedLinkedListSet storage associatedSet = _mapIdToSet(id);
        return associatedSet.isEmpty(associated);
    }

    /// @notice Checks if the reference set is empty
    function referenceIsEmpty(address associated, uint64 id) external view returns (bool) {
        EnumerableSet.Bytes32Set storage referenceSet = _referenceSets[associated][id];
        return referenceSet.length() == 0;
    }

    /// @notice Gets all contents of the reference set
    function referenceEnumerate(address associated, uint64 id) external view returns (bytes32[] memory ret) {
        EnumerableSet.Bytes32Set storage referenceSet = _referenceSets[associated][id];
        ret = new bytes32[](referenceSet.length());
        for (uint256 i = 0; i < referenceSet.length(); i++) {
            ret[i] = referenceSet.at(i);
        }
    }

    /// @notice Gets all contents of the associated set
    function associatedEnumerate(address associated, uint64 id) external view returns (bytes32[] memory ret) {
        AssociatedLinkedListSet storage set = _mapIdToSet(id);
        SetValue[] memory values = set.getAll(associated);
        // Unsafe cast lol
        assembly ("memory-safe") {
            ret := values
        }
    }

    function referenceGetFlags(address associated, uint64 id)
        external
        view
        returns (bytes32[] memory keys, uint16[] memory metas)
    {
        EnumerableMap.Bytes32ToUintMap storage referenceMeta = _referenceMeta[associated][id];

        keys = new bytes32[](referenceMeta.length());
        metas = new uint16[](referenceMeta.length());

        for (uint256 i = 0; i < referenceMeta.length(); i++) {
            (bytes32 key, uint256 meta) = referenceMeta.at(i);
            keys[i] = key;
            metas[i] = uint16(meta);
        }
    }

    function associatedGetFlags(address associated, uint64 id, bytes30 key) external view returns (uint16 meta) {
        AssociatedLinkedListSet storage associatedSet = _mapIdToSet(id);
        meta = associatedSet.getFlags(associated, SetValue.wrap(key));
    }

    function _mapIdToSet(uint64 id) private view returns (AssociatedLinkedListSet storage associatedSet) {
        if (id == ID_1) {
            associatedSet = set1;
        } else if (id == ID_2) {
            associatedSet = set2;
        } else {
            revert("Invalid id");
        }
    }
}
