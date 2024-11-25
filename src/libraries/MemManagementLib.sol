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

import {HookConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {ExecutionStorage, ValidationStorage} from "../account/AccountStorage.sol";
import {LinkedListSet, LinkedListSetLib, SENTINEL_VALUE, SetValue} from "./LinkedListSetLib.sol";

type MemSnapshot is uint256;

/// @title Memory Management Library
/// @author Alchemy
/// @notice A library for managing memory in ModularAccount. Handles loading data from storage into memory, and
/// manipulating the free memory pointer.
library MemManagementLib {
    /// @notice Load execution hooks associated both with a validation function and an execution selector.
    /// @param execData The execution storage struct to load from.
    /// @param valData The validation storage struct to load from.
    /// @return hooks An array of `HookConfig` items, representing the execution hooks.
    function loadExecHooks(ExecutionStorage storage execData, ValidationStorage storage valData)
        internal
        view
        returns (HookConfig[] memory hooks)
    {
        // Load selector-assoc hooks first, then validation-assoc, because execution order is reversed
        // This next code segment is adapted from the function LinkedListSetLib.getAll.
        mapping(bytes32 => bytes32) storage llsMap = execData.executionHooks.map;
        uint256 size = 0;
        bytes32 cursor = llsMap[SENTINEL_VALUE];

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
            hooks := mload(0x40)
        }

        while (!LinkedListSetLib.isSentinel(cursor) && cursor != bytes32(0)) {
            unchecked {
                ++size;
            }
            // Place the item into the return array manually. Since the size was just incremented, it will point to
            // the next location to write to.
            assembly ("memory-safe") {
                mstore(add(hooks, mul(size, 0x20)), cursor)
            }

            cursor = llsMap[cursor];
        }

        // Load validation-assoc hooks
        uint256 validationAssocHooksLength = valData.executionHookCount;
        llsMap = valData.executionHooks.map;
        // Notably, we invert the mapping lookup ordering for validation-assoc hooks, because we know the length
        // ahead-of-time, thus saving an `sload`. This is why the cursor starts at SENTINEL_VALUE.
        cursor = SENTINEL_VALUE;

        for (uint256 i = 0; i < validationAssocHooksLength; ++i) {
            unchecked {
                ++size;
            }

            cursor = llsMap[cursor];

            assembly ("memory-safe") {
                mstore(add(hooks, mul(size, 0x20)), cursor)
            }
        }

        assembly ("memory-safe") {
            // Update the free memory pointer with the now-known length of the array.
            mstore(0x40, add(hooks, mul(add(size, 1), 0x20)))
            // Set the length of the array.
            mstore(hooks, size)
        }

        return hooks;
    }

    /// @notice Load execution hooks associated with an execution selector.
    /// @param execData The execution storage struct to load from.
    /// @return hooks An array of `HookConfig` items, representing the execution hooks.
    function loadExecHooks(ExecutionStorage storage execData) internal view returns (HookConfig[] memory) {
        HookConfig[] memory hooks;

        SetValue[] memory hooksSet = LinkedListSetLib.getAll(execData.executionHooks);

        // SetValue is internally a bytes31, and HookConfig is a bytes25, which are both left-aligned. This cast is
        // safe so long as only HookConfig entries are added to the set.
        assembly ("memory-safe") {
            hooks := hooksSet
        }

        return hooks;
    }

    /// @notice Load execution hooks associated with a validation function.
    /// @param valData The validation storage struct to load from.
    /// @return hooks An array of `HookConfig` items, representing the execution hooks.
    function loadExecHooks(ValidationStorage storage valData) internal view returns (HookConfig[] memory) {
        uint256 validationAssocHooksLength = valData.executionHookCount;

        return _loadValidationAssociatedHooks(validationAssocHooksLength, valData.executionHooks);
    }

    /// @notice Load validation hooks associated with a validation function.
    /// @param valData The validation storage struct to load from.
    /// @return hooks An array of `HookConfig` items, representing the validation hooks.
    function loadValidationHooks(ValidationStorage storage valData) internal view returns (HookConfig[] memory) {
        uint256 validationHookCount = valData.validationHookCount;

        return _loadValidationAssociatedHooks(validationHookCount, valData.validationHooks);
    }

    /// @notice Load all selectors that have been added to a validation function.
    /// @param valData The validation storage struct to load from.
    /// @return selectors An array of the selectors the validation function is allowed to validate.
    function loadSelectors(ValidationStorage storage valData) internal view returns (bytes4[] memory selectors) {
        SetValue[] memory selectorsSet = LinkedListSetLib.getAll(valData.selectors);

        // SetValue is internally a bytes31, and both bytes4 and bytes31 are left-aligned. This cast is safe so
        // long as only bytes4 entries are added to the set.
        assembly ("memory-safe") {
            selectors := selectorsSet
        }

        return selectors;
    }

    /// @notice Reverses an array of `HookConfig` items in place.
    function reverseArr(HookConfig[] memory hooks) internal pure {
        bytes32[] memory casted;

        // Cast to bytes32[] to use the shared reverseArr function
        assembly ("memory-safe") {
            casted := hooks
        }

        _reverseArr(casted);
    }

    /// @notice Reverses an array of `bytes4` items in place.
    function reverseArr(bytes4[] memory selectors) internal pure {
        bytes32[] memory casted;

        // Cast to bytes32[] to use the shared reverseArr function
        assembly ("memory-safe") {
            casted := selectors
        }

        _reverseArr(casted);
    }

    /// @notice If the callData is an encoded function call to IModularAccount.execute, retrieves the target of the
    /// call.
    /// @param callData The calldata to check.
    /// @return target The target of the call.
    function getExecuteTarget(bytes calldata callData) internal pure returns (address) {
        address target;

        assembly ("memory-safe") {
            target := and(calldataload(add(callData.offset, 4)), 0xffffffffffffffffffffffffffffffffffffffff)
        }

        return target;
    }

    /// @notice Captures a snapshot of the free memory pointer.
    /// @return The snapshot of the free memory pointer.
    function freezeFMP() internal pure returns (MemSnapshot) {
        MemSnapshot snapshot;

        assembly ("memory-safe") {
            snapshot := mload(0x40)
        }

        return snapshot;
    }

    /// @notice Restores the free memory pointer to a previous snapshot.
    /// @dev This invalidates any memory allocated since the snapshot was taken.
    /// @param snapshot The snapshot to restore to.
    function restoreFMP(MemSnapshot snapshot) internal pure {
        assembly ("memory-safe") {
            mstore(0x40, snapshot)
        }
    }

    /// @notice Used to load both pre validation hooks and pre execution hooks, associated with a validation
    /// function. The caller must first get the length of the hooks from the ValidationStorage struct.
    function _loadValidationAssociatedHooks(uint256 hookCount, LinkedListSet storage hooks)
        private
        view
        returns (HookConfig[] memory)
    {
        HookConfig[] memory hookArr = new HookConfig[](hookCount);

        mapping(bytes32 => bytes32) storage llsMap = hooks.map;
        bytes32 cursor = SENTINEL_VALUE;

        for (uint256 i = 0; i < hookCount; ++i) {
            cursor = llsMap[cursor];
            hookArr[i] = HookConfig.wrap(bytes25(cursor));
        }

        return hookArr;
    }

    function _reverseArr(bytes32[] memory hooks) private pure {
        uint256 len = hooks.length;
        uint256 halfLen = len / 2;

        for (uint256 i = 0; i < halfLen; ++i) {
            uint256 j = len - i - 1;

            (hooks[i], hooks[j]) = (hooks[j], hooks[i]);
        }
    }
}
