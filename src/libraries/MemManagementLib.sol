// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {HookConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {ExecutionData, ValidationData} from "../account/AccountStorage.sol";
import {LinkedListSet, LinkedListSetLib, SENTINEL_VALUE, SetValue} from "./LinkedListSetLib.sol";

library MemManagementLib {
    function loadExecHooks(ExecutionData storage execData, ValidationData storage valData)
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

    function loadExecHooks(ExecutionData storage execData) internal view returns (HookConfig[] memory) {
        HookConfig[] memory hooks;

        SetValue[] memory hooksSet = LinkedListSetLib.getAll(execData.executionHooks);

        // SetValue is internally a bytes30, and HookConfig is a bytes25, which are both left-aligned. This cast is
        // safe so long as only HookConfig entries are added to the set.
        assembly ("memory-safe") {
            hooks := hooksSet
        }

        return hooks;
    }

    function loadExecHooks(ValidationData storage valData) internal view returns (HookConfig[] memory) {
        uint256 validationAssocHooksLength = valData.executionHookCount;

        return _loadValidationAssociatedHooks(validationAssocHooksLength, valData.executionHooks);
    }

    function loadValidationHooks(ValidationData storage valData) internal view returns (HookConfig[] memory) {
        uint256 validationHookCount = valData.validationHookCount;

        return _loadValidationAssociatedHooks(validationHookCount, valData.validationHooks);
    }

    function loadSelectors(ValidationData storage valData) internal view returns (bytes4[] memory selectors) {
        SetValue[] memory selectorsSet = LinkedListSetLib.getAll(valData.selectors);

        // SetValue is internally a bytes30, and both bytes4 and bytes30 are left-aligned. This cast is safe so
        // long as only bytes4 entries are added to the set.
        assembly ("memory-safe") {
            selectors := selectorsSet
        }

        return selectors;
    }

    function reverseArr(HookConfig[] memory hooks) internal pure {
        bytes32[] memory casted;

        // Cast to bytes32[] to use the shared reverseArr function
        assembly ("memory-safe") {
            casted := hooks
        }

        _reverseArr(casted);
    }

    function reverseArr(bytes4[] memory selectors) internal pure {
        bytes32[] memory casted;

        // Cast to bytes32[] to use the shared reverseArr function
        assembly ("memory-safe") {
            casted := selectors
        }

        _reverseArr(casted);
    }

    // If the callData is an encoded function call to IModularAccount.execute, retrieves the target of the call.
    function getExecuteTarget(bytes calldata callData) internal pure returns (address) {
        address target;

        assembly ("memory-safe") {
            target := and(calldataload(add(callData.offset, 4)), 0xffffffffffffffffffffffffffffffffffffffff)
        }

        return target;
    }

    // Used to load both pre-validation hooks and pre-execution hooks, associated with a validation function.
    // The caller must first get the length of the hooks from the ValidationData struct.
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
