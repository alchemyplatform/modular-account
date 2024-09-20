// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {HookConfig, ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

// bytes = keccak256("ERC6900.ModularAccount.Storage")
bytes32 constant _ACCOUNT_STORAGE_SLOT = 0xc531f081ecdb5a90f38c197521797881a6e5c752a7d451780f325a95f8b91f45;

// Represents data associated with a specifc function selector.
struct ExecutionData {
    // The module that implements this execution function.
    // If this is a native function, the address must remain address(0).
    address module;
    // Whether or not the function needs runtime validation, or can be called by anyone. The function can still be
    // state changing if this flag is set to true.
    // Note that even if this is set to true, user op validation will still be required, otherwise anyone could
    // drain the account of native tokens by wasting gas.
    bool skipRuntimeValidation;
    // Whether or not a global validation function may be used to validate this function.
    bool allowGlobalValidation;
    // The execution hooks for this function selector.
    EnumerableSet.Bytes32Set executionHooks;
}

struct ValidationData {
    // Whether or not this validation can be used as a global validation function.
    bool isGlobal;
    // Whether or not this validation is allowed to validate ERC-1271 signatures.
    bool isSignatureValidation;
    // Whether or not this validation is allowed to validate ERC-4337 user operations.
    bool isUserOpValidation;
    // The pre validation hooks for this validation function.
    ModuleEntity[] preValidationHooks;
    // Execution hooks to run with this validation function.
    EnumerableSet.Bytes32Set executionHooks;
    // The set of selectors that may be validated by this validation function.
    EnumerableSet.Bytes32Set selectors;
}

struct AccountStorage {
    // AccountStorageInitializable variables
    uint8 initialized;
    bool initializing;
    // Execution functions and their associated functions
    mapping(bytes4 selector => ExecutionData) executionData;
    mapping(ModuleEntity validationFunction => ValidationData) validationData;
    // For ERC165 introspection
    mapping(bytes4 => uint256) supportedIfaces;
    mapping(uint256 => bool) deferredInstallNonceUsed;
}

function getAccountStorage() pure returns (AccountStorage storage _storage) {
    assembly ("memory-safe") {
        _storage.slot := _ACCOUNT_STORAGE_SLOT
    }
}

using EnumerableSet for EnumerableSet.Bytes32Set;

function toSetValue(ModuleEntity moduleEntity) pure returns (bytes32) {
    return bytes32(ModuleEntity.unwrap(moduleEntity));
}

function toModuleEntity(bytes32 setValue) pure returns (ModuleEntity) {
    return ModuleEntity.wrap(bytes24(setValue));
}

// ExecutionHook layout:
// 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF______________________ Hook Module Entity
// 0x________________________________________________AA____________________ is pre hook
// 0x__________________________________________________BB__________________ is post hook

function toSetValue(HookConfig hookConfig) pure returns (bytes32) {
    return bytes32(HookConfig.unwrap(hookConfig));
}

function toHookConfig(bytes32 setValue) pure returns (HookConfig) {
    return HookConfig.wrap(bytes25(setValue));
}

function toSetValue(bytes4 selector) pure returns (bytes32) {
    return bytes32(selector);
}

function toSelector(bytes32 setValue) pure returns (bytes4) {
    return bytes4(setValue);
}

/// @dev Helper function to get all elements of a set into memory.
function toModuleEntityArray(EnumerableSet.Bytes32Set storage set) view returns (ModuleEntity[] memory) {
    uint256 length = set.length();
    ModuleEntity[] memory result = new ModuleEntity[](length);
    for (uint256 i = 0; i < length; ++i) {
        bytes32 key = set.at(i);
        result[i] = ModuleEntity.wrap(bytes24(key));
    }
    return result;
}
