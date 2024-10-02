// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {
    LinkedListSet,
    LinkedListSetLib,
    SetValue
} from "@erc6900/modular-account-libs/libraries/LinkedListSetLib.sol";

import {HookConfig, ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {ValidationLocator} from "../libraries/ValidationLocatorLib.sol";

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
    LinkedListSet executionHooks;
}

struct ValidationData {
    address module;
    // Whether or not this validation can be used as a global validation function.
    bool isGlobal;
    // Whether or not this validation is allowed to validate ERC-1271 signatures.
    bool isSignatureValidation;
    // Whether or not this validation is allowed to validate ERC-4337 user operations.
    bool isUserOpValidation;
    // The pre validation hooks for this validation function.
    ModuleEntity[] preValidationHooks;
    // Execution hooks to run with this validation function.
    LinkedListSet executionHooks;
    // The set of selectors that may be validated by this validation function.
    LinkedListSet selectors;
}

struct AccountStorage {
    // AccountStorageInitializable variables
    uint8 initialized;
    bool initializing;
    // Execution functions and their associated functions
    mapping(bytes4 selector => ExecutionData) executionData;
    mapping(ValidationLocator => ValidationData) validationData;
    // For ERC165 introspection
    mapping(bytes4 => uint256) supportedIfaces;
    mapping(uint256 => bool) deferredInstallNonceUsed;
    uint32 validationIdsUsed;
}

function getAccountStorage() pure returns (AccountStorage storage _storage) {
    assembly ("memory-safe") {
        _storage.slot := _ACCOUNT_STORAGE_SLOT
    }
}

function toSetValue(HookConfig hookConfig) pure returns (SetValue) {
    return SetValue.wrap(bytes30(HookConfig.unwrap(hookConfig)));
}

function toSetValue(bytes4 selector) pure returns (SetValue) {
    return SetValue.wrap(bytes30(selector));
}

function toHookConfigArray(LinkedListSet storage set) view returns (HookConfig[] memory) {
    SetValue[] memory values = LinkedListSetLib.getAll(set);
    HookConfig[] memory result;

    // SetValue is internally a bytes30, and HookConfig is a bytes25, which are both left-aligned. This cast is
    // safe so long as only HookConfig entries are added to the set.
    assembly ("memory-safe") {
        result := values
    }

    return result;
}
