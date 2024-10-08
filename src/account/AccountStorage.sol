// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {HookConfig, ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {LinkedListSet, SetValue} from "../libraries/LinkedListSetLib.sol";

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
    // Whether or not this validation can be used as a global validation function.
    bool isGlobal;
    // Whether or not this validation is allowed to validate ERC-1271 signatures.
    bool isSignatureValidation;
    // Whether or not this validation is allowed to validate ERC-4337 user operations.
    bool isUserOpValidation;
    // Length of the validation hooks for this validation function. The length is stored here, in the same storage
    // slot as the flags, to save an `sload` when putting the hooks into memory.
    uint8 validationHookCount;
    // Length of execution hooks for this validation function. The length is stored here, in the same storage slot
    // as the flags, to save an `sload` when putting the hooks into memory.
    uint8 executionHookCount;
    // The validation hooks for this validation function.
    LinkedListSet validationHooks;
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

function toSetValue(HookConfig hookConfig) pure returns (SetValue) {
    return SetValue.wrap(bytes30(HookConfig.unwrap(hookConfig)));
}

function toSetValue(bytes4 selector) pure returns (SetValue) {
    return SetValue.wrap(bytes30(selector));
}
