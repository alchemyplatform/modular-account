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

import {Vm} from "forge-std/Vm.sol";

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {
    ExecutionManifest,
    IExecutionModule,
    ManifestExecutionFunction,
    ManifestExecutionHook
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import {ModuleBase} from "../../../src/modules/ModuleBase.sol";

// Used within HookOrdering.t.sol, see that file for details on usage.
contract HookOrderCheckerModule is
    IValidationModule,
    IValidationHookModule,
    IExecutionModule,
    IExecutionHookModule,
    ModuleBase
{
    // Stored as a uint256 to make it easier to do the VM staticcall storage writes
    uint256[] public recordedFunctionCalls;

    function validateUserOp(uint32 entityId, PackedUserOperation calldata, bytes32) external returns (uint256) {
        recordedFunctionCalls.push(uint256(entityId));

        return 0;
    }

    function validateRuntime(address, uint32 entityId, address, uint256, bytes calldata, bytes calldata)
        external
    {
        recordedFunctionCalls.push(uint256(entityId));
    }

    function validateSignature(address, uint32 entityId, address, bytes32, bytes calldata)
        external
        view
        returns (bytes4)
    {
        // Use the VM cheat code to write to storage even in a view context
        _pushToRecordedFunctionCalls(entityId);
        return IERC1271.isValidSignature.selector;
    }

    function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata, bytes32)
        external
        returns (uint256)
    {
        recordedFunctionCalls.push(uint256(entityId));

        return 0;
    }

    function preRuntimeValidationHook(uint32 entityId, address, uint256, bytes calldata, bytes calldata)
        external
    {
        recordedFunctionCalls.push(uint256(entityId));
    }

    function preSignatureValidationHook(uint32 entityId, address, bytes32, bytes calldata) external view {
        // Use the VM cheat code to write to storage even in a view context
        _pushToRecordedFunctionCalls(entityId);
    }

    function preExecutionHook(uint32 entityId, address, uint256, bytes calldata) external returns (bytes memory) {
        recordedFunctionCalls.push(uint256(entityId));
        return "";
    }

    function postExecutionHook(uint32 entityId, bytes calldata) external {
        recordedFunctionCalls.push(uint256(entityId));
    }

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function foo(uint32 index) external {
        recordedFunctionCalls.push(index);
    }

    function getRecordedFunctionCalls() external view returns (uint256[] memory) {
        return recordedFunctionCalls;
    }

    function moduleId() external pure returns (string memory) {
        return "alchemy-test.hook-order-checker.v0.0.1";
    }

    // Does not return any execution hooks, the caller should add any requested execution hooks prior to calling
    // `installExecution` with the desired entity IDs.
    function executionManifest() external pure returns (ExecutionManifest memory) {
        ManifestExecutionFunction[] memory executionFunctions = new ManifestExecutionFunction[](1);
        executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: this.foo.selector,
            skipRuntimeValidation: false,
            allowGlobalValidation: false
        });

        return ExecutionManifest({
            executionFunctions: executionFunctions,
            executionHooks: new ManifestExecutionHook[](0),
            interfaceIds: new bytes4[](0)
        });
    }

    // Normally we can't write to storage within a staticcall, so the signature validation and signature validation
    // hooks would be unable to record their access order. However, we can use the VM cheat code to write to
    // storage even in a view context, so we can record the order of function calls.
    function _pushToRecordedFunctionCalls(uint32 entityId) internal view {
        uint256 arrayLength;
        uint256 arrayLengthSlot;
        uint256 contentsStartingSlot;

        assembly ("memory-safe") {
            arrayLengthSlot := recordedFunctionCalls.slot
            arrayLength := sload(arrayLengthSlot)
            mstore(0, arrayLengthSlot)
            contentsStartingSlot := keccak256(0, 32)
        }

        _store(bytes32(arrayLengthSlot), bytes32(arrayLength + 1));

        _store(bytes32(contentsStartingSlot + arrayLength), bytes32(uint256(entityId)));
    }

    function _store(bytes32 slot, bytes32 value) internal view {
        address vm = address(uint160(uint256(keccak256("hevm cheat code"))));

        (bool success,) = vm.staticcall(abi.encodeCall(Vm.store, (address(this), slot, value)));

        if (!success) {
            revert("VM Staticcall failed");
        }
    }
}
