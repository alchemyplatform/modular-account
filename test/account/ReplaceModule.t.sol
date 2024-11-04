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

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {
    ExecutionManifest,
    ManifestExecutionFunction,
    ManifestExecutionHook
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {
    Call, IModularAccount, ModuleEntity
} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {SingleSignerValidationModule} from "../../src/modules/validation/SingleSignerValidationModule.sol";

import {MockModule} from "../mocks/modules/MockModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

interface TestModule {
    function testFunction() external;
}

contract UpgradeModuleTest is AccountTestBase {
    address public target = address(1000);
    uint256 public sendAmount = 1 ether;
    uint32 public entityId = 10;

    // From MockModule
    event ReceivedCall(bytes msgData, uint256 msgValue);

    function setUp() public override {
        _revertSnapshot = vm.snapshotState();
    }

    function test_upgradeModuleExecutionFunction() public withSMATest {
        ExecutionManifest memory m;
        ManifestExecutionFunction[] memory executionFunctions = new ManifestExecutionFunction[](1);
        executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: TestModule.testFunction.selector,
            skipRuntimeValidation: true,
            allowGlobalValidation: true
        });
        m.executionFunctions = executionFunctions;
        ManifestExecutionHook[] memory executionHooks = new ManifestExecutionHook[](1);
        executionHooks[0] = ManifestExecutionHook({
            executionSelector: TestModule.testFunction.selector,
            entityId: entityId,
            isPreHook: true,
            isPostHook: true
        });
        m.executionHooks = executionHooks;

        MockModule moduleV1 = new MockModule(m);
        MockModule moduleV2 = new MockModule(m);
        vm.startPrank(address(entryPoint));
        account1.installExecution(address(moduleV1), moduleV1.executionManifest(), "");

        // test installed
        vm.expectEmit(true, true, true, true);
        bytes memory callData = abi.encodePacked(TestModule.testFunction.selector);
        emit ReceivedCall(
            abi.encodeCall(IExecutionHookModule.preExecutionHook, (entityId, address(entryPoint), 0, callData)), 0
        );
        emit ReceivedCall(callData, 0);
        TestModule(address(account1)).testFunction();

        // upgrade module by batching uninstall + install calls
        vm.startPrank(owner1);
        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(account1),
            value: 0,
            data: abi.encodeCall(
                IModularAccount.uninstallExecution, (address(moduleV1), moduleV1.executionManifest(), "")
            )
        });
        calls[1] = Call({
            target: address(account1),
            value: 0,
            data: abi.encodeCall(
                IModularAccount.installExecution, (address(moduleV2), moduleV2.executionManifest(), "")
            )
        });
        account1.executeWithRuntimeValidation(
            abi.encodeCall(account1.executeBatch, (calls)),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
        );

        // test installed, test if old module still installed
        assertEq(account1.getExecutionData((TestModule.testFunction.selector)).module, address(moduleV2));
        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(
            abi.encodeCall(IExecutionHookModule.preExecutionHook, (entityId, address(owner1), 0, callData)), 0
        );
        emit ReceivedCall(abi.encodePacked(TestModule.testFunction.selector), 0);
        TestModule(address(account1)).testFunction();
    }

    function test_upgradeModuleValidationFunction() public withSMATest {
        // Setup new validaiton with pre validation and execution hooks associated with a validator
        SingleSignerValidationModule validation1 = new SingleSignerValidationModule();
        SingleSignerValidationModule validation2 = new SingleSignerValidationModule();
        uint32 validationEntityId1 = 10;
        uint32 validationEntityId2 = 11;

        MockModule mockPreValAndPermissionsModule = new MockModule(
            ExecutionManifest({
                executionFunctions: new ManifestExecutionFunction[](0),
                executionHooks: new ManifestExecutionHook[](0),
                interfaceIds: new bytes4[](0)
            })
        );

        ModuleEntity currModuleEntity = ModuleEntityLib.pack(address(validation1), validationEntityId1);
        ModuleEntity newModuleEntity = ModuleEntityLib.pack(address(validation2), validationEntityId2);

        bytes[] memory hooksForVal1 = new bytes[](2);
        hooksForVal1[0] = abi.encodePacked(
            HookConfigLib.packValidationHook(address(mockPreValAndPermissionsModule), validationEntityId1)
        );
        hooksForVal1[1] = abi.encodePacked(
            HookConfigLib.packExecHook(address(mockPreValAndPermissionsModule), validationEntityId1, true, true)
        );

        vm.prank(address(entryPoint));
        account1.installValidation(
            ValidationConfigLib.pack(currModuleEntity, true, false, true),
            new bytes4[](0),
            abi.encode(validationEntityId1, owner1),
            hooksForVal1
        );
        // Test that setup worked. Pre val + pre exec hooks should run
        vm.startPrank(owner1);
        bytes memory callData = abi.encodeCall(IModularAccount.execute, (address(target), sendAmount, ""));
        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(
            abi.encodeCall(
                IValidationHookModule.preRuntimeValidationHook,
                (validationEntityId1, address(owner1), 0, callData, "")
            ),
            0
        );
        emit ReceivedCall(
            abi.encodeCall(
                IExecutionHookModule.preExecutionHook, (validationEntityId1, address(owner1), 0, callData)
            ),
            0
        );
        account1.executeWithRuntimeValidation(callData, _encodeSignature(currModuleEntity, GLOBAL_VALIDATION, ""));
        assertEq(target.balance, sendAmount);

        // upgrade module by batching uninstall + install calls
        bytes[] memory hooksForVal2 = new bytes[](2);
        hooksForVal2[0] = abi.encodePacked(
            HookConfigLib.packValidationHook(address(mockPreValAndPermissionsModule), validationEntityId2)
        );
        hooksForVal2[1] = abi.encodePacked(
            HookConfigLib.packExecHook(address(mockPreValAndPermissionsModule), validationEntityId2, true, true)
        );

        bytes[] memory emptyBytesArr = new bytes[](0);
        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(account1),
            value: 0,
            data: abi.encodeCall(
                IModularAccount.uninstallValidation, (currModuleEntity, abi.encode(validationEntityId1), emptyBytesArr)
            )
        });
        calls[1] = Call({
            target: address(account1),
            value: 0,
            data: abi.encodeCall(
                IModularAccount.installValidation,
                (
                    ValidationConfigLib.pack(newModuleEntity, true, false, true),
                    new bytes4[](0),
                    abi.encode(validationEntityId2, owner1),
                    hooksForVal2
                )
            )
        });
        account1.executeWithRuntimeValidation(
            abi.encodeCall(account1.executeBatch, (calls)),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
        );

        // Test if old validation still works, expect fail
        vm.expectRevert(
            abi.encodePacked(
                ModularAccountBase.ValidationFunctionMissing.selector, abi.encode(IModularAccount.execute.selector)
            )
        );
        account1.executeWithRuntimeValidation(
            abi.encodeCall(IModularAccount.execute, (target, sendAmount, "")),
            _encodeSignature(currModuleEntity, GLOBAL_VALIDATION, "")
        );

        // Test if new validation works
        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(
            abi.encodeCall(
                IValidationHookModule.preRuntimeValidationHook,
                (validationEntityId2, address(owner1), 0, callData, "")
            ),
            0
        );
        emit ReceivedCall(
            abi.encodeCall(
                IExecutionHookModule.preExecutionHook, (validationEntityId2, address(entryPoint), 0, callData)
            ),
            0
        );
        account1.executeWithRuntimeValidation(callData, _encodeSignature(newModuleEntity, GLOBAL_VALIDATION, ""));
        assertEq(target.balance, 2 * sendAmount);
        vm.stopPrank();
    }
}
