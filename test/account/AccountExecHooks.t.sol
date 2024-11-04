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
    IModule,
    ManifestExecutionFunction,
    ManifestExecutionHook
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";

import {MockModule} from "../mocks/modules/MockModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract AccountExecHooksTest is AccountTestBase {
    MockModule public mockModule1;

    bytes4 internal constant _EXEC_SELECTOR = bytes4(uint32(1));
    uint32 internal constant _PRE_HOOK_ENTITY_ID_1 = 1;
    uint32 internal constant _POST_HOOK_ENTITY_ID_2 = 2;
    uint32 internal constant _BOTH_HOOKS_ENTITY_ID_3 = 3;

    ExecutionManifest internal _m1;

    event ExecutionInstalled(address indexed module, ExecutionManifest manifest);
    event ExecutionUninstalled(address indexed module, bool onUninstallSucceeded, ExecutionManifest manifest);
    // emitted by MockModule
    event ReceivedCall(bytes msgData, uint256 msgValue);

    function setUp() public override {
        _revertSnapshot = vm.snapshotState();
        _allowTestDirectCalls();

        _m1.executionFunctions.push(
            ManifestExecutionFunction({
                executionSelector: _EXEC_SELECTOR,
                skipRuntimeValidation: true,
                allowGlobalValidation: false
            })
        );
    }

    function test_preExecHook_install() public withSMATest {
        _installExecution1WithHooks(
            ManifestExecutionHook({
                executionSelector: _EXEC_SELECTOR,
                entityId: _PRE_HOOK_ENTITY_ID_1,
                isPreHook: true,
                isPostHook: false
            })
        );
    }

    /// @dev Module 1 hook pair: [1, null]
    ///      Expected execution: [1, null]
    function test_preExecHook_run() public withSMATest {
        test_preExecHook_install();

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(
            abi.encodeWithSelector(
                IExecutionHookModule.preExecutionHook.selector,
                _PRE_HOOK_ENTITY_ID_1,
                address(this), // caller
                uint256(0), // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            0 // msg value in call to module
        );

        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);
    }

    function test_preExecHook_uninstall() public withSMATest {
        test_preExecHook_install();

        _uninstallExecution(mockModule1);
    }

    function test_execHookPair_install() public withSMATest {
        _installExecution1WithHooks(
            ManifestExecutionHook({
                executionSelector: _EXEC_SELECTOR,
                entityId: _BOTH_HOOKS_ENTITY_ID_3,
                isPreHook: true,
                isPostHook: true
            })
        );
    }

    /// @dev Module 1 hook pair: [1, 2]
    ///      Expected execution: [1, 2]
    function test_execHookPair_run() public withSMATest {
        test_execHookPair_install();

        vm.expectEmit(true, true, true, true);
        // pre hook call
        emit ReceivedCall(
            abi.encodeWithSelector(
                IExecutionHookModule.preExecutionHook.selector,
                _BOTH_HOOKS_ENTITY_ID_3,
                address(this), // caller
                uint256(0), // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            0 // msg value in call to module
        );
        vm.expectEmit(true, true, true, true);
        // exec call
        emit ReceivedCall(abi.encodePacked(_EXEC_SELECTOR), 0);
        vm.expectEmit(true, true, true, true);
        // post hook call
        emit ReceivedCall(
            abi.encodeCall(IExecutionHookModule.postExecutionHook, (_BOTH_HOOKS_ENTITY_ID_3, "")),
            0 // msg value in call to module
        );

        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);
    }

    function test_execHookPair_uninstall() public withSMATest {
        test_execHookPair_install();

        _uninstallExecution(mockModule1);
    }

    function test_postOnlyExecHook_install() public withSMATest {
        _installExecution1WithHooks(
            ManifestExecutionHook({
                executionSelector: _EXEC_SELECTOR,
                entityId: _POST_HOOK_ENTITY_ID_2,
                isPreHook: false,
                isPostHook: true
            })
        );
    }

    /// @dev Module 1 hook pair: [null, 2]
    ///      Expected execution: [null, 2]
    function test_postOnlyExecHook_run() public withSMATest {
        test_postOnlyExecHook_install();

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(
            abi.encodeCall(IExecutionHookModule.postExecutionHook, (_POST_HOOK_ENTITY_ID_2, "")),
            0 // msg value in call to module
        );

        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);
    }

    function test_postOnlyExecHook_uninstall() public withSMATest {
        test_postOnlyExecHook_install();

        _uninstallExecution(mockModule1);
    }

    function _installExecution1WithHooks(ManifestExecutionHook memory execHooks) internal {
        _m1.executionHooks.push(execHooks);
        mockModule1 = new MockModule(_m1);

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IModule.onInstall, (bytes("a"))), 0);
        vm.expectEmit(true, true, true, true);
        emit ExecutionInstalled(address(mockModule1), _m1);

        // vm.startPrank(owner1);
        account1.installExecution({
            module: address(mockModule1),
            manifest: mockModule1.executionManifest(),
            moduleInstallData: bytes("a")
        });
        // vm.stopPrank();
    }

    function _uninstallExecution(MockModule module) internal {
        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IModule.onUninstall, (bytes("b"))), 0);
        vm.expectEmit(true, true, true, true);
        emit ExecutionUninstalled(address(module), true, module.executionManifest());

        account1.uninstallExecution(address(module), module.executionManifest(), bytes("b"));
    }
}
