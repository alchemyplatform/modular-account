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

import {
    IPlugin,
    PluginManifest,
    ManifestExecutionHook,
    ManifestAssociatedFunction,
    ManifestAssociatedFunctionType,
    ManifestFunction
} from "modular-account-libs/interfaces/IPlugin.sol";
import {IPluginManager} from "modular-account-libs/interfaces/IPluginManager.sol";
import {IStandardExecutor, Call} from "modular-account-libs/interfaces/IStandardExecutor.sol";

import {MockPlugin} from "../../mocks/MockPlugin.sol";
import {AccountStateMutatingPlugin} from "../../mocks/plugins/AccountStateMutatingPlugin.sol";
import {AccountStatePhasesTest} from "./AccountStatePhases.t.sol";

// Tests the account state phase behavior when the source of the state modification happens during execution.
contract AccountStatePhasesUOValidationTest is AccountStatePhasesTest {
    // Test cases covered here
    // These are listed in the order they are run in the test suite.
    // The "source" indicates which in which phase the plugin will perform a modification, and the "target"
    // indicates which phase will change as a result of the modification.
    //
    // - Source: pre-Exec
    //     - Target: pre-UserOp-Validation
    //         - n/a - runs before
    //     - Target: UserOp-Validation
    //         - n/a - runs before
    //     - Target: pre-Runtime-Validation
    //         - n/a - runs before
    //     - Target: Runtime-Validation
    //         - n/a - runs before
    //     - Target: pre-Exec (same phase)
    //         - Addition (first element): *impossible*
    //         - Addition (not first): should *not* run
    //         - Removal: should still run
    //     - Target: Exec (same phase)
    //         - Replace: original should run
    //         - Removal: original should run
    //     - Target: post-Exec (same phase)
    //         - Addition (associated, first pre-exec): *impossible*
    //         - Addition (associated, non-first pre-exec): should *not* run
    //         - Removal (associated, first pre-exec): *impossible*
    //         - Removal (associated, non-first pre-exec): should still run
    //         - Addition (first post-only): should *not* run
    //         - Addition (non-first post-only): should *not* run
    //         - Removal (first post-only): should still run
    //         - Removal (non-first post-only): should still run
    // - Source: Exec
    //     - Target: pre-UserOp-Validation
    //         - n/a - runs before
    //     - Target: UserOp-Validation
    //         - n/a - runs before
    //     - Target: pre-Runtime-Validation
    //         - n/a - runs before
    //     - Target: Runtime-Validation
    //         - n/a - runs before
    //     - Target: pre-Exec (same phase)
    //         - n/a - runs before
    //     - Target: Exec (same phase)
    //         - Won’t test, since it’s the same single-element field.
    //     - Target: post-Exec (same phase)
    //         - Addition (associated, first pre-exec): should *not* run
    //         - Addition (associated, non-first pre-exec): should *not* run
    //         - Removal (associated, first pre-exec): should still run
    //         - Removal (associated, non-first pre-exec): should still run
    //         - Addition (first post-only): should *not* run
    //         - Addition (non-first post-only): should *not* run
    //         - Removal (first post-only): should still run
    //         - Removal (non-first post-only): should still run
    // - Source: post-Exec
    //     - Target: pre-UserOp-Validation
    //         - n/a - runs before
    //     - Target: UserOp-Validation
    //         - n/a - runs before
    //     - Target: pre-Runtime-Validation
    //         - n/a - runs before
    //     - Target: Runtime-Validation
    //         - n/a - runs before
    //     - Target: pre-Exec (same phase)
    //         - n/a - runs before
    //     - Target: Exec (same phase)
    //         - n/a - runs before
    //     - Target: post-Exec (same phase)
    //         - Addition (associated, first pre-exec): should *not* run
    //         - Addition (associated, non-first pre-exec): should *not* run
    //         - Removal (associated, first pre-exec): should still run
    //         - Removal (associated, non-first pre-exec): should still run
    //         - Addition (first post-only): should *not* run
    //         - Addition (non-first post-only): should *not* run
    //         - Removal (first post-only): should still run
    //         - Removal (non-first post-only): should still run

    // Source: pre-Exec
    // Target: pre-UserOp-Validation
    // n/a - runs before

    // Source: pre-Exec
    // Target: UserOp-Validation
    // n/a - runs before

    // Source: pre-Exec
    // Target: pre-Runtime-Validation
    // n/a - runs before

    // Source: pre-Exec
    // Target: Runtime-Validation
    // n/a - runs before

    // Source: pre-Exec
    // Target: pre-Exec (same phase)
    // Addition (first element): *impossible*

    function test_ASP_preExec_add_preExec_notFirstElement() public {
        // Source: pre-Exec
        // Target: pre-Exec (same phase)
        // Addition (not first): should *not* run

        // Set up the mock plugin with a pre-Exec hook, which will be added and should not run.
        _initMockPluginPreExecutionHook();

        // Install the ASM plugin with a pre exec hook that will add a pre exec hook.
        // It also needs a pre exec hook to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: true,
            setPostExec: false,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.PRE_EXECUTION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // both user op and runtime validation. This will trigger the ASM plugin's pre exec hook to install the
        // mock plugin's pre exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.preExecutionHook.selector),
            0 // Should be called 0 times
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preExec_remove_preExec() public {
        // Source: pre-Exec
        // Target: pre-Exec (same phase)
        // Removal: should still run

        // Set up the mock plugin with a pre-Exec hook, which will be removed and should still run.
        _initMockPluginPreExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a pre exec hook that will remove the mock plugin's pre exec hook.
        // It also needs a pre exec hook to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: true,
            setPostExec: false,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_EXECUTION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // both user op and runtime validation. This will trigger the ASM plugin's pre exec hook to remove the
        // mock plugin's pre exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock plugin's hook should still run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.preExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preExec_replace_exec() public {
        // Source: pre-Exec
        // Target: Exec (same phase)
        // Replace: original should run

        // Set up the mock plugin with an Exec function, which will replace the one defined by the ASM plugin
        // and should not be run.
        _initMockPluginExecFunction();

        // Install the ASM plugin with a pre exec hook that will replace the exec function.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: true,
            setPostExec: false,
            setRTValidation: false,
            setPreRTValidation: false
        });
        // Encode two self-calls: one to uninstall ASM plugin, one to install the mock plugin.
        Call[] memory calls = _generateCallsUninstallASMInstallMock();
        asmPlugin.setCallback(
            abi.encodeCall(IStandardExecutor.executeBatch, (calls)),
            AccountStateMutatingPlugin.FunctionId.PRE_EXECUTION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // both user op and runtime validation. This will trigger the ASM plugin's pre exec hook to replace the
        // exec function with the mock plugin's exec function. The original should run, not the replacement.
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(AccountStateMutatingPlugin.executionFunction.selector),
            1 // Should be called 1 time
        );
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(AccountStateMutatingPlugin.executionFunction.selector),
            0 // Should be called 0 times
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preExec_remove_exec() public {
        // Source: pre-Exec
        // Target: Exec (same phase)
        // Removal: original should run

        // Install the ASM plugin with a pre exec hook that will remove the exec function.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: true,
            setPostExec: false,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(asmPlugin), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_EXECUTION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // both user op and runtime validation. This will trigger the ASM plugin's pre exec hook to remove the
        // exec function. This NOT cause the call to revert, due to being in the same phase.
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(AccountStateMutatingPlugin.executionFunction.selector),
            1 // Should be called 1 time
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    // Source: pre-Exec
    // Target: post-Exec (same phase)
    // Addition (associated, first pre-exec): *impossible*

    function test_ASP_preExec_add_postExec_associated_notFirstElement() public {
        // Source: pre-Exec
        // Target: post-Exec (same phase)
        // Addition (associated, non-first pre-exec): should *not* run

        // Set up the mock plugin with an associated post-Exec hook, which will be added and should not run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the ASM plugin with a pre exec hook that will add a post exec hook.
        // It also needs a pre exec hook to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: true,
            setPostExec: false,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.PRE_EXECUTION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // both user op and runtime validation. This will trigger the ASM plugin's pre exec hook to install the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    // Source: pre-Exec
    // Target: post-Exec (same phase)
    // Removal (associated, first pre-exec): *impossible*

    function test_ASP_preExec_remove_postExec_associated_notFirstElement() public {
        // Source: pre-Exec
        // Target: post-Exec (same phase)
        // Removal (associated, non-first pre-exec): should still run

        // Set up the mock plugin with an associated post-Exec hook, which will be removed and should still run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a pre exec hook that will remove the mock plugin's post exec hook.
        // It also needs a pre exec hook to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: true,
            setPostExec: false,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_EXECUTION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // both user op and runtime validation. This will trigger the ASM plugin's pre exec hook to remove the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock plugin's hook should still run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preExec_add_postExec_firstElement() public {
        // Source: pre-Exec
        // Target: post-Exec (same phase)
        // Addition (first post-only): should *not* run

        // Set up the mock plugin with a post-Exec hook, which will be added and should not run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the ASM plugin with a pre exec hook that will add a post exec hook.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: true,
            setPostExec: false,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.PRE_EXECUTION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // both user op and runtime validation. This will trigger the ASM plugin's pre exec hook to install the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preExec_add_postExec_notFirstElement() public {
        // Source: pre-Exec
        // Target: post-Exec (same phase)
        // Addition (non-first post-only): should *not* run

        // Set up the mock plugin with a post-Exec hook, which will be added and should not run.
        _initMockPluginPostOnlyExecutionHook();

        // Since the ASM plugin can't define a post-only hook due to using a pre exec hook for its action, we
        // need to add another mock plugin to add the first post-only exec hook, in order to test this case.

        PluginManifest memory m2;
        m2.executionHooks = new ManifestExecutionHook[](1);
        m2.executionHooks[0] = ManifestExecutionHook({
            executionSelector: AccountStateMutatingPlugin.executionFunction.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.NONE,
                functionId: 0, // Unused
                dependencyIndex: 0 // Unused
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0 // Unused
            })
        });
        bytes32 manifestHash2 = _manifestHashOf(m2);
        MockPlugin mockPlugin2 = new MockPlugin(m2);

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onInstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(address(mockPlugin2), manifestHash2, _EMPTY_DEPENDENCIES);
        vm.prank(owner1);
        account1.installPlugin(address(mockPlugin2), manifestHash2, "", _EMPTY_DEPENDENCIES);

        // Install the ASM plugin with a pre exec hook that will add a post exec hook.
        // It also needs a post-only exec hook to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: true,
            setPostExec: true,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.PRE_EXECUTION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // both user op and runtime validation. This will trigger the ASM plugin's pre exec hook to install the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        vm.expectCall(
            address(mockPlugin2),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preExec_remove_postExec_firstElement() public {
        // Source: pre-Exec
        // Target: post-Exec (same phase)
        // Removal (first post-only): should still run

        // Set up the mock plugin with a post-Exec hook, which will be removed and should still run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a pre exec hook that will remove the mock plugin's post exec hook.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: true,
            setPostExec: false,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_EXECUTION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // both user op and runtime validation. This will trigger the ASM plugin's pre exec hook to remove the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock plugin's hook should still run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preExec_remove_postExec_notFirstElement() public {
        // Source: pre-Exec
        // Target: post-Exec (same phase)
        // Removal (non-first post-only): should still run

        // Since the ASM plugin can't define a post-only hook due to using a pre exec hook for its action, we
        // need to add another mock plugin to add the first post-only exec hook, in order to test this case.

        PluginManifest memory m2;
        m2.executionHooks = new ManifestExecutionHook[](1);
        m2.executionHooks[0] = ManifestExecutionHook({
            executionSelector: AccountStateMutatingPlugin.executionFunction.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.NONE,
                functionId: 0, // Unused
                dependencyIndex: 0 // Unused
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0 // Unused
            })
        });
        bytes32 manifestHash2 = _manifestHashOf(m2);
        MockPlugin mockPlugin2 = new MockPlugin(m2);

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onInstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(address(mockPlugin2), manifestHash2, _EMPTY_DEPENDENCIES);
        vm.prank(owner1);
        account1.installPlugin(address(mockPlugin2), manifestHash2, "", _EMPTY_DEPENDENCIES);

        // Set up the mock plugin with a post-Exec hook, which will be removed and should still run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a pre exec hook that will remove the mock plugin's post exec hook.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: true,
            setPostExec: false,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_EXECUTION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // both user op and runtime validation. This will trigger the ASM plugin's pre exec hook to remove the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock plugin's hook should still run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.expectCall(
            address(mockPlugin2),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    // Source: Exec
    // Target: pre-UserOp-Validation
    // n/a - runs before

    // Source: Exec
    // Target: UserOp-Validation
    // n/a - runs before

    // Source: Exec
    // Target: pre-Runtime-Validation
    // n/a - runs before

    // Source: Exec
    // Target: Runtime-Validation
    // n/a - runs before

    // Source: Exec
    // Target: pre-Exec (same phase)
    // n/a - runs before

    // Source: Exec
    // Target: Exec (same phase)
    // Won’t test, since it’s the same single-element field.

    function test_ASP_exec_add_postExec_associated_firstElement() public {
        // Source: Exec
        // Target: post-Exec (same phase)
        // Addition (associated, first pre-exec): should *not* run

        // Set up the mock plugin with an associated post-Exec hook, which will be added and should not run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the ASM plugin with an exec function that will add a post exec hook.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: false,
            setPostExec: false,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.EXECUTION_FUNCTION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // user op and runtime validation. This will trigger the ASM plugin's exec function to install the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_exec_add_postExec_associated_notFirstElement() public {
        // Source: Exec
        // Target: post-Exec (same phase)
        // Addition (associated, non-first pre-exec): should *not* run

        // Set up the mock plugin with an associated post-Exec hook, which will be added and should not run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the ASM plugin with an exec function that will add a post exec hook.
        // It also needs a post exec hook to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: true,
            setPostExec: true,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.EXECUTION_FUNCTION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // user op and runtime validation. This will trigger the ASM plugin's exec function to install the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_exec_remove_postExec_associated_firstElement() public {
        // Source: Exec
        // Target: post-Exec (same phase)
        // Removal (associated, first pre-exec): should still run

        // Set up the mock plugin with an associated post-Exec hook, which will be removed and should still run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with an exec function that will remove the mock plugin's post exec hook.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: false,
            setPostExec: false,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.EXECUTION_FUNCTION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // user op and runtime validation. This will trigger the ASM plugin's exec function to remove the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock plugin's hook should still run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_exec_remove_postExec_associated_notFirstElement() public {
        // Source: Exec
        // Target: post-Exec (same phase)
        // Removal (associated, non-first pre-exec): should still run

        // Set up the mock plugin with an associated post-Exec hook, which will be removed and should still run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with an exec function that will remove the mock plugin's post exec hook.
        // It also needs an associated post exec hook to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: true,
            setPostExec: true,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.EXECUTION_FUNCTION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // user op and runtime validation. This will trigger the ASM plugin's exec function to remove the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock plugin's hook should still run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_exec_add_postExec_firstElement() public {
        // Source: Exec
        // Target: post-Exec (same phase)
        // Addition (first post-only): should *not* run

        // Set up the mock plugin with a post-Exec hook, which will be added and should not run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the ASM plugin with an exec function that will add a post exec hook.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: false,
            setPostExec: false,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.EXECUTION_FUNCTION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // user op and runtime validation. This will trigger the ASM plugin's exec function to install the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_exec_add_postExec_notFirstElement() public {
        // Source: Exec
        // Target: post-Exec (same phase)
        // Addition (non-first post-only): should *not* run

        // Set up the mock plugin with a post-Exec hook, which will be added and should not run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the ASM plugin with an exec function that will add a post exec hook.
        // It also needs a post exec hook to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: false,
            setPostExec: true,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.EXECUTION_FUNCTION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // user op and runtime validation. This will trigger the ASM plugin's exec function to install the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_exec_remove_postExec_firstElement() public {
        // Source: Exec
        // Target: post-Exec (same phase)
        // Removal (first post-only): should still run

        // Set up the mock plugin with a post-Exec hook, which will be removed and should still run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with an exec function that will remove the mock plugin's post exec hook.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: false,
            setPostExec: false,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.EXECUTION_FUNCTION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // user op and runtime validation. This will trigger the ASM plugin's exec function to remove the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock plugin's hook should still run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_exec_remove_postExec_notFirstElement() public {
        // Source: Exec
        // Target: post-Exec (same phase)
        // Removal (non-first post-only): should still run

        // Set up the mock plugin with a post-Exec hook, which will be removed and should still run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with an exec function that will remove the mock plugin's post exec hook.
        // It also needs a post exec hook to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: false,
            setPostExec: true,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.EXECUTION_FUNCTION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // user op and runtime validation. This will trigger the ASM plugin's exec function to remove the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock plugin's hook should still run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    // Source: post-Exec
    // Target: pre-UserOp-Validation
    // n/a - runs before

    // Source: post-Exec
    // Target: UserOp-Validation
    // n/a - runs before

    // Source: post-Exec
    // Target: pre-Runtime-Validation
    // n/a - runs before

    // Source: post-Exec
    // Target: Runtime-Validation
    // n/a - runs before

    // Source: post-Exec
    // Target: pre-Exec
    // n/a - runs before

    // Source: post-Exec
    // Target: Exec
    // n/a - runs before

    // Source: post-Exec
    // Target: post-Exec (same phase)
    // Addition (associated, first pre-exec): impossible with the current order of running post-only exec hooks
    // after associated post hooks.

    function test_ASP_postExec_add_postExec_associated_notFirstElement() public {
        // Source: post-Exec
        // Target: post-Exec (same phase)
        // Addition (associated, non-first pre-exec): should *not* run

        // Set up the mock plugin with an associated post-Exec hook, which will be added and should not run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the ASM plugin with a post exec hook that will add a post exec hook.
        // To ensure the ASM plugin's post exec hook runs first, it needs to be associated, so we also define an
        // empty pre-exec hook.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: true,
            setPostExec: true,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.POST_EXECUTION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // user op and runtime validation. This will trigger the ASM plugin's post exec hook to install the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock plugin's hook should not run.
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    // Source: post-Exec
    // Target: post-Exec (same phase)
    // Removal (associated, first pre-exec): impossible with the current order of running post-only exec hooks
    // after associated post hooks.

    function test_ASP_postExec_remove_postExec_associated_notFirstElement() public {
        // Source: post-Exec
        // Target: post-Exec (same phase)
        // Removal (associated, non-first pre-exec): should still run

        // Set up the mock plugin with an associated post-Exec hook, which will be removed and should still run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a post exec hook that will remove the mock plugin's post exec hook.
        // To ensure the ASM plugin's post exec hook runs first, it needs to be associated, so we also define an
        // empty pre-exec hook. This also ensures it is not the first post exec hook.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: true,
            setPostExec: true,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.POST_EXECUTION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // user op and runtime validation. This will trigger the ASM plugin's post exec hook to remove the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // ASM plugin's hook should still run.
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_postExec_add_postExec_firstElement() public {
        // Source: post-Exec
        // Target: post-Exec (same phase)
        // Addition (first post-only): should *not* run

        // Set up the mock plugin with a post-Exec hook, which will be added and should not run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the ASM plugin with a post exec hook that will add a post exec hook.
        // To ensure the ASM plugin's post exec hook runs first, it needs to be associated, so we also define an
        // empty pre-exec hook.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: true,
            setPostExec: true,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.POST_EXECUTION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // user op and runtime validation. This will trigger the ASM plugin's post exec hook to install the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // ASM plugin's hook should not run.
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_postExec_add_postExec_notFirstElement() public {
        // Source: post-Exec
        // Target: post-Exec (same phase)
        // Addition (non-first post-only): should *not* run

        // Set up the mock plugin with a post-Exec hook, which will be added and should not run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the ASM plugin with a post exec hook that will add a post exec hook.
        // This will be a post-only hook.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: false,
            setPostExec: true,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.POST_EXECUTION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // user op and runtime validation. This will trigger the ASM plugin's post exec hook to install the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // ASM plugin's hook should not run.
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_postExec_remove_postExec_firstElement() public {
        // Source: post-Exec
        // Target: post-Exec (same phase)
        // Removal (first post-only): should still run

        // Set up the mock plugin with a post-Exec hook, which will be removed and should still run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a post exec hook that will remove the mock plugin's post exec hook.
        // To ensure the ASM plugin's post exec hook runs first, it needs to be associated, so we also define an
        // empty pre-exec hook. This also ensures it is not the first post exec hook.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: true,
            setPostExec: true,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.POST_EXECUTION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // user op and runtime validation. This will trigger the ASM plugin's post exec hook to remove the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // ASM plugin's hook should still run.
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_postExec_remove_postExec_notFirstElement() public {
        // Source: post-Exec
        // Target: post-Exec (same phase)
        // Removal (non-first post-only): should still run

        // Set up the mock plugin with a post-Exec hook, which will be removed and should still run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a post exec hook that will remove the mock plugin's post exec hook.
        // This will be a post-only hook.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setPreExec: false,
            setPostExec: true,
            setRTValidation: false,
            setPreRTValidation: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.POST_EXECUTION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account by mocking a call from the EntryPoint, bypassing
        // user op and runtime validation. This will trigger the ASM plugin's post exec hook to remove the
        // mock plugin's post exec hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock plugin's hook should still run.
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(address(entryPoint));
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }
}
