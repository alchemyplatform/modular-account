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

import {IPlugin} from "modular-account-libs/interfaces/IPlugin.sol";
import {IPluginManager} from "modular-account-libs/interfaces/IPluginManager.sol";
import {IStandardExecutor, Call} from "modular-account-libs/interfaces/IStandardExecutor.sol";

import {UpgradeableModularAccount} from "../../../src/account/UpgradeableModularAccount.sol";
import {AccountStateMutatingPlugin} from "../../mocks/plugins/AccountStateMutatingPlugin.sol";
import {AccountStatePhasesTest} from "./AccountStatePhases.t.sol";

// Tests the account state phase behavior when the source of the state modification
// happens during runtime validation.
contract AccountStatePhasesRTValidationTest is AccountStatePhasesTest {
    // Test cases covered here:
    // These are listed in the order they are run in the test suite.
    // The "source" indicates which in which phase the plugin will perform a modification, and the "target"
    // indicates which phase will change as a result of the modification.
    //
    // - Source: pre-Runtime-Validation
    //     - Target: pre-UserOp-Validation
    //         - n/a - can’t run in the same call
    //     - Target: UserOp-Validation
    //         - n/a - can’t run in the same call
    //     - Target: pre-Runtime-Validation (same phase)
    //         - Addition: adding a hook should not result in that hook running.
    //         - Removal: removing a hook should still have the hook run.
    //     - Target: Runtime-Validation (same phase)
    //         - Replace: original should run
    //         - Removal: original should run
    //     - Target: pre-Exec (different phase)
    //         - Addition (first element): should run
    //         - Addition (not first): should run
    //         - Removal: should *not* run
    //     - Target: Exec (different phase)
    //         - Replace: replacement should run
    //         - Removal: should revert as empty
    //     - Target: post-Exec (different phase)
    //         - Addition (associated, first pre-exec): should run
    //         - Addition (associated, non-first pre-exec): should run
    //         - Removal (associated, first pre-exec): should *not* run
    //         - Removal (associated, non-first pre-exec): should *not* run
    //         - Addition (first post-only): should run
    //         - Addition (non-first post-only): should run
    //         - Removal (first post-only): should *not* run
    //         - Removal (non-first post-only): should *not* run
    // - Source: Runtime-Validation
    //     - Target: pre-UserOp-Validation
    //         - n/a - can’t run in the same call
    //     - Target: UserOp-Validation
    //         - n/a - can’t run in the same call
    //     - Target: pre-Runtime-Validation (same phase)
    //         - n/a - runs before
    //     - Target: Runtime-Validation (same phase)
    //         - Won’t test, since it’s the same single-element field.
    //     - Target: pre-Exec (different phase)
    //         - Addition (first element): should run
    //         - Addition (not first): should run
    //         - Removal: should *not* run
    //     - Target: Exec (different phase)
    //         - Replace: replacement should run
    //         - Removal: should revert as empty
    //     - Target: post-Exec (different phase)
    //         - Addition (associated, first pre-exec): should run
    //         - Addition (associated, non-first pre-exec): should run
    //         - Removal (associated, first pre-exec): should *not* run
    //         - Removal (associated, non-first pre-exec): should *not* run
    //         - Addition (first post-only): should run
    //         - Addition (non-first post-only): should run
    //         - Removal (first post-only): should *not* run
    //         - Removal (non-first post-only): should *not* run

    // Source: pre-Runtime-Validation
    // Target: pre-UserOp-Validation
    // n/a - can’t run in the same call

    // Source: pre-Runtime-Validation
    // Target: UserOp-Validation
    // n/a - can’t run in the same call

    function test_ASP_preRTValidation_add_preRTValidation() public {
        // Source: pre-Runtime-Validation
        // Target: pre-Runtime-Validation (same phase)
        // Addition: adding a hook should not result in that hook running.

        // Set up the mock plugin with a pre-Runtime-Validation hook, which will be added and should not run.
        _initMockPluginPreRuntimeValidationHook();

        // Install the ASM plugin with a pre runtime validation hook that will add a pre runtime validation
        // hook.
        // Runtime validation is also needed to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: true,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // ASM
        // plugin's pre runtime validation function to install the mock plugin's pre runtime validation hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock
        // plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(AccountStateMutatingPlugin.preRuntimeValidationHook.selector),
            0 // Should be called 0 times
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preRTValidation_remove_preRTValidation() public {
        // Source: pre-Runtime-Validation
        // Target: pre-Runtime-Validation (same phase)
        // Removal: removing a hook should still have the hook run.

        // Set up the mock plugin with a pre-Runtime-Validation hook, which will be removed and should run.
        _initMockPluginPreRuntimeValidationHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a pre runtime validation hook that will remove the mock plugin's pre
        // runtime validation hook.
        // Runtime validation is also needed to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: true,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // ASM plugin's pre runtime validation function to remove the mock plugin's pre runtime validation hook.
        // Per the 6900 spec, because this is in the same phase, the state change should not be applied and the
        // mock plugin's hook should run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(AccountStateMutatingPlugin.preRuntimeValidationHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preRTValidation_replace_RTValidation() public {
        // Source: pre-Runtime-Validation
        // Target: Runtime-Validation (same phase)
        // Replace: original should run

        // Set up the mock plugin with a Runtime-Validation function, which will replace the one defined by the
        // ASM plugin and should not be run.
        // To allow the call to complete as intended, we also add the execution function to the mock plugin.
        m1.executionFunctions.push(AccountStateMutatingPlugin.executionFunction.selector);
        _initMockPluginRuntimeValidationFunction();

        // Install the ASM plugin with a pre runtime validation hook that will replace the runtime validation
        // function.
        // Runtime validation is also needed to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: true,
            setPreExec: false,
            setPostExec: false
        });
        // Encode two self-calls: one to uninstall ASM plugin, one to install the mock plugin.
        Call[] memory calls = _generateCallsUninstallASMInstallMock();
        asmPlugin.setCallback(
            abi.encodeCall(IStandardExecutor.executeBatch, (calls)),
            AccountStateMutatingPlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // ASM plugin's pre runtime validation function to replace the runtime validation function with the mock
        // plugin's runtime validation function. The original should run, not the replacement.
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(AccountStateMutatingPlugin.runtimeValidationFunction.selector),
            1 // Should be called 1 time
        );
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(AccountStateMutatingPlugin.runtimeValidationFunction.selector),
            0 // Should be called 0 times
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preRTValidation_remove_RTValidation() public {
        // Source: pre-Runtime-Validation
        // Target: Runtime-Validation (same phase)
        // Removal: original should run

        // To allow the exec call to not revert, we add the execution function to the mock plugin.
        _initMockPluginExecFunction();

        // Install the ASM plugin with a pre runtime validation hook that will remove the runtime validation
        // function.
        // Runtime validation is also needed to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: true,
            setPreExec: false,
            setPostExec: false
        });
        Call[] memory calls = _generateCallsUninstallASMInstallMock();
        asmPlugin.setCallback(
            abi.encodeCall(IStandardExecutor.executeBatch, (calls)),
            AccountStateMutatingPlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // ASM plugin's pre runtime validation function to remove the runtime validation function. The original
        // runtime validation function should run.
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(AccountStateMutatingPlugin.runtimeValidationFunction.selector),
            1 // Should be called 1 time
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preRTValidation_add_preExec_firstElement() public {
        // Source: pre-Runtime-Validation
        // Target: pre-Exec (different phase)
        // Addition (first element): should run

        // Set up the mock plugin with a pre-Exec hook, which will be added and should run.
        _initMockPluginPreExecutionHook();

        // Install the ASM plugin with a pre runtime validation hook that will add a pre exec hook.
        // It also needs a runtime validation function to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: true,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // ASM plugin's pre runtime validation function to install the mock plugin's pre exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.preExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preRTValidation_add_preExec_notFirstElement() public {
        // Source: pre-Runtime-Validation
        // Target: pre-Exec (different phase)
        // Addition (not first): should run

        // Set up the mock plugin with a pre-Exec hook, which will be added and should run.
        _initMockPluginPreExecutionHook();

        // Install the ASM plugin with a pre runtime validation hook that will add a pre exec hook.
        // It also needs a runtime validation function to allow the call to be performed, and a pre exec hook to
        // ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: true,
            setPreExec: true,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // ASM plugin's pre runtime validation function to install the mock plugin's pre exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.preExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.preExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preRTValidation_remove_preExec() public {
        // Source: pre-Runtime-Validation
        // Target: pre-Exec (different phase)
        // Removal: should *not* run

        // Set up the mock plugin with a pre-Exec hook, which will be removed and should not run.
        _initMockPluginPreExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a pre runtime validation hook that will remove the mock plugin's pre exec
        // hook.
        // It also needs a runtime validation function to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: true,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // ASM plugin's pre runtime validation function to remove the mock plugin's pre exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.preExecutionHook.selector),
            0 // Should be called 0 times
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preRTValidation_replace_exec() public {
        // Source: pre-Runtime-Validation
        // Target: Exec (different phase)
        // Replace: replacement should run

        // Set up the mock plugin with an Exec function, which will replace the one defined by the ASM plugin
        // and should be run.
        _initMockPluginExecFunction();

        // Install the ASM plugin with a pre runtime validation hook that will replace the exec function.
        // Runtime validation is also needed to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: true,
            setPreExec: false,
            setPostExec: false
        });
        // Encode two self-calls: one to uninstall ASM plugin, one to install the mock plugin.
        Call[] memory calls = _generateCallsUninstallASMInstallMock();
        asmPlugin.setCallback(
            abi.encodeCall(IStandardExecutor.executeBatch, (calls)),
            AccountStateMutatingPlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // ASM plugin's pre runtime validation function to replace the exec function with the mock plugin's exec
        // function. The replacement should run, not the original.
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(AccountStateMutatingPlugin.executionFunction.selector),
            0 // Should be called 0 times
        );
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(AccountStateMutatingPlugin.executionFunction.selector),
            1 // Should be called 1 time
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preRTValidation_remove_exec() public {
        // Source: pre-Runtime-Validation
        // Target: Exec (different phase)
        // Removal: should revert as empty

        // Install the ASM plugin with a pre runtime validation hook that will remove the exec function.
        // Runtime validation is also needed to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: true,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(asmPlugin), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // ASM plugin's pre runtime validation function to remove the exec function. This should cause the call to
        // revert, but only after the ASM plugin's runtime validation function has run.
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.runtimeValidationFunction.selector),
            1 // Should be called 1 time
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.UnrecognizedFunction.selector,
                AccountStateMutatingPlugin.executionFunction.selector
            )
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preRTValidation_add_postExec_associated_firstElement() public {
        // Source: pre-Runtime-Validation
        // Target: post-Exec (different phase)
        // Addition (associated, first pre-exec): should run

        // Set up the mock plugin with an associated post-Exec hook, which will be added and should run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the ASM plugin with a pre runtime validation hook that will add a post exec hook.
        // It also needs a runtime validation function to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: true,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // ASM plugin's pre runtime validation function to install the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preRTValidation_add_postExec_associated_notFirstElement() public {
        // Source: pre-Runtime-Validation
        // Target: post-Exec (different phase)
        // Addition (associated, non-first pre-exec): should run

        // Set up the mock plugin with an associated post-Exec hook, which will be added and should run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the ASM plugin with a pre runtime validation hook that will add a post exec hook.
        // It also needs a runtime validation function to allow the call to be performed, and a pre exec hook to
        // ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: true,
            setPreExec: true,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // ASM plugin's pre runtime validation function to install the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preRTValidation_remove_postExec_associated_firstElement() public {
        // Source: pre-Runtime-Validation
        // Target: post-Exec (different phase)
        // Removal (associated, first pre-exec): should *not* run

        // Set up the mock plugin with an associated post-Exec hook, which will be removed and should not run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a pre runtime validation hook that will remove the mock plugin's post exec
        // hook.
        // It also needs a runtime validation function to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: true,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // ASM plugin's pre runtime validation function to remove the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preRTValidation_remove_postExec_associated_notFirstElement() public {
        // Source: pre-Runtime-Validation
        // Target: post-Exec (different phase)
        // Removal (associated, non-first pre-exec): should *not* run

        // Set up the mock plugin with an associated post-Exec hook, which will be removed and should not run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a pre runtime validation hook that will remove the mock plugin's post exec
        // hook. It also needs a runtime validation function to allow the call to be performed, and a pre exec
        // hook to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: true,
            setPreExec: true,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // ASM plugin's pre runtime validation function to remove the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preRTValidation_add_postExec_firstElement() public {
        // Source: pre-Runtime-Validation
        // Target: post-Exec (different phase)
        // Addition (first post-only): should run

        // Set up the mock plugin with a post-Exec hook, which will be added and should run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the ASM plugin with a pre runtime validation hook that will add a post exec hook.
        // It also needs a runtime validation function to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: true,
            setPostExec: false,
            setPreExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // ASM plugin's pre runtime validation function to install the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preRTValidation_add_postExec_notFirstElement() public {
        // Source: pre-Runtime-Validation
        // Target: post-Exec (different phase)
        // Addition (non-first post-only): should run

        // Set up the mock plugin with a post-Exec hook, which will be added and should run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the ASM plugin with a pre runtime validation hook that will add a post exec hook.
        // It also needs a runtime validation function to allow the call to be performed, and a post-only exec hook
        // to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: true,
            setPostExec: true,
            setPreExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // ASM plugin's pre runtime validation function to install the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should run.
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
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preRTValidation_remove_postExec_firstElement() public {
        // Source: pre-Runtime-Validation
        // Target: post-Exec (different phase)
        // Removal (first post-only): should *not* run

        // Set up the mock plugin with a post-Exec hook, which will be removed and should not run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a pre runtime validation hook that will remove the mock plugin's post exec
        // hook.
        // It also needs a runtime validation function to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: true,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // ASM plugin's pre runtime validation function to remove the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_preRTValidation_remove_postExec_notFirstElement() public {
        // Source: pre-Runtime-Validation
        // Target: post-Exec (different phase)
        // Removal (non-first post-only): should *not* run

        // Set up the mock plugin with a post-Exec hook, which will be removed and should not run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a pre runtime validation hook that will remove the mock plugin's post exec
        // hook. It also needs a runtime validation function to allow the call to be performed, and a post-only
        // exec hook to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: true,
            setPostExec: true,
            setPreExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // ASM plugin's pre runtime validation function to remove the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
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
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    // Source: Runtime-Validation
    // Target: pre-UserOp-Validation
    // n/a - can’t run in the same call

    // Source: Runtime-Validation
    // Target: UserOp-Validation
    // n/a - can’t run in the same call

    // Source: Runtime-Validation
    // Target: pre-Runtime-Validation (same phase)
    // n/a - runs before

    // Source: Runtime-Validation
    // Target: Runtime-Validation (same phase)
    // Won’t test, since it’s the same single-element field.

    function test_ASP_RTValidation_add_preExec_firstElement() public {
        // Source: Runtime-Validation
        // Target: pre-Exec (different phase)
        // Addition (first element): should run

        // Set up the mock plugin with a pre-Exec hook, which will be added and should run.
        _initMockPluginPreExecutionHook();

        // Install the ASM plugin with a runtime validation function that will add a pre exec hook.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.RUNTIME_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // mock plugin's runtime validation function to install the mock plugin's pre exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.preExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_RTValidation_add_preExec_notFirstElement() public {
        // Source: Runtime-Validation
        // Target: pre-Exec (different phase)
        // Addition (not first): should run

        // Set up the mock plugin with a pre-Exec hook, which will be added and should run.
        _initMockPluginPreExecutionHook();

        // Install the ASM plugin with a runtime validation function that will add a pre exec hook.
        // It also needs a pre exec hook to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: false,
            setPreExec: true,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.RUNTIME_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // mock plugin's runtime validation function to install the mock plugin's pre exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.preExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.preExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_RTValidation_remove_preExec() public {
        // Source: Runtime-Validation
        // Target: pre-Exec (different phase)
        // Removal: should *not* run

        // Set up the mock plugin with a pre-Exec hook, which will be removed and should not run.
        _initMockPluginPreExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a runtime validation function that will remove the mock plugin's pre exec
        // hook.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.RUNTIME_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger the
        // mock plugin's runtime validation function to remove the mock plugin's pre exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.preExecutionHook.selector),
            0 // Should be called 0 times
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_RTValidation_replace_exec() public {
        // Source: Runtime-Validation
        // Target: Exec (different phase)
        // Replace: replacement should run

        // Set up the mock plugin with an Exec function, which will replace the one defined by the ASM plugin
        // and should be run.
        _initMockPluginExecFunction();

        // Install the ASM plugin with a runtime validation function that will replace the exec function.
        // Runtime validation is also needed to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        // Encode two self-calls: one to uninstall ASM plugin, one to install the mock plugin.
        Call[] memory calls = _generateCallsUninstallASMInstallMock();
        asmPlugin.setCallback(
            abi.encodeCall(IStandardExecutor.executeBatch, (calls)),
            AccountStateMutatingPlugin.FunctionId.RUNTIME_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger
        // the ASM plugin's runtime validation function to replace the exec function with the mock plugin's exec
        // function. The replacement should run, not the original.
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(AccountStateMutatingPlugin.executionFunction.selector),
            0 // Should be called 0 times
        );
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(AccountStateMutatingPlugin.executionFunction.selector),
            1 // Should be called 1 time
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_RTValidation_remove_exec() public {
        // Source: Runtime-Validation
        // Target: Exec (different phase)
        // Removal: should revert as empty

        // Install the ASM plugin with a runtime validation function that will remove the exec function.
        // Runtime validation is also needed to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(asmPlugin), "", "")),
            AccountStateMutatingPlugin.FunctionId.RUNTIME_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger
        // the ASM plugin's runtime validation function to remove the exec function. This should cause the call to
        // revert, but only after the ASM plugin's runtime validation function has run.
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.runtimeValidationFunction.selector),
            1 // Should be called 1 time
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.UnrecognizedFunction.selector,
                AccountStateMutatingPlugin.executionFunction.selector
            )
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_RTValidation_add_postExec_associated_firstElement() public {
        // Source: Runtime-Validation
        // Target: post-Exec (different phase)
        // Addition (associated, first pre-exec): should run

        // Set up the mock plugin with an associated post-Exec hook, which will be added and should run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the ASM plugin with a runtime validation function that will add a post exec hook.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.RUNTIME_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger
        // the ASM plugin's runtime validation function to install the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_RTValidation_add_postExec_associated_notFirstElement() public {
        // Source: Runtime-Validation
        // Target: post-Exec (different phase)
        // Addition (associated, non-first pre-exec): should run

        // Set up the mock plugin with an associated post-Exec hook, which will be added and should run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the ASM plugin with a runtime validation function that will add a post exec hook.
        // It also needs a pre exec hook to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: false,
            setPreExec: true,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.RUNTIME_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger
        // the ASM plugin's runtime validation function to install the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_RTValidation_remove_postExec_associated_firstElement() public {
        // Source: Runtime-Validation
        // Target: post-Exec (different phase)
        // Removal (associated, first pre-exec): should *not* run

        // Set up the mock plugin with an associated post-Exec hook, which will be removed and should not run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a runtime validation function that will remove the mock plugin's post exec
        // hook.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.RUNTIME_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger
        // the ASM plugin's runtime validation function to remove the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_RTValidation_remove_postExec_associated_notFirstElement() public {
        // Source: Runtime-Validation
        // Target: post-Exec (different phase)
        // Removal (associated, non-first pre-exec): should *not* run

        // Set up the mock plugin with an associated post-Exec hook, which will be removed and should not run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a runtime validation function that will remove the mock plugin's post exec
        // hook. It also needs a pre exec hook to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: false,
            setPreExec: true,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.RUNTIME_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger
        // the ASM plugin's runtime validation function to remove the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_RTValidation_add_postExec_firstElement() public {
        // Source: Runtime-Validation
        // Target: post-Exec (different phase)
        // Addition (first post-only): should run

        // Set up the mock plugin with a post-Exec hook, which will be added and should run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the ASM plugin with a runtime validation function that will add a post exec hook.
        // It also needs a runtime validation function to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: false,
            setPostExec: false,
            setPreExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.RUNTIME_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger
        // the ASM plugin's runtime validation function to install the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_RTValidation_add_postExec_notFirstElement() public {
        // Source: Runtime-Validation
        // Target: post-Exec (different phase)
        // Addition (non-first post-only): should run

        // Set up the mock plugin with a post-Exec hook, which will be added and should run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the ASM plugin with a runtime validation function that will add a post exec hook.
        // It also needs a post-only exec hook to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: false,
            setPostExec: true,
            setPreExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.RUNTIME_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger
        // the ASM plugin's runtime validation function to install the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should run.
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
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_RTValidation_remove_postExec_firstElement() public {
        // Source: Runtime-Validation
        // Target: post-Exec (different phase)
        // Removal (first post-only): should *not* run

        // Set up the mock plugin with a post-Exec hook, which will be removed and should not run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a runtime validation function that will remove the mock plugin's post exec
        // hook.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: false,
            setPostExec: false,
            setPreExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.RUNTIME_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger
        // the ASM plugin's runtime validation function to remove the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
        // mock plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

    function test_ASP_RTValidation_remove_postExec_notFirstElement() public {
        // Source: Runtime-Validation
        // Target: post-Exec (different phase)
        // Removal (non-first post-only): should *not* run

        // Set up the mock plugin with a post-Exec hook, which will be removed and should not run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a runtime validation function that will remove the mock plugin's post exec
        // hook. It also needs a post-only exec hook to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: false,
            setPreUOValidation: false,
            setRTValidation: true,
            setPreRTValidation: false,
            setPostExec: true,
            setPreExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.RUNTIME_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a direct runtime call. This will trigger
        // the ASM plugin's runtime validation function to remove the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the
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
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }
}
