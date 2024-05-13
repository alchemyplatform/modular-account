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

import {IPluginManager} from "modular-account-libs/interfaces/IPluginManager.sol";
import {IPlugin} from "modular-account-libs/interfaces/IPlugin.sol";
import {IStandardExecutor, Call} from "modular-account-libs/interfaces/IStandardExecutor.sol";

import {AccountStatePhasesTest} from "./AccountStatePhases.t.sol";
import {AccountStateMutatingPlugin} from "../../mocks/plugins/AccountStateMutatingPlugin.sol";

// Tests the account state phase behavior when the source of the state modification
// happens during user op validation.
contract AccountStatePhasesUOValidationTest is AccountStatePhasesTest {
    // Test cases covered here:
    // These are listed in the order they are run in the test suite.
    // The "source" indicates which in which phase the plugin will perform a modification, and the "target"
    // indicates which phase will change as a result of the modification.
    //
    // - Source: pre-UserOp-Validation
    //     - Target: pre-UserOp-Validation (same phase)
    //         - Addition: adding a hook should not result in that hook running.
    //         - Removal: removing a hook should still have the hook run.
    //     - Target: UserOp-Validation (same phase)
    //         - Replace: original should run
    //         - Removal: original should run
    //     - Target: pre-Runtime-Validation (different phase)
    //         - n/a - can’t run in the same user op
    //     - Target: Runtime-Validation (different phase)
    //         - n/a - can’t run in the same user op
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
    // - Source: UserOp-Validation
    //     - Target: pre-UserOp-Validation (same phase)
    //         - n/a - happens before user op validation
    //     - Target: UserOp-Validation (same phase)
    //         - Won’t test, since it’s the same single-element field.
    //     - Target: pre-Runtime-Validation (different phase)
    //         - n/a - can’t run in the same user op
    //     - Target: Runtime-Validation (different phase)
    //         - n/a - can’t run in the same user op
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

    function test_ASP_preUOValidation_add_preUOValidation() public {
        // Source: pre-UserOp-Validation
        // Target: pre-UserOp-Validation (same phase)
        // Addition: adding a hook should not result in that hook running.

        // Set up the mock plugin with a pre-UserOp-Validation hook, which will be added and should not run.
        _initMockPluginPreUserOpValidationHook();

        // Install the ASM plugin with a pre user op validation hook that will add a pre user op validation hook.
        // It also needs a user op validation function to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: true,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin to
        // install the mock plugin's pre user op validation hook during the first pre-UserOp-Validation hook.
        // Per the 6900 spec, the state change should not be applied yet and the mock plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.preUserOpValidationHook.selector),
            0 // Should be called 0 times
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_preUOValidation_remove_preUOValidation() public {
        // Source: pre-UserOp-Validation
        // Target: pre-UserOp-Validation (same phase)
        // Removal: removing a hook should still have the hook run.

        // Set up the mock plugin with a pre-UserOp-Validation hook, which will be removed and should still run.
        _initMockPluginPreUserOpValidationHook();

        // Install the plugin as part of the starting state. By installing this first, it will run AFTER the ASM
        // plugin's pre-UserOp-Validation hook, giving the modification a chance to change the logic.
        _installMockPlugin();

        // Install the ASM plugin with a pre user op validation hook that will remove the mock plugin's pre user op
        // validation hook.
        // It also needs a user op validation function to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: true,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK
        );
        _installASMPlugin();

        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.preUserOpValidationHook.selector),
            1 // Should be called 1 time
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_preUOValidation_replace_UOValidation() public {
        // Source: pre-UserOp-Validation
        // Target: UserOp-Validation (same phase)
        // Replace: original should run

        // Set up the mock plugin with a userOpValidation function, which will replace the one defined by the ASM
        // plugin and should not be run.
        _initMockPluginUserOpValidationFunction();

        // Install the ASM plugin with a pre user op validation hook that will replace its own user op validation
        // function.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: true,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        // Encode two self-calls: one to uninstall ASM plugin, one to install the mock plugin.
        Call[] memory calls = _generateCallsUninstallASMInstallMock();
        asmPlugin.setCallback(
            abi.encodeCall(IStandardExecutor.executeBatch, (calls)),
            AccountStateMutatingPlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin to
        // replace its own user op validation function with the mock plugin's user op validation function during
        // the
        // first pre-UserOp-Validation hook. The original should run, not the replacement.
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.userOpValidationFunction.selector),
            1 // Should be called 1 time
        );
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.userOpValidationFunction.selector),
            0 // Should be called 0 times
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_preUOValidation_remove_UOValidation() public {
        // Source: pre-UserOp-Validation
        // Target: UserOp-Validation (same phase)
        // Removal: original should run

        // Install the ASM plugin with a pre user op validation hook that will remove its own user op validation
        // function.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: true,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });

        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(asmPlugin), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin to
        // remove its own user op validation function during the first pre-UserOp-Validation hook. The original
        // should run.
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.userOpValidationFunction.selector),
            1 // Should be called 1 time
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    // Source: pre-UserOp-Validation
    // Target: pre-Runtime-Validation (different phase)
    // n/a - can’t run in the same user op

    // Source: pre-UserOp-Validation
    // Target: Runtime-Validation (different phase)
    // n/a - can’t run in the same user op

    function test_ASP_preUOValidation_add_preExec_firstElement() public {
        // Source: pre-UserOp-Validation
        // Target: pre-Exec (different phase)
        // Addition (first element): should run

        // Set up the mock plugin with a pre-Exec hook, which will be added and should run.
        _initMockPluginPreExecutionHook();

        // Install the ASM plugin with a pre user op validation hook that will add a pre exec hook.
        // It also needs a user op validation function to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: true,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin to
        // install the mock plugin's pre exec hook during the first pre-UserOp-Validation hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.preExecutionHook.selector),
            1 // Should be called 1 time
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_preUOValidation_add_preExec_notFirstElement() public {
        // Source: pre-UserOp-Validation
        // Target: pre-Exec (different phase)
        // Addition (not first): should run

        // Set up the mock plugin with a pre-Exec hook, which will be added and should run.
        _initMockPluginPreExecutionHook();

        // Install the ASM plugin with a pre user op validation hook that will add a pre exec hook.
        // It also needs a user op validation function to allow the call to be performed, and a pre exec hook to
        // ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: true,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: true,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin to
        // install the mock plugin's pre exec hook during the first pre-UserOp-Validation hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should run.
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
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_preUOValidation_remove_preExec() public {
        // Source: pre-UserOp-Validation
        // Target: pre-Exec (different phase)
        // Removal: should *not* run

        // Set up the mock plugin with a pre-Exec hook, which will be removed and should not run.
        _initMockPluginPreExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a pre user op validation hook that will remove the mock plugin's pre exec
        // hook.
        // It also needs a user op validation function to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: true,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin to
        // remove the mock plugin's pre exec hook during the first pre-UserOp-Validation hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.preExecutionHook.selector),
            0 // Should be called 0 times
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_preUOValidation_replace_exec() public {
        // Source: pre-UserOp-Validation
        // Target: Exec (different phase)
        // Replace: replacement should run

        // Set up the mock plugin with an exec function, which will replace the one defined by the ASM plugin and
        // should be run.
        _initMockPluginExecFunction();

        // Install the ASM plugin with a pre user op validation hook that will replace the exec function.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: true,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        // Encode two self-calls: one to uninstall ASM plugin, one to install the mock plugin.
        Call[] memory calls = _generateCallsUninstallASMInstallMock();
        asmPlugin.setCallback(
            abi.encodeCall(IStandardExecutor.executeBatch, (calls)),
            AccountStateMutatingPlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin to
        // replace its own exec function with the mock plugin's exec function during the first
        // pre-UserOp-Validation
        // hook. The replacement should run, not the original.
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
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_preUOValidation_remove_exec() public {
        // Source: pre-UserOp-Validation
        // Target: Exec (different phase)
        // Removal: should revert as empty

        // Install the ASM plugin with a pre user op validation hook that will remove the exec function.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: true,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(asmPlugin), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin to
        // remove its own exec function during the first pre-UserOp-Validation hook. Then, the call should revert
        // during the execution phase because the exec function is empty.

        // Cannot use vm.expectRevert because it would only apply to the top-level call to `handleOps`, not the
        // internal call. Instead, we use expectCall with a count of 0.
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(AccountStateMutatingPlugin.executionFunction.selector),
            0 // Should be called 0 times
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_preUOValidation_add_postExec_associated_firstElement() public {
        // Source: pre-UserOp-Validation
        // Target: post-Exec (different phase)
        // Addition (associated, first pre-exec): should run

        // Set up the mock plugin with an associated post-Exec hook, which will be added and should run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the ASM plugin with a pre user op validation hook that will add a post exec hook.
        // It also needs a user op validation function to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: true,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin to
        // install the mock plugin's associated post exec hook during the first pre-UserOp-Validation hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_preUOValidation_add_postExec_associated_notFirstElement() public {
        // Source: pre-UserOp-Validation
        // Target: post-Exec (different phase)
        // Addition (associated, non-first pre-exec): should run

        // Set up the mock plugin with an associated post-Exec hook, which will be added and should run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the ASM plugin with a pre user op validation hook that will add a post exec hook.
        // It also needs a user op validation function to allow the call to be performed, and a pre exec hook to
        // ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: true,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: true,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin to
        // install the mock plugin's associated post exec hook during the first pre-UserOp-Validation hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_preUOValidation_remove_postExec_associated_firstElement() public {
        // Source: pre-UserOp-Validation
        // Target: post-Exec (different phase)
        // Removal (associated, first pre-exec): should *not* run

        // Set up the mock plugin with an associated post-Exec hook, which will be removed and should not run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a pre user op validation hook that will remove the mock plugin's associated
        // post exec hook.
        // It also needs a user op validation function to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: true,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin to
        // remove the mock plugin's associated post exec hook during the first pre-UserOp-Validation hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_preUOValidation_remove_postExec_associated_notFirstElement() public {
        // Source: pre-UserOp-Validation
        // Target: post-Exec (different phase)
        // Removal (associated, non-first pre-exec): should *not* run

        // Set up the mock plugin with an associated post-Exec hook, which will be removed and should not run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a pre user op validation hook that will remove the mock plugin's associated
        // post exec hook.
        // It also needs a user op validation function to allow the call to be performed, and a pre exec hook to
        // ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: true,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: true,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin to
        // remove the mock plugin's associated post exec hook during the first pre-UserOp-Validation hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_preUOValidation_add_postExec_firstElement() public {
        // Source: pre-UserOp-Validation
        // Target: post-Exec (different phase)
        // Addition (first post-only): should run

        // Set up the mock plugin with a post-Exec hook, which will be added and should run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the ASM plugin with a pre user op validation hook that will add a post exec hook.
        // It also needs a user op validation function to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: true,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin to
        // install the mock plugin's post exec hook during the first pre-UserOp-Validation hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_preUOValidation_add_postExec_notFirstElement() public {
        // Source: pre-UserOp-Validation
        // Target: post-Exec (different phase)
        // Addition (non-first post-only): should run

        // Set up the mock plugin with a post-Exec hook, which will be added and should run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the ASM plugin with a pre user op validation hook that will add a post exec hook.
        // It also needs a user op validation function to allow the call to be performed, and a pre exec hook to
        // ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: true,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: true
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin to
        // install the mock plugin's post exec hook during the first pre-UserOp-Validation hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should run.
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
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_preUOValidation_remove_postExec_firstElement() public {
        // Source: pre-UserOp-Validation
        // Target: post-Exec (different phase)
        // Removal (first post-only): should *not* run

        // Set up the mock plugin with a post-Exec hook, which will be removed and should not run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a pre user op validation hook that will remove the mock plugin's post exec
        // hook.
        // It also needs a user op validation function to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: true,
            setRTValidation: false,
            setPreRTValidation: false,
            setPostExec: false,
            setPreExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin to
        // remove the mock plugin's post exec hook during the first pre-UserOp-Validation hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_preUOValidation_remove_postExec_notFirstElement() public {
        // Source: pre-UserOp-Validation
        // Target: post-Exec (different phase)
        // Removal (non-first post-only): should *not* run

        // Set up the mock plugin with a post-Exec hook, which will be removed and should not run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a pre user op validation hook that will remove the mock plugin's post exec
        // hook.
        // It also needs a user op validation function to allow the call to be performed, and a post-only exec hook
        // to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: true,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: true
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin to
        // remove the mock plugin's post exec hook during the first pre-UserOp-Validation hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should not run.
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
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    // Source: UserOp-Validation
    // Target: pre-UserOp-Validation (same phase)
    // n/a - happens before user op validation

    // Source: UserOp-Validation
    // Target: UserOp-Validation (same phase)
    // Won’t test, since it’s the same single-element field.

    // Source: UserOp-Validation
    // Target: pre-Runtime-Validation (different phase)
    // n/a - can’t run in the same user op

    // Source: UserOp-Validation
    // Target: Runtime-Validation (different phase)
    // n/a - can’t run in the same user op

    function test_ASP_UOValidation_add_preExec_firstElement() public {
        // Source: UserOp-Validation
        // Target: pre-Exec (different phase)
        // Addition (first element): should run

        // Set up the mock plugin with a pre-Exec hook, which will be added and should run.
        _initMockPluginPreExecutionHook();

        // Install the ASM plugin with a user op validation function that will add a pre exec hook.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: false,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.USER_OP_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin's
        // user op validation function to install the mock plugin's pre exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.preExecutionHook.selector),
            1 // Should be called 1 time
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_UOValidation_add_preExec_notFirstElement() public {
        // Source: UserOp-Validation
        // Target: pre-Exec (different phase)
        // Addition (not first): should run

        // Set up the mock plugin with a pre-Exec hook, which will be added and should run.
        _initMockPluginPreExecutionHook();

        // Install the ASM plugin with a user op validation function that will add a pre exec hook.
        // It also needs a pre exec hook to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: false,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: true,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.USER_OP_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin's
        // user op validation function to install the mock plugin's pre exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should run.
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
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_UOValidation_remove_preExec() public {
        // Source: UserOp-Validation
        // Target: pre-Exec (different phase)
        // Removal: should *not* run

        // Set up the mock plugin with a pre-Exec hook, which will be removed and should not run.
        _initMockPluginPreExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a user op validation function that will remove the mock plugin's pre exec
        // hook.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: false,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.USER_OP_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin's
        // user op validation function to remove the mock plugin's pre exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.preExecutionHook.selector),
            0 // Should be called 0 times
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_UOValidation_replace_exec() public {
        // Source: UserOp-Validation
        // Target: Exec (different phase)
        // Replace: replacement should run

        // Set up the mock plugin with an exec function, which will replace the one defined by the ASM plugin and
        // should be run.
        _initMockPluginExecFunction();

        // Install the ASM plugin with a user op validation function that will replace the exec function.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: false,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        // Encode two self-calls: one to uninstall ASM plugin, one to install the mock plugin.
        Call[] memory calls = _generateCallsUninstallASMInstallMock();
        asmPlugin.setCallback(
            abi.encodeCall(IStandardExecutor.executeBatch, (calls)),
            AccountStateMutatingPlugin.FunctionId.USER_OP_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin's
        // user op validation function to replace the exec function with the mock plugin's exec function. The
        // replacement should run, not the original.
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
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_UOValidation_remove_exec() public {
        // Source: UserOp-Validation
        // Target: Exec (different phase)
        // Removal: should revert as empty

        // Install the ASM plugin with a user op validation function that will remove the exec function.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: false,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(asmPlugin), "", "")),
            AccountStateMutatingPlugin.FunctionId.USER_OP_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin's
        // user op validation function to remove the exec function. Then, the call should revert during the
        // execution phase because the exec function is empty.
        vm.expectCall(
            address(asmPlugin),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(AccountStateMutatingPlugin.executionFunction.selector),
            0 // Should be called 0 times
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_UOValidation_add_postExec_associated_firstElement() public {
        // Source: UserOp-Validation
        // Target: post-Exec (different phase)
        // Addition (associated, first pre-exec): should run

        // Set up the mock plugin with an associated post-Exec hook, which will be added and should run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the ASM plugin with a user op validation function that will add a post exec hook.
        // It also needs a user op validation function to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: false,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.USER_OP_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin's
        // user op validation function to install the mock plugin's associated post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_UOValidation_add_postExec_associated_notFirstElement() public {
        // Source: UserOp-Validation
        // Target: post-Exec (different phase)
        // Addition (associated, non-first pre-exec): should run

        // Set up the mock plugin with an associated post-Exec hook, which will be added and should run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the ASM plugin with a user op validation function that will add a post exec hook.
        // It also needs a user op validation function to allow the call to be performed, and a pre exec hook to
        // ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: false,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: true,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.USER_OP_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin's
        // user op validation function to install the mock plugin's associated post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_UOValidation_remove_postExec_associated_firstElement() public {
        // Source: UserOp-Validation
        // Target: post-Exec (different phase)
        // Removal (associated, first pre-exec): should *not* run

        // Set up the mock plugin with an associated post-Exec hook, which will be removed and should not run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a user op validation function that will remove the mock plugin's associated
        // post exec hook.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: false,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.USER_OP_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin's
        // user op validation function to remove the mock plugin's associated post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_UOValidation_remove_postExec_associated_notFirstElement() public {
        // Source: UserOp-Validation
        // Target: post-Exec (different phase)
        // Removal (associated, non-first pre-exec): should *not* run

        // Set up the mock plugin with an associated post-Exec hook, which will be removed and should not run.
        _initMockPluginPreAndPostExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a user op validation function that will remove the mock plugin's associated
        // post exec hook.
        // It also needs a user op validation function to allow the call to be performed, and a pre exec hook to
        // ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: false,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: true,
            setPostExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.USER_OP_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin's
        // user op validation function to remove the mock plugin's associated post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_UOValidation_add_postExec_firstElement() public {
        // Source: UserOp-Validation
        // Target: post-Exec (different phase)
        // Addition (first post-only): should run

        // Set up the mock plugin with a post-Exec hook, which will be added and should run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the ASM plugin with a user op validation function that will add a post exec hook.
        // It also needs a user op validation function to allow the call to be performed.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: false,
            setRTValidation: false,
            setPreRTValidation: false,
            setPostExec: false,
            setPreExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.USER_OP_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin's
        // user op validation function to install the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            1 // Should be called 1 time
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_UOValidation_add_postExec_notFirstElement() public {
        // Source: UserOp-Validation
        // Target: post-Exec (different phase)
        // Addition (non-first post-only): should run

        // Set up the mock plugin with a post-Exec hook, which will be added and should run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the ASM plugin with a user op validation function that will add a post exec hook.
        // It also needs a user op validation function to allow the call to be performed, and a post-only exec hook
        // to
        // ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: false,
            setRTValidation: false,
            setPreRTValidation: false,
            setPreExec: false,
            setPostExec: true
        });
        asmPlugin.setCallback(
            abi.encodeCall(
                IPluginManager.installPlugin, (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES)
            ),
            AccountStateMutatingPlugin.FunctionId.USER_OP_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin's
        // user op validation function to install the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should run.
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
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_UOValidation_remove_postExec_firstElement() public {
        // Source: UserOp-Validation
        // Target: post-Exec (different phase)
        // Removal (first post-only): should *not* run

        // Set up the mock plugin with a post-Exec hook, which will be removed and should not run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a user op validation function that will remove the mock plugin's post exec
        // hook.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: false,
            setRTValidation: false,
            setPreRTValidation: false,
            setPostExec: false,
            setPreExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.USER_OP_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin's
        // user op validation function to remove the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should not run.
        vm.expectCall(
            address(mockPlugin1),
            // Partial calldata is provided to match against different parameters.
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector),
            0 // Should be called 0 times
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_ASP_UOValidation_remove_postExec_notFirstElement() public {
        // Source: UserOp-Validation
        // Target: post-Exec (different phase)
        // Removal (non-first post-only): should *not* run

        // Set up the mock plugin with a post-Exec hook, which will be removed and should not run.
        _initMockPluginPostOnlyExecutionHook();

        // Install the mock plugin as part of the starting state.
        _installMockPlugin();

        // Install the ASM plugin with a user op validation function that will remove the mock plugin's post exec
        // hook.
        // It also needs a user op validation function to allow the call to be performed, and a post-only exec hook
        // to ensure that the mock plugin's hook is not the first one.
        asmPlugin.configureInstall({
            setUOValidation: true,
            setPreUOValidation: false,
            setRTValidation: false,
            setPreRTValidation: false,
            setPostExec: true,
            setPreExec: false
        });
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "")),
            AccountStateMutatingPlugin.FunctionId.USER_OP_VALIDATION
        );
        _installASMPlugin();

        // Call the `executionFunction` function on the account via a user op. This will trigger the ASM plugin's
        // user op validation function to remove the mock plugin's post exec hook.
        // Per the 6900 spec, because this is in a different phase, the state change should be applied and the mock
        // plugin's hook should not run.
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
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }
}
