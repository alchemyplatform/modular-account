// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";
import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";
import {UserOperation} from "../../src/interfaces/erc4337/UserOperation.sol";
import {IPluginManager} from "../../src/interfaces/IPluginManager.sol";
import {IStandardExecutor, Call} from "../../src/interfaces/IStandardExecutor.sol";
import {
    IPlugin,
    ManifestExecutionHook,
    PluginManifest,
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction
} from "../../src/interfaces/IPlugin.sol";
import {FunctionReference, FunctionReferenceLib} from "../../src/libraries/FunctionReferenceLib.sol";
import {MultiOwnerMSCAFactory} from "../../src/factory/MultiOwnerMSCAFactory.sol";

import {AccountStateMutatingPlugin} from "../mocks/plugins/AccountStateMutatingPlugin.sol";
import {MockPlugin} from "../mocks/MockPlugin.sol";

// A test that verifies how the account caches the state of plugins. This is intended to ensure consistency of
// execution flow when either hooks or plugins change installation state within a single call to the account.
// NOTE: This test implicitly depends on hooks executionorder being latest-to-oldest. This is not guaranteed by
// the spec, but is currently the case. If that changes, this test will need to be updated.
contract AccountStatePhasesTest is Test {
    using ECDSA for bytes32;

    IEntryPoint public entryPoint;
    MultiOwnerPlugin public multiOwnerPlugin;
    MultiOwnerMSCAFactory public factory;
    address payable beneficiary;

    address public owner1;
    uint256 public owner1Key;
    UpgradeableModularAccount public account1;

    AccountStateMutatingPlugin public asmPlugin;

    MockPlugin public mockPlugin1;
    bytes32 public manifestHash1;
    PluginManifest public m1;

    // Function ID constants to use with the mock plugin.
    uint8 internal constant _PRE_HOOK_FUNCTION_ID_1 = 1;
    uint8 internal constant _POST_HOOK_FUNCTION_ID_2 = 2;
    uint8 internal constant _PRE_UO_VALIDATION_HOOK_FUNCTION_ID_3 = 3;
    uint8 internal constant _PRE_RT_VALIDATION_HOOK_FUNCTION_ID_4 = 4;
    uint8 internal constant _UO_VALIDATION_FUNCTION_ID_5 = 5;
    uint8 internal constant _RT_VALIDATION_FUNCTION_ID_6 = 6;

    // Event re-declarations for vm.expectEmit
    event PluginInstalled(
        address indexed plugin,
        bytes32 manifestHash,
        FunctionReference[] dependencies,
        IPluginManager.InjectedHook[] injectedHooks
    );
    event PluginUninstalled(address indexed plugin, bool indexed callbacksSucceeded);
    event ReceivedCall(bytes msgData, uint256 msgValue);

    // Empty arrays for convenience
    FunctionReference[] internal _EMPTY_DEPENDENCIES;
    IPluginManager.InjectedHook[] internal _EMPTY_INJECTED_HOOKS;
    bytes[] internal _EMPTY_HOOK_APPLY_DATA;

    // Constants for running user ops
    uint256 constant CALL_GAS_LIMIT = 300000;
    uint256 constant VERIFICATION_GAS_LIMIT = 1000000;

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));
        multiOwnerPlugin = new MultiOwnerPlugin();
        asmPlugin = new AccountStateMutatingPlugin();

        (owner1, owner1Key) = makeAddrAndKey("owner1");
        beneficiary = payable(makeAddr("beneficiary"));
        address accountImpl = address(new UpgradeableModularAccount(IEntryPoint(address(entryPoint))));

        factory = new MultiOwnerMSCAFactory(
            address(this),
            address(multiOwnerPlugin),
            accountImpl,
            keccak256(abi.encode(multiOwnerPlugin.pluginManifest())),
            entryPoint
        );

        // Add 2 owners to the account:
        // - The owner1 EOA, for signing user operations
        // - The AccountStateMutatingPlugin, for authorizing runtime calls to installPlugin/uninstallPlugin
        address[] memory owners = new address[](2);
        owners[0] = owner1;
        owners[1] = address(asmPlugin);
        account1 = UpgradeableModularAccount(payable(factory.createAccount(0, owners)));
        vm.deal(address(account1), 100 ether);
    }

    // How these tests will work
    // - Create a custom plugin "AccountStateMutatingPlugin" that can perform install / uninstall during hooks,
    // validation, or execution.
    // - This is done by pushing the call encoding responsibilitiy to this test, and just exposing a "side"
    // method that specifies the callback it should do in a given phase back toward the calling account.
    // - Authorization for install/uninstall can be granted by making the plugin itself an owner in multi-owner
    // plugin, which will
    // authorize runtime calls.
    // - The contents of what is called are defined in a mock plugin like the exec hooks test.

    // ALL TEST CASES:
    // These are listed in the order they are run in the test suite.
    // The "source" indicates which in which phase the plugin will perform a modification, and the "target"
    // indicates which phase will change as a result of the modification.
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
    //         - Addition (not first): should ***not*** run
    //         - Removal: should still run
    //     - Target: Exec (same phase)
    //         - Replace: original should run
    //         - Removal: original should run
    //     - Target: post-Exec (same phase)
    //         - Addition (associated, first pre-exec): *impossible*
    //         - Addition (associated, non-first pre-exec): should ****not**** run
    //         - Removal (associated, first pre-exec): *impossible*
    //         - Removal (associated, non-first pre-exec): should still run
    //         - Addition (first post-only): should ****not**** run
    //         - Addition (non-first post-only): should ****not**** run
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
    //         - Addition (associated, first pre-exec): should ****not**** run
    //         - Addition (associated, non-first pre-exec): should ****not**** run
    //         - Removal (associated, first pre-exec): should still run
    //         - Removal (associated, non-first pre-exec): should still run
    //         - Addition (first post-only): should ****not**** run
    //         - Addition (non-first post-only): should ****not**** run
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
    //         - Addition (associated, first pre-exec): should ****not**** run
    //         - Addition (associated, non-first pre-exec): should ****not**** run
    //         - Removal (associated, first pre-exec): should still run
    //         - Removal (associated, non-first pre-exec): should still run
    //         - Addition (first post-only): should ****not**** run
    //         - Addition (non-first post-only): should ****not**** run
    //         - Removal (first post-only): should still run
    //         - Removal (non-first post-only): should still run

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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(asmPlugin), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(asmPlugin), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
            1 // Should be called 0 times
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(asmPlugin), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
            1 // Should be called 0 times
        );
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
        asmPlugin.setCallback(
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(asmPlugin), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(asmPlugin), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
            1 // Should be called 0 times
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(asmPlugin), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
            1 // Should be called 0 times
        );
        vm.prank(owner1);
        AccountStateMutatingPlugin(address(account1)).executionFunction();
    }

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
        // Addition (not first): should **not** run

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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(asmPlugin), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
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
            abi.encodeCall(IPluginManager.uninstallPlugin, (address(mockPlugin1), "", "", _EMPTY_HOOK_APPLY_DATA)),
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
        // Addition (first post-only): should ****not**** run
    }

    function test_ASP_preExec_add_postExec_notFirstElement() public {
        // Source: pre-Exec
        // Target: post-Exec (same phase)
        // Addition (non-first post-only): should ****not**** run
    }

    function test_ASP_preExec_remove_postExec_firstElement() public {
        // Source: pre-Exec
        // Target: post-Exec (same phase)
        // Removal (first post-only): should still run
    }

    function test_ASP_preExec_remove_postExec_notFirstElement() public {
        // Source: pre-Exec
        // Target: post-Exec (same phase)
        // Removal (non-first post-only): should still run
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
        // Addition (associated, first pre-exec): should ****not**** run
    }

    function test_ASP_exec_add_postExec_associated_notFirstElement() public {
        // Source: Exec
        // Target: post-Exec (same phase)
        // Addition (associated, non-first pre-exec): should ****not**** run
    }

    function test_ASP_exec_remove_postExec_associated_firstElement() public {
        // Source: Exec
        // Target: post-Exec (same phase)
        // Removal (associated, first pre-exec): should still run
    }

    function test_ASP_exec_remove_postExec_associated_notFirstElement() public {
        // Source: Exec
        // Target: post-Exec (same phase)
        // Removal (associated, non-first pre-exec): should still run
    }

    function test_ASP_exec_add_postExec_firstElement() public {
        // Source: Exec
        // Target: post-Exec (same phase)
        // Addition (first post-only): should ****not**** run
    }

    function test_ASP_exec_add_postExec_notFirstElement() public {
        // Source: Exec
        // Target: post-Exec (same phase)
        // Addition (non-first post-only): should ****not**** run
    }

    function test_ASP_exec_remove_postExec_firstElement() public {
        // Source: Exec
        // Target: post-Exec (same phase)
        // Removal (first post-only): should still run
    }

    function test_ASP_exec_remove_postExec_notFirstElement() public {
        // Source: Exec
        // Target: post-Exec (same phase)
        // Removal (non-first post-only): should still run
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

    function test_ASP_postExec_add_postExec_associated_firstElement() public {
        // Source: post-Exec
        // Target: post-Exec (same phase)
        // Addition (associated, first pre-exec): should ****not**** run
    }

    function test_ASP_postExec_add_postExec_associated_notFirstElement() public {
        // Source: post-Exec
        // Target: post-Exec (same phase)
        // Addition (associated, non-first pre-exec): should ****not**** run
    }

    function test_ASP_postExec_remove_postExec_associated_firstElement() public {
        // Source: post-Exec
        // Target: post-Exec (same phase)
        // Removal (associated, first pre-exec): should still run
    }

    function test_ASP_postExec_remove_postExec_associated_notFirstElement() public {
        // Source: post-Exec
        // Target: post-Exec (same phase)
        // Removal (associated, non-first pre-exec): should still run
    }

    function test_ASP_postExec_add_postExec_firstElement() public {
        // Source: post-Exec
        // Target: post-Exec (same phase)
        // Addition (first post-only): should ****not**** run
    }

    function test_ASP_postExec_add_postExec_notFirstElement() public {
        // Source: post-Exec
        // Target: post-Exec (same phase)
        // Addition (non-first post-only): should ****not**** run
    }

    function test_ASP_postExec_remove_postExec_firstElement() public {
        // Source: post-Exec
        // Target: post-Exec (same phase)
        // Removal (first post-only): should still run
    }

    function test_ASP_postExec_remove_postExec_notFirstElement() public {
        // Source: post-Exec
        // Target: post-Exec (same phase)
        // Removal (non-first post-only): should still run
    }

    // Test assertion stubs - used to assert behavior in the "second half" of tests.
    // The logic is pulled out into functions here for better reuse.
    // TODO: is this useful / helpful?

    // Helper functions

    // Mock plugin config helpers - shortcuts to configure with 1 plugin function.
    // Does not install the mock plugin.

    function _initMockPluginPreUserOpValidationHook() internal {
        m1.preUserOpValidationHooks.push(
            ManifestAssociatedFunction({
                executionSelector: AccountStateMutatingPlugin.executionFunction.selector,
                associatedFunction: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.SELF,
                    functionId: _PRE_UO_VALIDATION_HOOK_FUNCTION_ID_3,
                    dependencyIndex: 0 // unused
                })
            })
        );
        _initMockPlugin();
    }

    function _initMockPluginUserOpValidationFunction() internal {
        m1.userOpValidationFunctions.push(
            ManifestAssociatedFunction({
                executionSelector: AccountStateMutatingPlugin.executionFunction.selector,
                associatedFunction: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.SELF,
                    functionId: _UO_VALIDATION_FUNCTION_ID_5,
                    dependencyIndex: 0 // unused
                })
            })
        );
        _initMockPlugin();
    }

    function _initMockPluginPreRuntimeValidationHook() internal {
        m1.preRuntimeValidationHooks.push(
            ManifestAssociatedFunction({
                executionSelector: AccountStateMutatingPlugin.executionFunction.selector,
                associatedFunction: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.SELF,
                    functionId: _PRE_RT_VALIDATION_HOOK_FUNCTION_ID_4,
                    dependencyIndex: 0 // unused
                })
            })
        );
        _initMockPlugin();
    }

    function _initMockPluginRuntimeValidationFunction() internal {
        m1.runtimeValidationFunctions.push(
            ManifestAssociatedFunction({
                executionSelector: AccountStateMutatingPlugin.executionFunction.selector,
                associatedFunction: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.SELF,
                    functionId: _RT_VALIDATION_FUNCTION_ID_6,
                    dependencyIndex: 0 // unused
                })
            })
        );
        _initMockPlugin();
    }

    function _initMockPluginPreExecutionHook() internal {
        m1.executionHooks.push(
            ManifestExecutionHook({
                executionSelector: AccountStateMutatingPlugin.executionFunction.selector,
                preExecHook: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.SELF,
                    functionId: _PRE_HOOK_FUNCTION_ID_1,
                    dependencyIndex: 0 // Unused
                }),
                postExecHook: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.NONE,
                    functionId: 0, // Unused
                    dependencyIndex: 0 // Unused
                })
            })
        );
        _initMockPlugin();
    }

    function _initMockPluginExecFunction() internal {
        m1.executionFunctions.push(AccountStateMutatingPlugin.executionFunction.selector);
        _initMockPlugin();
    }

    function _initMockPluginPreAndPostExecutionHook() internal {
        m1.executionHooks.push(
            ManifestExecutionHook({
                executionSelector: AccountStateMutatingPlugin.executionFunction.selector,
                preExecHook: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.SELF,
                    functionId: _PRE_HOOK_FUNCTION_ID_1,
                    dependencyIndex: 0 // Unused
                }),
                postExecHook: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.SELF,
                    functionId: _POST_HOOK_FUNCTION_ID_2,
                    dependencyIndex: 0 // Unused
                })
            })
        );
        _initMockPlugin();
    }

    function _initMockPluginPostOnlyExecutionHook() internal {
        m1.executionHooks.push(
            ManifestExecutionHook({
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
            })
        );
        _initMockPlugin();
    }

    // Other helper functions

    // Installs the account state mutating plugin. Prior to calling this, the test should configure the desired
    // plugin functions and callbacks, since the manifest will mutate based on that.
    function _installASMPlugin() internal {
        FunctionReference[] memory dependencies = new FunctionReference[](0);
        IPluginManager.InjectedHook[] memory injectedHooks = new IPluginManager.InjectedHook[](0);
        bytes32 manifestHash = _manifestHashOf(asmPlugin.pluginManifest());
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(address(asmPlugin), manifestHash, dependencies, injectedHooks);
        vm.prank(owner1);
        account1.installPlugin(address(asmPlugin), manifestHash, "", dependencies, injectedHooks);
    }

    // Sets up the manifest hash variable and deploys the mock plugin.
    function _initMockPlugin() internal {
        manifestHash1 = _manifestHashOf(m1);
        mockPlugin1 = new MockPlugin(m1);
    }

    // Installs the mock plugin onto the account. Prior to calling this, the test should configure the desired
    // plugin functions, and call _initMockPlugin() to set up the mock plugin.
    function _installMockPlugin() internal {
        FunctionReference[] memory dependencies = new FunctionReference[](0);
        IPluginManager.InjectedHook[] memory injectedHooks = new IPluginManager.InjectedHook[](0);
        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onInstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(address(mockPlugin1), manifestHash1, dependencies, injectedHooks);
        vm.prank(owner1);
        account1.installPlugin(address(mockPlugin1), manifestHash1, "", dependencies, injectedHooks);
    }

    function _manifestHashOf(PluginManifest memory manifest) internal pure returns (bytes32) {
        return keccak256(abi.encode(manifest));
    }

    function _generateAndSignUserOp() internal view returns (UserOperation[] memory ops) {
        ops = new UserOperation[](1);
        ops[0] = UserOperation({
            sender: address(account1),
            nonce: entryPoint.getNonce(address(account1), 0),
            initCode: "",
            callData: abi.encodeCall(AccountStateMutatingPlugin.executionFunction, ()),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(ops[0]);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        ops[0].signature = abi.encodePacked(r, s, v);
    }

    function _generateCallsUninstallASMInstallMock() internal view returns (Call[] memory) {
        // Encode two self-calls: one to uninstall ASM plugin, one to install the mock plugin.
        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(account1),
            value: 0 ether,
            data: abi.encodeCall(IPluginManager.uninstallPlugin, (address(asmPlugin), "", "", _EMPTY_HOOK_APPLY_DATA))
        });
        calls[1] = Call({
            target: address(account1),
            value: 0 ether,
            data: abi.encodeCall(
                IPluginManager.installPlugin,
                (address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS)
                )
        });
        return calls;
    }
}
