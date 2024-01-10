// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";

import {UpgradeableModularAccount} from "../../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerPlugin} from "../../../src/plugins/owner/MultiOwnerPlugin.sol";
import {IEntryPoint} from "../../../src/interfaces/erc4337/IEntryPoint.sol";
import {UserOperation} from "../../../src/interfaces/erc4337/UserOperation.sol";
import {IPluginManager} from "../../../src/interfaces/IPluginManager.sol";
import {IStandardExecutor, Call} from "../../../src/interfaces/IStandardExecutor.sol";
import {
    IPlugin,
    ManifestExecutionHook,
    PluginManifest,
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction
} from "../../../src/interfaces/IPlugin.sol";
import {FunctionReference, FunctionReferenceLib} from "../../../src/libraries/FunctionReferenceLib.sol";
import {MultiOwnerMSCAFactory} from "../../../src/factory/MultiOwnerMSCAFactory.sol";

import {AccountStateMutatingPlugin} from "../../mocks/plugins/AccountStateMutatingPlugin.sol";
import {MockPlugin} from "../../mocks/MockPlugin.sol";

// A test suite that verifies how the account caches the state of plugins. This is intended to ensure consistency
// of execution flow when either hooks or plugins change installation state within a single call to the account.
// The follow tests inherit from this test base:
// - AccountStatePhasesUOValidationTest
// - AccountStatePhasesRTValidationTest
// - AccountStatePhasesExecTest
// NOTE: This test implicitly depends on hooks executionorder being latest-to-oldest. This is not guaranteed by
// the spec, but is currently the case. If that changes, this test will need to be updated.
// How these tests will work
// - Create a custom plugin "AccountStateMutatingPlugin" that can perform install / uninstall during hooks,
// validation, or execution.
// - This is done by pushing the call encoding responsibilitiy to this test, and just exposing a "side"
// method that specifies the callback it should do in a given phase back toward the calling account.
// - Authorization for install/uninstall can be granted by making the plugin itself an owner in multi-owner
// plugin, which will
// authorize runtime calls.
// - The contents of what is called are defined in a mock plugin like the exec hooks test.
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

    // HELPER FUNCTIONS

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

    // Installs the account state mutating plugin. Prior to calling this, the test should configure the desired
    // plugin functions and callbacks, since the manifest will change based on that configuration.
    function _installASMPlugin() internal {
        bytes32 manifestHash = _manifestHashOf(asmPlugin.pluginManifest());
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(address(asmPlugin), manifestHash, _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS);
        vm.prank(owner1);
        account1.installPlugin(address(asmPlugin), manifestHash, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS);
    }

    // Sets up the manifest hash variable and deploys the mock plugin.
    function _initMockPlugin() internal {
        manifestHash1 = _manifestHashOf(m1);
        mockPlugin1 = new MockPlugin(m1);
    }

    // Installs the mock plugin onto the account. Prior to calling this, the test should configure the desired
    // plugin functions, and call _initMockPlugin() to set up the mock plugin.
    function _installMockPlugin() internal {
        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onInstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(address(mockPlugin1), manifestHash1, _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS);
        vm.prank(owner1);
        account1.installPlugin(address(mockPlugin1), manifestHash1, "", _EMPTY_DEPENDENCIES, _EMPTY_INJECTED_HOOKS);
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
