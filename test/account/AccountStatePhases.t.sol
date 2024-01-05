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

    function test_UOValidation_installPreExecHook_isExecuted_firstHook() public {
        // Set up the mock plugin with a pre-exec hook.
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

        // Install the ASM plugin with a user operation validation function, that will install a pre-exec hook from
        // the mock plugin.
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

        // Call the `executionFunction` function on the account. This will trigger the ASM plugin to install the
        // mock plugin during its user op validation function.
        // Per the 6900 spec, the state change from validation should be applied and recognized during execution,
        // which means the pre-execution hook on the mock plugin should be run.
        entryPoint.handleOps(_generateAndSignUserOp(), beneficiary);
    }

    function test_UOValidation_installPreExecHook_isExecuted_secondHook() public {}

    // Helper functions

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

    // Will read the manifest from the state var m1 and install the plugin
    // function _installMockPlugin() internal {
    //     mockPlugin1 = new MockPlugin(m1);
    //     manifestHash1 = _manifestHashOf(m1);
    //     FunctionReference[] memory dependencies = new FunctionReference[](0);
    //     IPluginManager.InjectedHook[] memory injectedHooks = new IPluginManager.InjectedHook[](0);
    //     vm.expectEmit(true, true, true, true);
    //     emit ReceivedCall(abi.encodeCall(IPlugin.onInstall, (bytes(""))), 0);
    //     vm.expectEmit(true, true, true, true);
    //     emit PluginInstalled(address(mockPlugin1), manifestHash1, dependencies, injectedHooks);
    //     vm.prank(owner1);
    //     account1.installPlugin(address(mockPlugin1), manifestHash1, "", dependencies, injectedHooks);
    // }

    function _initMockPlugin() internal {
        manifestHash1 = _manifestHashOf(m1);
        mockPlugin1 = new MockPlugin(m1);
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
}
