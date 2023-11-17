// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";
import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";
import {IPluginManager} from "../../src/interfaces/IPluginManager.sol";
import {FunctionReference, FunctionReferenceLib} from "../../src/libraries/FunctionReferenceLib.sol";
import {
    IPlugin,
    ManifestExecutionHook,
    PluginManifest,
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction
} from "../../src/interfaces/IPlugin.sol";

import {MultiOwnerMSCAFactory} from "../../src/factory/MultiOwnerMSCAFactory.sol";
import {MockPlugin} from "../mocks/MockPlugin.sol";

contract UpgradeableModularAccountExecHooksTest is Test {
    using ECDSA for bytes32;

    IEntryPoint public entryPoint;
    MultiOwnerPlugin public multiOwnerPlugin;
    MultiOwnerMSCAFactory public factory;
    MockPlugin public mockPlugin1;
    MockPlugin public mockPlugin2;
    bytes32 public manifestHash1;
    bytes32 public manifestHash2;

    address public owner1;
    uint256 public owner1Key;
    UpgradeableModularAccount public account1;

    bytes4 internal constant _EXEC_SELECTOR = bytes4(uint32(1));
    uint8 internal constant _PRE_HOOK_FUNCTION_ID_1 = 1;
    uint8 internal constant _POST_HOOK_FUNCTION_ID_2 = 2;
    uint8 internal constant _PRE_HOOK_FUNCTION_ID_3 = 3;
    uint8 internal constant _POST_HOOK_FUNCTION_ID_4 = 4;

    PluginManifest public m1;
    PluginManifest public m2;

    event PluginInstalled(
        address indexed plugin,
        bytes32 manifestHash,
        FunctionReference[] dependencies,
        IPluginManager.InjectedHook[] injectedHooks
    );
    event PluginUninstalled(address indexed plugin, bool indexed callbacksSucceeded);
    // emitted by MockPlugin
    event ReceivedCall(bytes msgData, uint256 msgValue);

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));
        multiOwnerPlugin = new MultiOwnerPlugin();

        (owner1, owner1Key) = makeAddrAndKey("owner1");
        address impl = address(new UpgradeableModularAccount(IEntryPoint(address(entryPoint))));

        factory = new MultiOwnerMSCAFactory(
            address(this), 
            address(multiOwnerPlugin), 
            impl, 
            keccak256(abi.encode(multiOwnerPlugin.pluginManifest())), 
            entryPoint
        );

        address[] memory owners = new address[](1);
        owners[0] = owner1;
        account1 = UpgradeableModularAccount(payable(factory.createAccount(0, owners)));
        vm.deal(address(account1), 100 ether);

        entryPoint.depositTo{value: 1 wei}(address(account1));

        m1.executionFunctions.push(_EXEC_SELECTOR);

        m1.runtimeValidationFunctions.push(
            ManifestAssociatedFunction({
                executionSelector: _EXEC_SELECTOR,
                associatedFunction: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
                    functionId: 0,
                    dependencyIndex: 0
                })
            })
        );
    }

    /// @dev Plugin 1 hook pair: [1, null]
    ///      Expected execution: [1, null]
    function test_preExecHook_install() public {
        vm.startPrank(owner1);

        _installPlugin1WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0})
        );

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, null]
    ///      Expected execution: [1, null]
    function test_preExecHook_run() public {
        test_preExecHook_install();

        vm.startPrank(owner1);

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                owner1, // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            0 // msg value in call to plugin
        );

        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);

        vm.stopPrank();
    }

    function testFuzz_preExecHook_revertData(bytes memory hookRevertReason) public {
        vm.startPrank(owner1);
        MockPlugin hookPlugin = _installPlugin1WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0})
        );

        vm.mockCallRevert(
            address(hookPlugin),
            abi.encodeCall(IPlugin.preExecutionHook, (1, owner1, 0, abi.encodeWithSelector(_EXEC_SELECTOR))),
            hookRevertReason
        );
        (bool success, bytes memory returnData) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);
        assertEq(
            returnData,
            abi.encodeWithSelector(
                UpgradeableModularAccount.PreExecHookReverted.selector, address(hookPlugin), 1, hookRevertReason
            )
        );
        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, null]
    ///      Expected execution: [1, null]
    function test_preExecHook_uninstall() public {
        test_preExecHook_install();

        vm.startPrank(owner1);

        _uninstallPlugin(mockPlugin1);

        vm.stopPrank();
    }

    function test_preExecHook_revertAlwaysDeny() public {
        vm.startPrank(owner1);

        _installPlugin1WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                functionId: 0,
                dependencyIndex: 0
            }),
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0})
        );

        (bool success, bytes memory returnData) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);
        assertEq(returnData, abi.encodeWithSelector(UpgradeableModularAccount.AlwaysDenyRule.selector));

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Expected execution: [1, 2]
    function test_execHookPair_install() public {
        vm.startPrank(owner1);

        _installPlugin1WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            })
        );

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Expected execution: [1, 2]
    function test_execHookPair_run() public {
        test_execHookPair_install();

        vm.startPrank(owner1);

        vm.expectEmit(true, true, true, true);
        // pre hook call
        emit ReceivedCall(
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                owner1, // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            0 // msg value in call to plugin
        );
        vm.expectEmit(true, true, true, true);
        // exec call
        emit ReceivedCall(abi.encodePacked(_EXEC_SELECTOR), 0);
        vm.expectEmit(true, true, true, true);
        // post hook call
        emit ReceivedCall(
            abi.encodeCall(
                IPlugin.postExecutionHook, (_POST_HOOK_FUNCTION_ID_2, abi.encode(_PRE_HOOK_FUNCTION_ID_1))
            ),
            0 // msg value in call to plugin
        );

        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Expected execution: [1, 2]
    function test_execHookPair_uninstall() public {
        test_execHookPair_install();

        vm.startPrank(owner1);

        _uninstallPlugin(mockPlugin1);

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [null, 2]
    ///      Expected execution: [null, 2]
    function test_postOnlyExecHook_install() public {
        vm.startPrank(owner1);

        _installPlugin1WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0}),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            })
        );

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [null, 2]
    ///      Expected execution: [null, 2]
    function test_postOnlyExecHook_run() public {
        test_postOnlyExecHook_install();

        vm.startPrank(owner1);

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(
            abi.encodeCall(IPlugin.postExecutionHook, (_POST_HOOK_FUNCTION_ID_2, "")),
            0 // msg value in call to plugin
        );

        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [null, 2]
    ///      Expected execution: [null, 2]
    function test_postOnlyExecHook_uninstall() public {
        test_postOnlyExecHook_install();

        vm.startPrank(owner1);

        _uninstallPlugin(mockPlugin1);

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, null]
    ///      Plugin 2 hook pair: [1, null]
    ///      Expected execution: [1, null]
    function test_overlappingPreExecHooks_install() public {
        vm.startPrank(owner1);

        // Install the first plugin.
        _installPlugin1WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0})
        );

        // Install a second plugin that applies the first plugin's hook to the same selector.
        FunctionReference[] memory dependencies = new FunctionReference[](1);
        dependencies[0] = FunctionReferenceLib.pack(address(mockPlugin1), _PRE_HOOK_FUNCTION_ID_1);
        _installPlugin2WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.DEPENDENCY,
                functionId: 0,
                dependencyIndex: 0
            }),
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0}),
            dependencies
        );

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, null]
    ///      Plugin 2 hook pair: [1, null]
    ///      Expected execution: [1, null]
    function test_overlappingPreExecHooks_run() public {
        test_overlappingPreExecHooks_install();

        vm.startPrank(owner1);

        // Expect the pre hook to be called just once.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                owner1, // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            1
        );

        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, null]
    ///      Plugin 2 hook pair: [1, null]
    ///      Expected execution: [1, null]
    function test_overlappingPreExecHooks_uninstall() public {
        test_overlappingPreExecHooks_install();

        vm.startPrank(owner1);

        // Uninstall the second plugin.
        _uninstallPlugin(mockPlugin2);

        // Expect the pre hook to still exist after uninstalling a plugin with a duplicate hook.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                owner1, // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            1
        );
        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);

        // Uninstall the first plugin.
        _uninstallPlugin(mockPlugin1);

        // Execution selector should no longer exist.
        (success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Plugin 2 hook pair: [1, 2]
    ///      Expected execution: [1, 2]
    function test_overlappingExecHookPairs_install() public {
        vm.startPrank(owner1);

        // Install the first plugin.
        _installPlugin1WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            })
        );

        // Install a second plugin that applies the first plugin's hook pair to the same selector.
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReferenceLib.pack(address(mockPlugin1), _PRE_HOOK_FUNCTION_ID_1);
        dependencies[1] = FunctionReferenceLib.pack(address(mockPlugin1), _POST_HOOK_FUNCTION_ID_2);
        _installPlugin2WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.DEPENDENCY,
                functionId: 0,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.DEPENDENCY,
                functionId: 0,
                dependencyIndex: 1
            }),
            dependencies
        );

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Plugin 2 hook pair: [1, 2]
    ///      Expected execution: [1, 2]
    function test_overlappingExecHookPairs_run() public {
        test_overlappingExecHookPairs_install();

        vm.startPrank(owner1);

        // Expect the pre hook to be called just once.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                owner1, // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            1
        );

        // Expect the post hook to be called just once, with the expected data.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                abi.encode(_PRE_HOOK_FUNCTION_ID_1) // preExecHookData
            ),
            1
        );

        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Plugin 2 hook pair: [1, 2]
    ///      Expected execution: [1, 2]
    function test_overlappingExecHookPairs_uninstall() public {
        test_overlappingExecHookPairs_install();

        vm.startPrank(owner1);

        // Uninstall the second plugin.
        _uninstallPlugin(mockPlugin2);

        // Expect the pre/post hooks to still exist after uninstalling a plugin with a duplicate hook.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                owner1, // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                abi.encode(_PRE_HOOK_FUNCTION_ID_1) // preExecHookData
            ),
            1
        );
        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);

        // Uninstall the first plugin.
        _uninstallPlugin(mockPlugin1);

        // Execution selector should no longer exist.
        (success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Plugin 2 hook pair: [3, 2]
    ///      Expected execution: [1, 2], [3, 2]
    function test_overlappingExecHookPairsOnPost_install() public {
        vm.startPrank(owner1);

        // Install the first plugin.
        _installPlugin1WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            })
        );

        // Install the second plugin.
        FunctionReference[] memory dependencies = new FunctionReference[](1);
        dependencies[0] = FunctionReferenceLib.pack(address(mockPlugin1), _POST_HOOK_FUNCTION_ID_2);
        _installPlugin2WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_3,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.DEPENDENCY,
                functionId: 0,
                dependencyIndex: 0
            }),
            dependencies
        );

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Plugin 2 hook pair: [3, 2]
    ///      Expected execution: [1, 2], [3, 2]
    function test_overlappingExecHookPairsOnPost_run() public {
        test_overlappingExecHookPairsOnPost_install();

        vm.startPrank(owner1);

        // Expect each pre hook to be called once.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                owner1, // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin2),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_3,
                owner1, // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            1
        );

        // Expect the post hook to be called twice, with the expected data.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                abi.encode(_PRE_HOOK_FUNCTION_ID_1) // preExecHookData
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                abi.encode(_PRE_HOOK_FUNCTION_ID_3) // preExecHookData
            ),
            1
        );

        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Plugin 2 hook pair: [3, 2]
    ///      Expected execution: [1, 2], [3, 2]
    function test_overlappingExecHookPairsOnPost_uninstall() public {
        test_overlappingExecHookPairsOnPost_install();

        vm.startPrank(owner1);

        // Uninstall the second plugin.
        _uninstallPlugin(mockPlugin2);

        // Expect the pre/post hooks to still exist after uninstalling a plugin with a duplicate hook.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                owner1, // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                abi.encode(_PRE_HOOK_FUNCTION_ID_1) // preExecHookData
            ),
            1
        );
        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);

        // Uninstall the first plugin.
        _uninstallPlugin(mockPlugin1);

        // Execution selector should no longer exist.
        (success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Plugin 2 hook pair: [1, 4]
    ///      Expected execution: [1, 2], [1, 4]
    function test_overlappingExecHookPairsOnPre_install() public {
        vm.startPrank(owner1);

        // Install the first plugin.
        _installPlugin1WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            })
        );

        // Install the second plugin.
        FunctionReference[] memory dependencies = new FunctionReference[](1);
        dependencies[0] = FunctionReferenceLib.pack(address(mockPlugin1), _PRE_HOOK_FUNCTION_ID_1);
        _installPlugin2WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.DEPENDENCY,
                functionId: 0,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_4,
                dependencyIndex: 0
            }),
            dependencies
        );

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Plugin 2 hook pair: [1, 4]
    ///      Expected execution: [1, 2], [1, 4]
    function test_overlappingExecHookPairsOnPre_run() public {
        test_overlappingExecHookPairsOnPre_install();

        vm.startPrank(owner1);

        // Expect the pre hook to be called twice, each passing data over to their respective post hooks.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                owner1, // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            2
        );

        // Expect each post hook to be called once, with the expected data.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                abi.encode(_PRE_HOOK_FUNCTION_ID_1) // preExecHookData
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin2),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_4,
                abi.encode(_PRE_HOOK_FUNCTION_ID_1) // preExecHookData
            ),
            1
        );

        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Plugin 2 hook pair: [1, 4]
    ///      Expected execution: [1, 2], [1, 4]
    function test_overlappingExecHookPairsOnPre_uninstall() public {
        test_overlappingExecHookPairsOnPre_install();

        vm.startPrank(owner1);

        // Uninstall the second plugin.
        _uninstallPlugin(mockPlugin2);

        // Expect the pre/post hooks to still exist after uninstalling a plugin with a duplicate hook.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                owner1, // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                abi.encode(_PRE_HOOK_FUNCTION_ID_1) // preExecHookData
            ),
            1
        );
        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);

        // Uninstall the first plugin.
        _uninstallPlugin(mockPlugin1);

        // Execution selector should no longer exist.
        (success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Plugin 2 hook pair: [1, null]
    ///      Expected execution: [1, 2]
    function test_overlappingExecHookPairsOnPreWithNullPost_install() public {
        vm.startPrank(owner1);

        // Install the first plugin.
        _installPlugin1WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            })
        );

        // Install the second plugin.
        FunctionReference[] memory dependencies = new FunctionReference[](1);
        dependencies[0] = FunctionReferenceLib.pack(address(mockPlugin1), _PRE_HOOK_FUNCTION_ID_1);
        _installPlugin2WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.DEPENDENCY,
                functionId: 0,
                dependencyIndex: 0
            }),
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0}),
            dependencies
        );

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Plugin 2 hook pair: [1, null]
    ///      Expected execution: [1, 2]
    function test_overlappingExecHookPairsOnPreWithNullPost_run() public {
        test_overlappingExecHookPairsOnPreWithNullPost_install();

        vm.startPrank(owner1);

        // Expect the pre hook to be called just once.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                owner1, // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            1
        );

        // Expect the post hook to be called just once, with the expected data.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                abi.encode(_PRE_HOOK_FUNCTION_ID_1) // preExecHookData
            ),
            1
        );

        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Plugin 2 hook pair: [1, null]
    ///      Expected execution: [1, 2]
    function test_overlappingExecHookPairsOnPreWithNullPost_uninstall() public {
        test_overlappingExecHookPairsOnPreWithNullPost_install();

        vm.startPrank(owner1);

        // Uninstall the second plugin.
        _uninstallPlugin(mockPlugin2);

        // Expect the pre/post hooks to still exist after uninstalling a plugin with a duplicate hook.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                owner1, // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                abi.encode(_PRE_HOOK_FUNCTION_ID_1) // preExecHookData
            ),
            1
        );
        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);

        // Uninstall the first plugin.
        _uninstallPlugin(mockPlugin1);

        // Execution selector should no longer exist.
        (success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Plugin 2 hook pair: [null, 2]
    ///      Expected execution: [1, 2], [null, 2]
    function test_overlappingExecHookPairsOnPostWithNullPre_install() public {
        vm.startPrank(owner1);

        // Install the first plugin.
        _installPlugin1WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            })
        );

        // Install the second plugin.
        FunctionReference[] memory dependencies = new FunctionReference[](1);
        dependencies[0] = FunctionReferenceLib.pack(address(mockPlugin1), _POST_HOOK_FUNCTION_ID_2);
        _installPlugin2WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0}),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.DEPENDENCY,
                functionId: 0,
                dependencyIndex: 0
            }),
            dependencies
        );

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Plugin 2 hook pair: [null, 2]
    ///      Expected execution: [1, 2], [null, 2]
    function test_overlappingExecHookPairsOnPostWithNullPre_run() public {
        test_overlappingExecHookPairsOnPostWithNullPre_install();

        vm.startPrank(owner1);

        // Expect the pre hook to be called just once.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                owner1, // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            1
        );

        // Expect the post hook to be called twice, with the expected data.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                abi.encode(_PRE_HOOK_FUNCTION_ID_1) // preExecHookData
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                "" // preExecHookData
            ),
            1
        );

        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Plugin 2 hook pair: [null, 2]
    ///      Expected execution: [1, 2], [null, 2]
    function test_overlappingExecHookPairsOnPostWithNullPre_uninstall() public {
        test_overlappingExecHookPairsOnPostWithNullPre_install();

        vm.startPrank(owner1);

        // Uninstall the second plugin.
        _uninstallPlugin(mockPlugin2);

        // Expect the pre/post hooks to still exist after uninstalling a plugin with a duplicate hook.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                owner1, // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                abi.encode(_PRE_HOOK_FUNCTION_ID_1) // preExecHookData
            ),
            1
        );
        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);

        // Uninstall the first plugin.
        _uninstallPlugin(mockPlugin1);

        // Execution selector should no longer exist.
        (success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [null, 2]
    ///      Plugin 2 hook pair: [null, 2]
    ///      Expected execution: [null, 2]
    function test_overlappingPostExecHooks_install() public {
        vm.startPrank(owner1);

        // Install the first plugin.
        _installPlugin1WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0}),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            })
        );

        // Install the second plugin.
        FunctionReference[] memory dependencies = new FunctionReference[](1);
        dependencies[0] = FunctionReferenceLib.pack(address(mockPlugin1), _POST_HOOK_FUNCTION_ID_2);
        _installPlugin2WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0}),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.DEPENDENCY,
                functionId: 0,
                dependencyIndex: 0
            }),
            dependencies
        );

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [null, 2]
    ///      Plugin 2 hook pair: [null, 2]
    ///      Expected execution: [null, 2]
    function test_overlappingPostExecHooks_run() public {
        test_overlappingPostExecHooks_install();

        vm.startPrank(owner1);

        // Expect the post hook to be called just once.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                "" // preExecHookData
            ),
            1
        );

        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [null, 2]
    ///      Plugin 2 hook pair: [null, 2]
    ///      Expected execution: [null, 2]
    function test_overlappingPostExecHooks_uninstall() public {
        test_overlappingPostExecHooks_install();

        vm.startPrank(owner1);

        // Uninstall the second plugin.
        _uninstallPlugin(mockPlugin2);

        // Expect the pre/post hooks to still exist after uninstalling a plugin with a duplicate hook.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                "" // preExecHookData
            ),
            1
        );
        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);

        // Uninstall the first plugin.
        _uninstallPlugin(mockPlugin1);

        // Execution selector should no longer exist.
        (success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Plugin 2 hook pair: [null, 2]
    ///      Expected execution: [1, 2], [null, 2]
    function test_execHooksWithPostOnlyForNativeFunction_install() public {
        vm.startPrank(owner1);

        // Install the first plugin.
        _installPlugin1WithHooks(
            UpgradeableModularAccount.execute.selector,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            })
        );

        // Install the second plugin.
        FunctionReference[] memory dependencies = new FunctionReference[](1);
        dependencies[0] = FunctionReferenceLib.pack(address(mockPlugin1), _POST_HOOK_FUNCTION_ID_2);
        _installPlugin2WithHooks(
            UpgradeableModularAccount.execute.selector,
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0}),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.DEPENDENCY,
                functionId: 0,
                dependencyIndex: 0
            }),
            dependencies
        );

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Plugin 2 hook pair: [null, 2]
    ///      Expected execution: [1, 2], [null, 2]
    function test_execHooksWithPostOnlyForNativeFunction_run() public {
        test_execHooksWithPostOnlyForNativeFunction_install();

        vm.startPrank(owner1);

        // Expect the pre hook to be called just once.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                owner1, // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(UpgradeableModularAccount.execute.selector, address(0), 0, "")
            ),
            1
        );

        // Expect the post hook to be called twice, with the expected data.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                abi.encode(_PRE_HOOK_FUNCTION_ID_1) // preExecHookData
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                "" // preExecHookData
            ),
            1
        );

        account1.execute(address(0), 0, "");

        vm.stopPrank();
    }

    function _installPlugin1WithHooks(
        bytes4 selector,
        ManifestFunction memory preHook,
        ManifestFunction memory postHook
    ) internal returns (MockPlugin) {
        m1.executionHooks.push(ManifestExecutionHook(selector, preHook, postHook));
        mockPlugin1 = new MockPlugin(m1);
        manifestHash1 = keccak256(abi.encode(mockPlugin1.pluginManifest()));

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onInstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(
            address(mockPlugin1), manifestHash1, new FunctionReference[](0), new IPluginManager.InjectedHook[](0)
        );

        account1.installPlugin({
            plugin: address(mockPlugin1),
            manifestHash: manifestHash1,
            pluginInitData: bytes(""),
            dependencies: new FunctionReference[](0),
            injectedHooks: new IPluginManager.InjectedHook[](0)
        });

        return mockPlugin1;
    }

    function _installPlugin2WithHooks(
        bytes4 selector,
        ManifestFunction memory preHook,
        ManifestFunction memory postHook,
        FunctionReference[] memory dependencies
    ) internal {
        if (preHook.functionType == ManifestAssociatedFunctionType.DEPENDENCY) {
            m2.dependencyInterfaceIds.push(type(IPlugin).interfaceId);
        }
        if (postHook.functionType == ManifestAssociatedFunctionType.DEPENDENCY) {
            m2.dependencyInterfaceIds.push(type(IPlugin).interfaceId);
        }

        m2.executionHooks.push(ManifestExecutionHook(selector, preHook, postHook));

        mockPlugin2 = new MockPlugin(m2);
        manifestHash2 = keccak256(abi.encode(mockPlugin2.pluginManifest()));

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onInstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(
            address(mockPlugin2), manifestHash2, dependencies, new IPluginManager.InjectedHook[](0)
        );

        account1.installPlugin({
            plugin: address(mockPlugin2),
            manifestHash: manifestHash2,
            pluginInitData: bytes(""),
            dependencies: dependencies,
            injectedHooks: new IPluginManager.InjectedHook[](0)
        });
    }

    function _uninstallPlugin(MockPlugin plugin) internal {
        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onUninstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginUninstalled(address(plugin), true);

        account1.uninstallPlugin(address(plugin), bytes(""), bytes(""), new bytes[](0));
    }
}
