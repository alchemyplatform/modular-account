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

import {Test} from "forge-std/Test.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {FunctionReferenceLib} from "modular-account-libs/libraries/FunctionReferenceLib.sol";
import {
    IPlugin,
    ManifestExecutionHook,
    PluginManifest,
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction
} from "modular-account-libs/interfaces/IPlugin.sol";
import {FunctionReference} from "modular-account-libs/interfaces/IPluginManager.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {PluginManagerInternals} from "../../src/account/PluginManagerInternals.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerModularAccountFactory} from "../../src/factory/MultiOwnerModularAccountFactory.sol";
import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";
import {MockPlugin} from "../mocks/MockPlugin.sol";

contract UpgradeableModularAccountExecHooksTest is Test {
    using ECDSA for bytes32;

    IEntryPoint public entryPoint;
    MultiOwnerPlugin public multiOwnerPlugin;
    MultiOwnerModularAccountFactory public factory;
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

    event PluginInstalled(address indexed plugin, bytes32 manifestHash, FunctionReference[] dependencies);
    event PluginUninstalled(address indexed plugin, bool indexed onUninstallSucceeded);

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));
        multiOwnerPlugin = new MultiOwnerPlugin();

        (owner1, owner1Key) = makeAddrAndKey("owner1");
        address impl = address(new UpgradeableModularAccount(IEntryPoint(address(entryPoint))));

        factory = new MultiOwnerModularAccountFactory(
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

    function test_overlappingPreExecHookAlwaysDeny_install() public {
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

        _installPlugin2WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                functionId: 0,
                dependencyIndex: 0
            }),
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0}),
            new FunctionReference[](0)
        );

        vm.stopPrank();
    }

    function test_overlappingPreExecHookAlwaysDeny_revert() public {
        test_overlappingPreExecHookAlwaysDeny_install();

        vm.startPrank(owner1);

        (bool success, bytes memory returnData) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);
        assertEq(returnData, abi.encodeWithSelector(UpgradeableModularAccount.AlwaysDenyRule.selector));

        vm.stopPrank();
    }

    function test_overlappingPreExecHookAlwaysDeny_uninstallPlugin1() public {
        test_overlappingPreExecHookAlwaysDeny_install();

        vm.startPrank(owner1);

        _uninstallPlugin(mockPlugin1);

        // Execution selector should no longer exist.
        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);

        vm.stopPrank();
    }

    function test_overlappingPreExecHookAlwaysDeny_uninstallPlugin2() public {
        test_overlappingPreExecHookAlwaysDeny_install();

        vm.startPrank(owner1);

        _uninstallPlugin(mockPlugin2);

        (bool success, bytes memory returnData) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);
        assertEq(returnData, abi.encodeWithSelector(UpgradeableModularAccount.AlwaysDenyRule.selector));

        vm.stopPrank();
    }

    /// Plugins cannot depend on hooks from other plugins.
    function test_overlappingPreExecHook_invalid() public {
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

        FunctionReference[] memory dependencies = new FunctionReference[](1);
        dependencies[0] = FunctionReferenceLib.pack(address(mockPlugin1), 1);

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        this.installPlugin2WithHooksNoSuccessCheck(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.DEPENDENCY,
                functionId: 0,
                dependencyIndex: 0
            }),
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0}),
            dependencies
        );
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
        vm.expectCall(address(mockPlugin1), abi.encodePacked(_EXEC_SELECTOR), 1);
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeCall(
                IPlugin.postExecutionHook, (_POST_HOOK_FUNCTION_ID_2, abi.encode(_PRE_HOOK_FUNCTION_ID_1))
            ),
            1
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

        vm.expectCall(
            address(mockPlugin1), abi.encodeCall(IPlugin.postExecutionHook, (_POST_HOOK_FUNCTION_ID_2, "")), 1
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

    function _installPlugin1WithHooks(
        bytes4 selector,
        ManifestFunction memory preHook,
        ManifestFunction memory postHook
    ) internal returns (MockPlugin) {
        m1.executionHooks.push(ManifestExecutionHook(selector, preHook, postHook));
        mockPlugin1 = new MockPlugin(m1);
        manifestHash1 = keccak256(abi.encode(mockPlugin1.pluginManifest()));

        vm.expectCall(address(mockPlugin1), abi.encodeCall(IPlugin.onInstall, (bytes(""))), 1);
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(address(mockPlugin1), manifestHash1, new FunctionReference[](0));

        account1.installPlugin({
            plugin: address(mockPlugin1),
            manifestHash: manifestHash1,
            pluginInstallData: bytes(""),
            dependencies: new FunctionReference[](0)
        });

        return mockPlugin1;
    }

    function _installPlugin2WithHooks(
        bytes4 selector,
        ManifestFunction memory preHook,
        ManifestFunction memory postHook,
        FunctionReference[] memory dependencies
    ) internal {
        _installPlugin2WithHooksInternal(selector, preHook, postHook, dependencies, true);
    }

    function installPlugin2WithHooksNoSuccessCheck(
        bytes4 selector,
        ManifestFunction memory preHook,
        ManifestFunction memory postHook,
        FunctionReference[] memory dependencies
    ) external {
        _installPlugin2WithHooksInternal(selector, preHook, postHook, dependencies, false);
    }

    function _installPlugin2WithHooksInternal(
        bytes4 selector,
        ManifestFunction memory preHook,
        ManifestFunction memory postHook,
        FunctionReference[] memory dependencies,
        bool expectSuccess
    ) internal {
        vm.startPrank(owner1);

        if (preHook.functionType == ManifestAssociatedFunctionType.DEPENDENCY) {
            m2.dependencyInterfaceIds.push(type(IPlugin).interfaceId);
        }
        if (postHook.functionType == ManifestAssociatedFunctionType.DEPENDENCY) {
            m2.dependencyInterfaceIds.push(type(IPlugin).interfaceId);
        }

        m2.executionHooks.push(ManifestExecutionHook(selector, preHook, postHook));

        mockPlugin2 = new MockPlugin(m2);
        manifestHash2 = keccak256(abi.encode(mockPlugin2.pluginManifest()));

        if (expectSuccess) {
            vm.expectCall(address(mockPlugin2), abi.encodeCall(IPlugin.onInstall, (bytes(""))), 1);
            vm.expectEmit(true, true, true, true);
            emit PluginInstalled(address(mockPlugin2), manifestHash2, dependencies);
        }

        account1.installPlugin({
            plugin: address(mockPlugin2),
            manifestHash: manifestHash2,
            pluginInstallData: bytes(""),
            dependencies: dependencies
        });

        vm.stopPrank();
    }

    function _uninstallPlugin(MockPlugin plugin) internal {
        vm.expectCall(address(plugin), abi.encodeCall(IPlugin.onUninstall, (bytes(""))), 1);
        vm.expectEmit(true, true, true, true);
        emit PluginUninstalled(address(plugin), true);

        account1.uninstallPlugin(address(plugin), bytes(""), bytes(""));
    }
}
