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
import {UserOperation} from "modular-account-libs/interfaces/UserOperation.sol";
import {
    IPlugin,
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
import {IMultiOwnerPlugin} from "../../src/plugins/owner/IMultiOwnerPlugin.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";
import {MockPlugin} from "../mocks/MockPlugin.sol";

contract UpgradeableModularAccountPreValidationHooksTest is Test {
    using ECDSA for bytes32;

    IEntryPoint public entryPoint;
    address payable public beneficiary;
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

    PluginManifest public m1;
    PluginManifest public m2;

    uint256 public constant CALL_GAS_LIMIT = 70000;
    uint256 public constant VERIFICATION_GAS_LIMIT = 1000000;

    event PluginInstalled(address indexed plugin, bytes32 manifestHash, FunctionReference[] dependencies);
    event PluginUninstalled(address indexed plugin, bool indexed onUninstallSucceeded);

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));
        multiOwnerPlugin = new MultiOwnerPlugin();

        (owner1, owner1Key) = makeAddrAndKey("owner1");
        beneficiary = payable(makeAddr("beneficiary"));
        vm.deal(beneficiary, 1 wei);

        address impl = address(new UpgradeableModularAccount(entryPoint));

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

    /// @dev Plugin 1 hook: 1
    ///      Plugin 2 hook: 2
    ///      Expected execution: [1, 2]
    function test_preRuntimeValidationHooks_install() public {
        vm.startPrank(owner1);

        _installPlugin1WithPreRuntimeValidationHook(
            _EXEC_SELECTOR,
            ManifestFunction({functionType: ManifestAssociatedFunctionType.SELF, functionId: 1, dependencyIndex: 0})
        );

        _installPlugin2WithPreRuntimeValidationHook(
            _EXEC_SELECTOR,
            ManifestFunction({functionType: ManifestAssociatedFunctionType.SELF, functionId: 2, dependencyIndex: 0}),
            new FunctionReference[](0)
        );

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook: 1
    ///      Plugin 2 hook: 2
    ///      Expected execution: [1, 2]
    function test_preRuntimeValidationHooks_run() public {
        test_preRuntimeValidationHooks_install();

        vm.startPrank(owner1);

        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preRuntimeValidationHook.selector,
                1,
                owner1, // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            1
        );

        vm.expectCall(
            address(mockPlugin2),
            abi.encodeWithSelector(
                IPlugin.preRuntimeValidationHook.selector,
                2,
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

    function testFuzz_preRuntimeValidationHooks_revert(bytes memory hookRevertReason) public {
        vm.startPrank(owner1);
        MockPlugin hookPlugin = _installPlugin1WithPreRuntimeValidationHook(
            _EXEC_SELECTOR,
            ManifestFunction({functionType: ManifestAssociatedFunctionType.SELF, functionId: 1, dependencyIndex: 0})
        );

        vm.mockCallRevert(
            address(hookPlugin),
            abi.encodeCall(
                IPlugin.preRuntimeValidationHook, (1, owner1, 0, abi.encodeWithSelector(_EXEC_SELECTOR))
            ),
            hookRevertReason
        );
        (bool success, bytes memory returnData) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);
        assertEq(
            returnData,
            abi.encodeWithSelector(
                UpgradeableModularAccount.PreRuntimeValidationHookFailed.selector,
                address(hookPlugin),
                1,
                hookRevertReason
            )
        );
        vm.stopPrank();
    }

    function test_preRuntimeValidationHooks_revertAlwaysDeny() public {
        vm.startPrank(owner1);

        _installPlugin1WithPreRuntimeValidationHook(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                functionId: 0,
                dependencyIndex: 0
            })
        );

        (bool success, bytes memory returnData) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);
        assertEq(returnData, abi.encodeWithSelector(UpgradeableModularAccount.AlwaysDenyRule.selector));

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook: 1
    ///      Plugin 2 hook: 2
    ///      Expected execution: [1, 2]
    function test_preRuntimeValidationHooks_uninstall() public {
        test_preRuntimeValidationHooks_install();

        vm.startPrank(owner1);

        // Uninstall the second plugin.
        _uninstallPlugin(mockPlugin2);

        // Expect hook 1 to exist, but not hook 2.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preRuntimeValidationHook.selector,
                1,
                owner1, // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin2),
            abi.encodeWithSelector(
                IPlugin.preRuntimeValidationHook.selector,
                2,
                owner1, // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            0
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

    /// Plugins cannot depend on hooks from other plugins.
    function test_overlappingPreRuntimeValidationHook_invalid() public {
        vm.startPrank(owner1);

        _installPlugin1WithPreRuntimeValidationHook(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                functionId: 0,
                dependencyIndex: 0
            })
        );

        FunctionReference[] memory dependencies = new FunctionReference[](1);
        dependencies[0] = FunctionReferenceLib.pack(address(mockPlugin1), 1);

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        this.installPlugin2WithpreRuntimeValidationHookNoSuccessCheck(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.DEPENDENCY,
                functionId: 0,
                dependencyIndex: 0
            }),
            dependencies
        );
    }

    function test_overlappingPreRuntimeValidationHookAlwaysDeny_install() public {
        vm.startPrank(owner1);

        _installPlugin1WithPreRuntimeValidationHook(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                functionId: 0,
                dependencyIndex: 0
            })
        );

        _installPlugin2WithPreRuntimeValidationHook(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                functionId: 0,
                dependencyIndex: 0
            }),
            new FunctionReference[](0)
        );

        vm.stopPrank();
    }

    function test_overlappingPreRuntimeValidationHookAlwaysDeny_revert() public {
        test_overlappingPreRuntimeValidationHookAlwaysDeny_install();

        vm.startPrank(owner1);

        (bool success, bytes memory returnData) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);
        assertEq(returnData, abi.encodeWithSelector(UpgradeableModularAccount.AlwaysDenyRule.selector));

        vm.stopPrank();
    }

    function test_overlappingPreRuntimeValidationHookAlwaysDeny_uninstallPlugin1() public {
        test_overlappingPreRuntimeValidationHookAlwaysDeny_install();

        vm.startPrank(owner1);

        _uninstallPlugin(mockPlugin1);

        // Execution selector should no longer exist.
        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);

        vm.stopPrank();
    }

    function test_overlappingPreRuntimeValidationHookAlwaysDeny_uninstallPlugin2() public {
        test_overlappingPreRuntimeValidationHookAlwaysDeny_install();

        vm.startPrank(owner1);

        _uninstallPlugin(mockPlugin2);

        (bool success, bytes memory returnData) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);
        assertEq(returnData, abi.encodeWithSelector(UpgradeableModularAccount.AlwaysDenyRule.selector));

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook: 1
    ///      Plugin 2 hook: 2
    ///      Expected execution: [1, 2]
    function test_preUserOpValidationHooks_install() public {
        vm.startPrank(owner1);

        _installPlugin1WithPreUserOpValidationHook(
            _EXEC_SELECTOR,
            ManifestFunction({functionType: ManifestAssociatedFunctionType.SELF, functionId: 1, dependencyIndex: 0})
        );

        _installPlugin2WithPreUserOpValidationHook(
            _EXEC_SELECTOR,
            ManifestFunction({functionType: ManifestAssociatedFunctionType.SELF, functionId: 2, dependencyIndex: 0}),
            new FunctionReference[](0)
        );

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook: 1
    ///      Plugin 2 hook: 2
    ///      Expected execution: [1, 2]
    function test_preUserOpValidationHooks_run() public {
        test_preUserOpValidationHooks_install();

        vm.startPrank(owner1);

        UserOperation memory userOp = UserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(_EXEC_SELECTOR),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(IPlugin.preUserOpValidationHook.selector, 1, userOp, userOpHash),
            1
        );

        vm.expectCall(
            address(mockPlugin2),
            abi.encodeWithSelector(IPlugin.preUserOpValidationHook.selector, 2, userOp, userOpHash),
            1
        );

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook: 1
    ///      Plugin 2 hook: 2
    ///      Expected execution: [1, 2]
    function test_preUserOpValidationHooks_uninstall() public {
        test_preUserOpValidationHooks_install();

        vm.startPrank(owner1);

        // Uninstall the second plugin.
        _uninstallPlugin(mockPlugin2);

        UserOperation memory userOp = UserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(_EXEC_SELECTOR),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        // Expect hook 1 to exist, but not hook 2.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(IPlugin.preUserOpValidationHook.selector, 1, userOp, userOpHash),
            1
        );
        vm.expectCall(
            address(mockPlugin2),
            abi.encodeWithSelector(IPlugin.preUserOpValidationHook.selector, 2, userOp, userOpHash),
            0
        );

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        // Uninstall the first plugin.
        _uninstallPlugin(mockPlugin1);

        vm.stopPrank();
    }

    function test_preUserOpValidationHooks_revertAlwaysDeny() public {
        vm.startPrank(owner1);

        _installPlugin1WithPreUserOpValidationHook(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                functionId: 0,
                dependencyIndex: 0
            })
        );

        vm.stopPrank();

        UserOperation memory userOp = UserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(_EXEC_SELECTOR),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        vm.startPrank(address(entryPoint));
        vm.expectRevert(UpgradeableModularAccount.AlwaysDenyRule.selector);
        account1.validateUserOp(userOp, userOpHash, 0);
    }

    function test_overlappingPreUserOpValidationHookAlwaysDeny_install() public {
        vm.startPrank(owner1);

        _installPlugin1WithPreUserOpValidationHook(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                functionId: 0,
                dependencyIndex: 0
            })
        );

        _installPlugin2WithPreUserOpValidationHook(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                functionId: 0,
                dependencyIndex: 0
            }),
            new FunctionReference[](0)
        );

        vm.stopPrank();
    }

    function _installPlugin1WithPreRuntimeValidationHook(bytes4 selector, ManifestFunction memory hook)
        internal
        returns (MockPlugin)
    {
        m1.preRuntimeValidationHooks.push(ManifestAssociatedFunction(selector, hook));

        mockPlugin1 = new MockPlugin(m1);
        manifestHash1 = keccak256(abi.encode(mockPlugin1.pluginManifest()));

        vm.expectCall(address(mockPlugin1), abi.encodeCall(IPlugin.onInstall, ("")), 1);
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

    function _installPlugin2WithPreRuntimeValidationHook(
        bytes4 selector,
        ManifestFunction memory hook,
        FunctionReference[] memory dependencies
    ) internal {
        _installPlugin2WithPreRuntimeValidationHookInternal(selector, hook, dependencies, true);
    }

    function installPlugin2WithpreRuntimeValidationHookNoSuccessCheck(
        bytes4 selector,
        ManifestFunction memory hook,
        FunctionReference[] memory dependencies
    ) external {
        _installPlugin2WithPreRuntimeValidationHookInternal(selector, hook, dependencies, false);
    }

    function _installPlugin2WithPreRuntimeValidationHookInternal(
        bytes4 selector,
        ManifestFunction memory hook,
        FunctionReference[] memory dependencies,
        bool expectSuccess
    ) internal {
        vm.startPrank(owner1);

        if (hook.functionType == ManifestAssociatedFunctionType.DEPENDENCY) {
            m2.dependencyInterfaceIds.push(type(IPlugin).interfaceId);
        }
        m2.preRuntimeValidationHooks.push(ManifestAssociatedFunction(selector, hook));

        mockPlugin2 = new MockPlugin(m2);
        manifestHash2 = keccak256(abi.encode(mockPlugin2.pluginManifest()));

        if (expectSuccess) {
            vm.expectCall(address(mockPlugin2), abi.encodeCall(IPlugin.onInstall, ("")), 1);
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

    function _installPlugin1WithPreUserOpValidationHook(bytes4 selector, ManifestFunction memory hook) internal {
        // Set up the user op validation function first.
        m1.dependencyInterfaceIds.push(type(IPlugin).interfaceId);
        FunctionReference[] memory dependencies = new FunctionReference[](1);
        dependencies[0] = FunctionReferenceLib.pack(
            address(multiOwnerPlugin), uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER)
        );
        m1.userOpValidationFunctions.push(
            ManifestAssociatedFunction({
                executionSelector: selector,
                associatedFunction: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.DEPENDENCY,
                    functionId: 0,
                    dependencyIndex: 0
                })
            })
        );

        m1.preUserOpValidationHooks.push(ManifestAssociatedFunction(selector, hook));

        mockPlugin1 = new MockPlugin(m1);
        manifestHash1 = keccak256(abi.encode(mockPlugin1.pluginManifest()));

        vm.expectCall(address(mockPlugin1), abi.encodeCall(IPlugin.onInstall, ("")), 1);
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(address(mockPlugin1), manifestHash1, dependencies);

        account1.installPlugin({
            plugin: address(mockPlugin1),
            manifestHash: manifestHash1,
            pluginInstallData: bytes(""),
            dependencies: dependencies
        });
    }

    function _installPlugin2WithPreUserOpValidationHook(
        bytes4 selector,
        ManifestFunction memory hook,
        FunctionReference[] memory dependencies
    ) internal {
        if (hook.functionType == ManifestAssociatedFunctionType.DEPENDENCY) {
            m2.dependencyInterfaceIds.push(type(IPlugin).interfaceId);
        }
        m2.preUserOpValidationHooks.push(ManifestAssociatedFunction(selector, hook));

        mockPlugin2 = new MockPlugin(m2);
        manifestHash2 = keccak256(abi.encode(mockPlugin2.pluginManifest()));

        vm.expectCall(address(mockPlugin2), abi.encodeCall(IPlugin.onInstall, ("")), 1);
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(address(mockPlugin2), manifestHash2, dependencies);

        account1.installPlugin({
            plugin: address(mockPlugin2),
            manifestHash: manifestHash2,
            pluginInstallData: bytes(""),
            dependencies: dependencies
        });
    }

    function _uninstallPlugin(MockPlugin plugin) internal {
        vm.expectCall(address(plugin), abi.encodeCall(IPlugin.onUninstall, ("")), 1);
        vm.expectEmit(true, true, true, true);
        emit PluginUninstalled(address(plugin), true);

        account1.uninstallPlugin(address(plugin), bytes(""), bytes(""));
    }
}
