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
import {IPaymaster} from "@eth-infinitism/account-abstraction/interfaces/IPaymaster.sol";
import {IAccountLoupe} from "modular-account-libs/interfaces/IAccountLoupe.sol";
import {PluginManifest} from "modular-account-libs/interfaces/IPlugin.sol";
import {IPlugin, PluginManifest} from "modular-account-libs/interfaces/IPlugin.sol";
import {FunctionReference, IPluginManager} from "modular-account-libs/interfaces/IPluginManager.sol";
import {IStandardExecutor} from "modular-account-libs/interfaces/IStandardExecutor.sol";
import {Call} from "modular-account-libs/interfaces/IStandardExecutor.sol";
import {FunctionReferenceLib} from "modular-account-libs/libraries/FunctionReferenceLib.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {PluginManagerInternals} from "../../src/account/PluginManagerInternals.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerModularAccountFactory} from "../../src/factory/MultiOwnerModularAccountFactory.sol";
import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";
import {IMultiOwnerPlugin} from "../../src/plugins/owner/IMultiOwnerPlugin.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";
import {SessionKeyPlugin} from "../../src/plugins/session/SessionKeyPlugin.sol";
import {Counter} from "../mocks/Counter.sol";
import {MockPlugin} from "../mocks/MockPlugin.sol";
import {
    CanChangeManifestPluginFactory, CanChangeManifestPlugin
} from "../mocks/plugins/ChangingManifestPlugin.sol";
import {ComprehensivePlugin} from "../mocks/plugins/ComprehensivePlugin.sol";
import {UninstallErrorsPlugin} from "../mocks/plugins/UninstallErrorsPlugin.sol";

contract UpgradeableModularAccountPluginManagerTest is Test {
    using ECDSA for bytes32;

    IEntryPoint public entryPoint;
    address payable public beneficiary;
    MultiOwnerPlugin public multiOwnerPlugin;
    SessionKeyPlugin public sessionKeyPlugin;
    MultiOwnerModularAccountFactory public factory;
    address public implementation;

    address public owner1;
    uint256 public owner1Key;
    UpgradeableModularAccount public account1;

    address public owner2;
    uint256 public owner2Key;
    UpgradeableModularAccount public account2;

    address[] public owners1;
    address[] public owners2;

    address public ethRecipient;
    Counter public counter;
    PluginManifest public manifest;

    uint256 public constant CALL_GAS_LIMIT = 500000;
    uint256 public constant VERIFICATION_GAS_LIMIT = 2000000;

    event PluginInstalled(address indexed plugin, bytes32 manifestHash, FunctionReference[] dependencies);
    event PluginUninstalled(address indexed plugin, bool indexed onUninstallSucceeded);
    event ReceivedCall(bytes msgData, uint256 msgValue);

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));
        (owner1, owner1Key) = makeAddrAndKey("owner1");
        beneficiary = payable(makeAddr("beneficiary"));
        vm.deal(beneficiary, 1 wei);

        multiOwnerPlugin = new MultiOwnerPlugin();
        sessionKeyPlugin = new SessionKeyPlugin();
        implementation = address(new UpgradeableModularAccount(entryPoint));
        bytes32 manifestHash = keccak256(abi.encode(multiOwnerPlugin.pluginManifest()));
        factory = new MultiOwnerModularAccountFactory(
            address(this), address(multiOwnerPlugin), implementation, manifestHash, entryPoint
        );

        // Compute counterfactual address
        owners1 = new address[](1);
        owners1[0] = owner1;
        account1 = UpgradeableModularAccount(payable(factory.getAddress(0, owners1)));
        vm.deal(address(account1), 100 ether);

        // Pre-deploy account two for different gas estimates
        (owner2, owner2Key) = makeAddrAndKey("owner2");
        owners2 = new address[](1);
        owners2[0] = owner2;
        account2 = UpgradeableModularAccount(payable(factory.createAccount(0, owners2)));
        vm.deal(address(account2), 100 ether);

        ethRecipient = makeAddr("ethRecipient");
        vm.deal(ethRecipient, 1 wei);
        counter = new Counter();
        counter.increment(); // amoritze away gas cost of zero->nonzero transition
    }

    function test_deployAccount() public {
        factory.createAccount(0, owners1);
    }

    function test_installPlugin_standard() public {
        vm.startPrank(owner2);

        bytes32 manifestHash = keccak256(abi.encode(sessionKeyPlugin.pluginManifest()));
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReferenceLib.pack(
            address(multiOwnerPlugin), uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER)
        );
        dependencies[1] = FunctionReferenceLib.pack(
            address(multiOwnerPlugin), uint8(IMultiOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        address[] memory sessionKeys = new address[](1);
        sessionKeys[0] = owner1;

        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(address(sessionKeyPlugin), manifestHash, dependencies);
        IPluginManager(account2).installPlugin({
            plugin: address(sessionKeyPlugin),
            manifestHash: manifestHash,
            pluginInstallData: abi.encode(
                sessionKeys, new bytes32[](sessionKeys.length), new bytes[][](sessionKeys.length)
            ),
            dependencies: dependencies
        });

        address[] memory plugins = IAccountLoupe(account2).getInstalledPlugins();
        assertEq(plugins.length, 2);
        assertEq(plugins[0], address(sessionKeyPlugin));
        assertEq(plugins[1], address(multiOwnerPlugin));
    }

    function test_installPlugin_ExecuteFromPlugin_PermittedExecSelectorNotInstalled() public {
        vm.startPrank(owner2);

        PluginManifest memory m;
        m.permittedExecutionSelectors = new bytes4[](1);
        m.permittedExecutionSelectors[0] = IPlugin.onInstall.selector;

        MockPlugin mockPluginWithBadPermittedExec = new MockPlugin(m);
        bytes32 manifestHash = keccak256(abi.encode(mockPluginWithBadPermittedExec.pluginManifest()));

        // This call should complete successfully, because we allow installation of plugins with non-existant
        // permitted call selectors.
        IPluginManager(account2).installPlugin({
            plugin: address(mockPluginWithBadPermittedExec),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    function test_installPlugin_invalidManifest() public {
        vm.startPrank(owner2);

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        IPluginManager(account2).installPlugin({
            plugin: address(sessionKeyPlugin),
            manifestHash: bytes32(0),
            pluginInstallData: abi.encode(owners1),
            dependencies: new FunctionReference[](0)
        });
    }

    function test_installPlugin_interfaceNotSupported() public {
        vm.startPrank(owner2);

        address badPlugin = address(1);
        vm.expectRevert(
            abi.encodeWithSelector(PluginManagerInternals.PluginInterfaceNotSupported.selector, address(badPlugin))
        );
        IPluginManager(account2).installPlugin({
            plugin: address(badPlugin),
            manifestHash: bytes32(0),
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    function test_installPlugin_alreadyInstalled() public {
        vm.startPrank(owner2);

        bytes32 manifestHash = keccak256(abi.encode(multiOwnerPlugin.pluginManifest()));

        vm.expectRevert(
            abi.encodeWithSelector(
                PluginManagerInternals.PluginAlreadyInstalled.selector, address(multiOwnerPlugin)
            )
        );
        IPluginManager(account2).installPlugin({
            plugin: address(multiOwnerPlugin),
            manifestHash: manifestHash,
            pluginInstallData: abi.encode(owners1),
            dependencies: new FunctionReference[](0)
        });
    }

    function test_installPlugin_failWithNativeFunctionSelector() public {
        vm.startPrank(owner2);

        PluginManifest memory manifestBad;
        manifestBad.executionFunctions = new bytes4[](1);
        manifestBad.executionFunctions[0] = IPluginManager.installPlugin.selector;
        MockPlugin mockPluginBad = new MockPlugin(manifestBad);
        bytes32 manifestHashBad = keccak256(abi.encode(mockPluginBad.pluginManifest()));

        vm.expectRevert(
            abi.encodeWithSelector(
                PluginManagerInternals.NativeFunctionNotAllowed.selector, IPluginManager.installPlugin.selector
            )
        );
        IPluginManager(account2).installPlugin({
            plugin: address(mockPluginBad),
            manifestHash: manifestHashBad,
            pluginInstallData: bytes(""),
            dependencies: new FunctionReference[](0)
        });
    }

    function test_installPlugin_failWithIPluginFunctionSelector() public {
        vm.startPrank(owner2);

        PluginManifest memory manifestBad;
        manifestBad.executionFunctions = new bytes4[](1);
        manifestBad.executionFunctions[0] = IPlugin.onInstall.selector;
        MockPlugin mockPluginBad = new MockPlugin(manifestBad);
        bytes32 manifestHashBad = keccak256(abi.encode(mockPluginBad.pluginManifest()));

        vm.expectRevert(
            abi.encodeWithSelector(
                PluginManagerInternals.IPluginFunctionNotAllowed.selector, IPlugin.onInstall.selector
            )
        );
        IPluginManager(account2).installPlugin({
            plugin: address(mockPluginBad),
            manifestHash: manifestHashBad,
            pluginInstallData: bytes(""),
            dependencies: new FunctionReference[](0)
        });
    }

    function test_installPlugin_failIfAddingIPluginInterfaceId() public {
        vm.startPrank(owner2);

        PluginManifest memory manifestBad;
        manifestBad.interfaceIds = new bytes4[](1);
        manifestBad.interfaceIds[0] = type(IPlugin).interfaceId;
        MockPlugin mockPluginBad = new MockPlugin(manifestBad);
        bytes32 manifestHashBad = keccak256(abi.encode(mockPluginBad.pluginManifest()));

        vm.expectRevert(PluginManagerInternals.InterfaceNotAllowed.selector);
        IPluginManager(account2).installPlugin({
            plugin: address(mockPluginBad),
            manifestHash: manifestHashBad,
            pluginInstallData: bytes(""),
            dependencies: new FunctionReference[](0)
        });
    }

    function test_installPlugin_failWtihErc4337FunctionSelector() public {
        vm.startPrank(owner2);

        PluginManifest memory manifestBad;
        manifestBad.executionFunctions = new bytes4[](1);
        manifestBad.executionFunctions[0] = IPaymaster.validatePaymasterUserOp.selector;
        MockPlugin mockPluginBad = new MockPlugin(manifestBad);
        bytes32 manifestHashBad = keccak256(abi.encode(mockPluginBad.pluginManifest()));

        vm.expectRevert(
            abi.encodeWithSelector(
                PluginManagerInternals.Erc4337FunctionNotAllowed.selector,
                IPaymaster.validatePaymasterUserOp.selector
            )
        );
        IPluginManager(account2).installPlugin({
            plugin: address(mockPluginBad),
            manifestHash: manifestHashBad,
            pluginInstallData: bytes(""),
            dependencies: new FunctionReference[](0)
        });
    }

    function test_installPlugin_missingDependency() public {
        vm.startPrank(owner2);

        manifest.dependencyInterfaceIds.push(type(IPlugin).interfaceId);
        MockPlugin newPlugin = new MockPlugin(manifest);
        bytes32 manifestHash = keccak256(abi.encode(newPlugin.pluginManifest()));

        // Add invalid function reference that points to the plugin being installed, rather than
        // an existing dependency.
        FunctionReference[] memory dependencies = new FunctionReference[](1);
        dependencies[0] = FunctionReferenceLib.pack(address(newPlugin), 0);
        vm.expectRevert(
            abi.encodeWithSelector(PluginManagerInternals.MissingPluginDependency.selector, address(newPlugin))
        );
        IPluginManager(account2).installPlugin({
            plugin: address(newPlugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: dependencies
        });

        // Add invalid function reference that points to a plugin that is not yet installed (and also is not the
        // one currently being installed).
        MockPlugin newPlugin2 = new MockPlugin(manifest);
        dependencies[0] = FunctionReferenceLib.pack(address(newPlugin2), 0);
        vm.expectRevert(
            abi.encodeWithSelector(PluginManagerInternals.MissingPluginDependency.selector, address(newPlugin2))
        );
        IPluginManager(account2).installPlugin({
            plugin: address(newPlugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: dependencies
        });
    }

    function test_uninstallPlugin_default() public {
        vm.startPrank(owner2);

        ComprehensivePlugin plugin = new ComprehensivePlugin();
        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));
        IPluginManager(account2).installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });

        vm.expectEmit(true, true, true, true);
        emit PluginUninstalled(address(plugin), true);
        IPluginManager(account2).uninstallPlugin({plugin: address(plugin), config: "", pluginUninstallData: ""});
        address[] memory plugins = IAccountLoupe(account2).getInstalledPlugins();
        assertEq(plugins.length, 1);
        assertEq(plugins[0], address(multiOwnerPlugin));
    }

    function test_uninstallPlugin_manifestParameter() public {
        vm.startPrank(owner2);

        ComprehensivePlugin plugin = new ComprehensivePlugin();
        bytes memory serializedManifest = abi.encode(plugin.pluginManifest());
        bytes32 manifestHash = keccak256(serializedManifest);
        IPluginManager(account2).installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });

        bytes memory config = abi.encode(
            UpgradeableModularAccount.UninstallPluginConfig({
                serializedManifest: serializedManifest,
                forceUninstall: false,
                callbackGasLimit: 0
            })
        );
        vm.expectEmit(true, true, true, true);
        emit PluginUninstalled(address(plugin), true);
        IPluginManager(account2).uninstallPlugin({plugin: address(plugin), config: config, pluginUninstallData: ""});
        address[] memory plugins = IAccountLoupe(account2).getInstalledPlugins();
        assertEq(plugins.length, 1);
        assertEq(plugins[0], address(multiOwnerPlugin));
    }

    function test_uninstallPlugin_invalidManifestFails() public {
        vm.startPrank(owner2);

        ComprehensivePlugin plugin = new ComprehensivePlugin();
        bytes memory serializedManifest = abi.encode(plugin.pluginManifest());
        bytes32 manifestHash = keccak256(serializedManifest);
        IPluginManager(account2).installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });

        // Attempt to uninstall with a blank manifest
        PluginManifest memory blankManifest;
        bytes memory config = abi.encode(
            UpgradeableModularAccount.UninstallPluginConfig({
                serializedManifest: abi.encode(blankManifest),
                forceUninstall: false,
                callbackGasLimit: 0
            })
        );

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        IPluginManager(account2).uninstallPlugin({plugin: address(plugin), config: config, pluginUninstallData: ""});

        // The forceUninstall flag doesn't let you succeed if your manifest is
        // wrong.
        config = abi.encode(
            UpgradeableModularAccount.UninstallPluginConfig({
                serializedManifest: abi.encode(blankManifest),
                forceUninstall: true,
                callbackGasLimit: 0
            })
        );

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        IPluginManager(account2).uninstallPlugin({plugin: address(plugin), config: config, pluginUninstallData: ""});

        address[] memory plugins = IAccountLoupe(account2).getInstalledPlugins();
        assertEq(plugins.length, 2);
        assertEq(plugins[0], address(plugin));
        assertEq(plugins[1], address(multiOwnerPlugin));
    }

    function test_uninstallPlugin_manifestHasChanged() public {
        vm.startPrank(owner2);

        CanChangeManifestPlugin plugin = new CanChangeManifestPluginFactory().newPlugin();
        bytes memory serializedManifest = abi.encode(plugin.pluginManifest());
        bytes32 manifestHash = keccak256(serializedManifest);
        IPluginManager(account2).installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });

        plugin.changeManifest();

        // Call an execution method which only appears in the initial manifest
        // to later check that it's been removed.
        CanChangeManifestPlugin(address(account2)).someExecutionFunction();

        // Default uninstall should fail because the manifest has changed.
        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        IPluginManager(account2).uninstallPlugin({plugin: address(plugin), config: "", pluginUninstallData: ""});

        // Uninstall should succeed with original manifest hash passed in
        bytes memory config = abi.encode(
            UpgradeableModularAccount.UninstallPluginConfig({
                serializedManifest: serializedManifest,
                forceUninstall: false,
                callbackGasLimit: 0
            })
        );
        vm.expectEmit(true, true, true, true);
        emit PluginUninstalled(address(plugin), true);
        IPluginManager(account2).uninstallPlugin({plugin: address(plugin), config: config, pluginUninstallData: ""});
        address[] memory plugins = IAccountLoupe(account2).getInstalledPlugins();
        assertEq(plugins.length, 1);
        assertEq(plugins[0], address(multiOwnerPlugin));

        // Check that the execution function which only appeared in the initial
        // manifest has been removed (i.e. the account didn't use the new
        // manifest for uninstallation despite being given the old one).
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.RuntimeValidationFunctionMissing.selector,
                CanChangeManifestPlugin.someExecutionFunction.selector
            )
        );
        CanChangeManifestPlugin(address(account2)).someExecutionFunction();
    }

    function test_forceOnUninstall() external {
        address plugin = _installPluginWithUninstallErrors(false);

        vm.expectRevert(
            abi.encodeWithSelector(
                PluginManagerInternals.PluginUninstallCallbackFailed.selector,
                plugin,
                abi.encodeWithSelector(UninstallErrorsPlugin.IntentionalUninstallError.selector)
            )
        );
        IPluginManager(account2).uninstallPlugin({plugin: plugin, config: "", pluginUninstallData: ""});

        bytes memory config = abi.encode(
            UpgradeableModularAccount.UninstallPluginConfig({
                serializedManifest: "",
                forceUninstall: true,
                callbackGasLimit: 0
            })
        );
        vm.expectEmit(true, true, true, true);
        emit PluginUninstalled(plugin, false);
        IPluginManager(account2).uninstallPlugin({plugin: plugin, config: config, pluginUninstallData: ""});
    }

    function test_onUninstallGasLimit() external {
        address plugin = _installPluginWithUninstallErrors(true);

        vm.expectRevert(
            abi.encodeWithSelector(PluginManagerInternals.PluginUninstallCallbackFailed.selector, plugin, "")
        );
        IPluginManager(account2).uninstallPlugin{gas: 100_000}({
            plugin: plugin,
            config: "",
            pluginUninstallData: ""
        });

        // Just `forceUninstall` isn't enough.
        bytes memory config = abi.encode(
            UpgradeableModularAccount.UninstallPluginConfig({
                serializedManifest: "",
                forceUninstall: true,
                callbackGasLimit: 0
            })
        );
        vm.expectRevert(bytes(""));
        IPluginManager(account2).uninstallPlugin{gas: 100_000}({
            plugin: plugin,
            config: config,
            pluginUninstallData: ""
        });

        config = abi.encode(
            UpgradeableModularAccount.UninstallPluginConfig({
                serializedManifest: "",
                forceUninstall: true,
                callbackGasLimit: 3000
            })
        );
        vm.expectEmit(true, true, true, true);
        emit PluginUninstalled(plugin, false);
        IPluginManager(account2).uninstallPlugin{gas: 100_000}({
            plugin: plugin,
            config: config,
            pluginUninstallData: ""
        });
    }

    function test_uninstallAndInstallInBatch() external {
        // Check that we can uninstall the `MultiOwnerPlugin`, leaving no
        // validator on `installPlugin`, and then install a different plugin
        // immediately after as part of the same batch execution. This is a
        // special case: normally an execution function with no runtime
        // validator cannot be runtime-called.
        vm.startPrank(owner2);

        ComprehensivePlugin plugin = new ComprehensivePlugin();
        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(account2),
            value: 0,
            data: abi.encodeCall(IPluginManager.uninstallPlugin, (address(multiOwnerPlugin), "", ""))
        });
        calls[1] = Call({
            target: address(account2),
            value: 0,
            data: abi.encodeCall(
                IPluginManager.installPlugin, (address(plugin), manifestHash, "", new FunctionReference[](0))
            )
        });
        vm.expectEmit(true, true, true, true);
        emit PluginUninstalled(address(multiOwnerPlugin), true);
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(address(plugin), manifestHash, new FunctionReference[](0));
        IStandardExecutor(account2).executeBatch(calls);
    }

    function test_uninstallAndInstallInBatch_failwithOtherCalls() external {
        // Test fail case for a special use case in `installPlugin`:
        // We can uninstall the `MultiOwnerPlugin`, leaving no validator on `installPlugin`, and then install a
        // different plugin immediately after as part of the same batch execution. This is a special case: normally
        // an execution function with no runtime validator cannot be runtime-called.
        // Here we test only the above is allowed, any other self-call is blocked

        vm.startPrank(owner2);

        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(account2),
            value: 0,
            data: abi.encodeCall(IPluginManager.uninstallPlugin, (address(multiOwnerPlugin), "", ""))
        });
        calls[1] = Call({
            target: address(account2),
            value: 0,
            data: abi.encodeCall(UpgradeableModularAccount.execute, (ethRecipient, 1 wei, ""))
        });

        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.RuntimeValidationFunctionMissing.selector,
                UpgradeableModularAccount.execute.selector
            )
        );
        IStandardExecutor(account2).executeBatch(calls);
    }

    function test_noNonSelfInstallAfterUninstall() external {
        // A companion to the previous test, ensuring that `installPlugin` can't
        // be called directly (e.g. not via `execute` or `executeBatch`) if it
        // has no validator.
        vm.startPrank(owner2);

        vm.expectEmit(true, true, true, true);
        emit PluginUninstalled(address(multiOwnerPlugin), true);
        account2.uninstallPlugin({plugin: address(multiOwnerPlugin), config: "", pluginUninstallData: ""});

        ComprehensivePlugin plugin = new ComprehensivePlugin();
        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.RuntimeValidationFunctionMissing.selector,
                IPluginManager.installPlugin.selector
            )
        );
        account2.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    // Internal Functions

    function _installPluginWithExecHooks() internal returns (MockPlugin plugin) {
        vm.startPrank(owner2);

        plugin = new MockPlugin(manifest);
        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        IPluginManager(account2).installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });

        vm.stopPrank();
    }

    function _installPluginWithUninstallErrors(bool shouldDrainGas) internal returns (address) {
        vm.startPrank(owner2);

        UninstallErrorsPlugin plugin = new UninstallErrorsPlugin(shouldDrainGas);
        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));
        IPluginManager(account2).installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
        return address(plugin);
    }

    function _installPluginWithHookUnapplyErrors(bool shouldDrainGas)
        internal
        returns (address pluginAddress, address hooksPluginAddress)
    {
        vm.startPrank(owner2);

        UninstallErrorsPlugin hooksPlugin = new UninstallErrorsPlugin(shouldDrainGas);
        IPluginManager(account2).installPlugin({
            plugin: address(hooksPlugin),
            manifestHash: keccak256(abi.encode(hooksPlugin.pluginManifest())),
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
        MockPlugin plugin = new MockPlugin(manifest);
        IPluginManager(account2).installPlugin({
            plugin: address(plugin),
            manifestHash: keccak256(abi.encode(plugin.pluginManifest())),
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
        return (address(plugin), address(hooksPlugin));
    }
}
