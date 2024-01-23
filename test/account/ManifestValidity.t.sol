// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {Test} from "forge-std/Test.sol";

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {PluginManagerInternals} from "../../src/account/PluginManagerInternals.sol";
import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";
import {FunctionReference} from "../../src/interfaces/IPluginManager.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";

import {MultiOwnerMSCAFactory} from "../../src/factory/MultiOwnerMSCAFactory.sol";
import {
    BadValidationMagicValue_UserOp_Plugin,
    BadValidationMagicValue_PreRuntimeValidationHook_Plugin,
    BadValidationMagicValue_PreUserOpValidationHook_Plugin,
    BadValidationMagicValue_PreExecHook_Plugin,
    BadValidationMagicValue_PostExecHook_Plugin,
    BadHookMagicValue_UserOpValidationFunction_Plugin,
    BadHookMagicValue_RuntimeValidationFunction_Plugin,
    BadHookMagicValue_PostExecHook_Plugin
} from "../mocks/plugins/ManifestValidityMocks.sol";

contract ManifestValidityTest is Test {
    IEntryPoint public entryPoint; // Just to be able to construct the factory
    MultiOwnerPlugin public multiOwnerPlugin;
    MultiOwnerMSCAFactory public factory;

    UpgradeableModularAccount public account;

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));
        multiOwnerPlugin = new MultiOwnerPlugin();
        address impl = address(new UpgradeableModularAccount(entryPoint));

        factory = new MultiOwnerMSCAFactory(
            address(this),
            address(multiOwnerPlugin),
            impl,
            keccak256(abi.encode(multiOwnerPlugin.pluginManifest())),
            entryPoint
        );

        // Create an account with "this" as the owner, so we can execute along the runtime path with regular
        // solidity semantics
        address[] memory owners = new address[](1);
        owners[0] = address(this);
        account = UpgradeableModularAccount(payable(factory.createAccount(0, owners)));
    }

    // Tests that the plugin manager rejects a plugin with a user op validationFunction set to "validation always
    // allow"
    function test_ManifestValidity_invalid_ValidationAlwaysAllow_UserOpValidationFunction() public {
        BadValidationMagicValue_UserOp_Plugin plugin = new BadValidationMagicValue_UserOp_Plugin();

        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        account.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInitData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    // Tests that the plugin manager rejects a plugin with a pre-runtime validation hook set to "validation always
    // allow"
    function test_ManifestValidity_invalid_ValidationAlwaysAllow_PreRuntimeValidationHook() public {
        BadValidationMagicValue_PreRuntimeValidationHook_Plugin plugin =
            new BadValidationMagicValue_PreRuntimeValidationHook_Plugin();

        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        account.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInitData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    // Tests that the plugin manager rejects a plugin with a pre-user op validation hook set to "validation always
    // allow"
    function test_ManifestValidity_invalid_ValidationAlwaysAllow_PreUserOpValidationHook() public {
        BadValidationMagicValue_PreUserOpValidationHook_Plugin plugin =
            new BadValidationMagicValue_PreUserOpValidationHook_Plugin();

        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        account.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInitData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    // Tests that the plugin manager rejects a plugin with a pre-execution hook set to "validation always allow"
    function test_ManifestValidity_invalid_ValidationAlwaysAllow_PreExecHook() public {
        BadValidationMagicValue_PreExecHook_Plugin plugin = new BadValidationMagicValue_PreExecHook_Plugin();

        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        account.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInitData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    // Tests that the plugin manager rejects a plugin with a post-execution hook set to "validation always allow"
    function test_ManifestValidity_invalid_ValidationAlwaysAllow_PostExecHook() public {
        BadValidationMagicValue_PostExecHook_Plugin plugin = new BadValidationMagicValue_PostExecHook_Plugin();

        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        account.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInitData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    // Tests that the plugin manager rejects a plugin with a user op validationFunction set to "hook always deny"
    function test_ManifestValidity_invalid_HookAlwaysDeny_UserOpValidation() public {
        BadHookMagicValue_UserOpValidationFunction_Plugin plugin =
            new BadHookMagicValue_UserOpValidationFunction_Plugin();

        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        account.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInitData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    // Tests that the plugin manager rejects a plugin with a runtime validationFunction set to "hook always deny"
    function test_ManifestValidity_invalid_HookAlwaysDeny_RuntimeValidationFunction() public {
        BadHookMagicValue_RuntimeValidationFunction_Plugin plugin =
            new BadHookMagicValue_RuntimeValidationFunction_Plugin();

        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        account.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInitData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    // Tests that the plugin manager rejects a plugin with a post-execution hook set to "hook always deny"
    function test_ManifestValidity_invalid_HookAlwaysDeny_PostExecHook() public {
        BadHookMagicValue_PostExecHook_Plugin plugin = new BadHookMagicValue_PostExecHook_Plugin();

        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        account.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInitData: "",
            dependencies: new FunctionReference[](0)
        });
    }
}
