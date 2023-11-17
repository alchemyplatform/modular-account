// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Test, console} from "forge-std/Test.sol";

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";

import {IPluginManager} from "../../src/interfaces/IPluginManager.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";
import {FunctionReference} from "../../src/libraries/FunctionReferenceLib.sol";

import {MultiOwnerMSCAFactory} from "../../src/factory/MultiOwnerMSCAFactory.sol";

import {Counter} from "../mocks/Counter.sol";
import {ResultCreatorPlugin} from "../mocks/plugins/ReturnDataPluginMocks.sol";

import {
    EFPCallerPlugin,
    EFPCallerPluginAnyExternal,
    EFPPermittedCallHookPlugin,
    EFPExternalPermittedCallHookPlugin
} from "../mocks/plugins/ExecFromPluginPermissionsMocks.sol";

contract ExecuteFromPluginPermissionsTest is Test {
    Counter public counter1;
    Counter public counter2;
    Counter public counter3;
    ResultCreatorPlugin public resultCreatorPlugin;

    IEntryPoint public entryPoint; // Just to be able to construct the factory
    MultiOwnerPlugin public multiOwnerPlugin;
    MultiOwnerMSCAFactory public factory;
    UpgradeableModularAccount public account;

    EFPCallerPlugin public efpCallerPlugin;
    EFPCallerPluginAnyExternal public efpCallerPluginAnyExternal;
    EFPPermittedCallHookPlugin public efpPermittedCallHookPlugin;
    EFPExternalPermittedCallHookPlugin public efpExternalPermittedCallHookPlugin;

    function setUp() public {
        // Initialize the interaction targets
        counter1 = new Counter();
        counter2 = new Counter();
        counter3 = new Counter();
        resultCreatorPlugin = new ResultCreatorPlugin();

        // Initialize the contracts needed to use the account.
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

        // Initialize the EFP caller plugins, which will attempt to use the permissions system to authorize calls.
        efpCallerPlugin = new EFPCallerPlugin();
        efpCallerPluginAnyExternal = new EFPCallerPluginAnyExternal();
        efpPermittedCallHookPlugin = new EFPPermittedCallHookPlugin();
        efpExternalPermittedCallHookPlugin = new EFPExternalPermittedCallHookPlugin();

        // Create an account with "this" as the owner, so we can execute along the runtime path with regular
        // solidity semantics
        address[] memory owners = new address[](1);
        owners[0] = address(this);
        account = UpgradeableModularAccount(payable(factory.createAccount(0, owners)));

        // Add the result creator plugin to the account
        bytes32 resultCreatorManifestHash = keccak256(abi.encode(resultCreatorPlugin.pluginManifest()));
        account.installPlugin({
            plugin: address(resultCreatorPlugin),
            manifestHash: resultCreatorManifestHash,
            pluginInitData: "",
            dependencies: new FunctionReference[](0),
            injectedHooks: new IPluginManager.InjectedHook[](0)
        });
        // Add the EFP caller plugin to the account
        bytes32 efpCallerManifestHash = keccak256(abi.encode(efpCallerPlugin.pluginManifest()));
        account.installPlugin({
            plugin: address(efpCallerPlugin),
            manifestHash: efpCallerManifestHash,
            pluginInitData: "",
            dependencies: new FunctionReference[](0),
            injectedHooks: new IPluginManager.InjectedHook[](0)
        });

        // Add the EFP caller plugin with any external permissions to the account
        bytes32 efpCallerAnyExternalManifestHash =
            keccak256(abi.encode(efpCallerPluginAnyExternal.pluginManifest()));
        account.installPlugin({
            plugin: address(efpCallerPluginAnyExternal),
            manifestHash: efpCallerAnyExternalManifestHash,
            pluginInitData: "",
            dependencies: new FunctionReference[](0),
            injectedHooks: new IPluginManager.InjectedHook[](0)
        });

        // Add the EFP caller plugin with permitted call hooks to the account
        bytes32 efpPermittedCallHookManifestHash =
            keccak256(abi.encode(efpPermittedCallHookPlugin.pluginManifest()));
        account.installPlugin({
            plugin: address(efpPermittedCallHookPlugin),
            manifestHash: efpPermittedCallHookManifestHash,
            pluginInitData: "",
            dependencies: new FunctionReference[](0),
            injectedHooks: new IPluginManager.InjectedHook[](0)
        });

        // Add the EFP caller plugin with an external permitted call hook to the account
        bytes32 efpExternalPermittedCallHookManifestHash =
            keccak256(abi.encode(efpExternalPermittedCallHookPlugin.pluginManifest()));
        account.installPlugin({
            plugin: address(efpExternalPermittedCallHookPlugin),
            manifestHash: efpExternalPermittedCallHookManifestHash,
            pluginInitData: "",
            dependencies: new FunctionReference[](0),
            injectedHooks: new IPluginManager.InjectedHook[](0)
        });
    }

    // Report the addresses to be used in the address constants in ExecFromPluginPermissionsMocks.sol
    function test_getPermissionsTestAddresses() public view {
        // solhint-disable no-console
        console.log("counter1 address: %s", address(counter1));
        console.log("counter2 address: %s", address(counter2));
        console.log("counter3 address: %s", address(counter3));
        console.log("resultCreatorPlugin address: %s", address(resultCreatorPlugin));
        // solhint-enable no-console
    }

    function test_executeFromPluginAllowed() public {
        bytes memory result = EFPCallerPlugin(address(account)).useEFPPermissionAllowed();
        bytes32 actual = abi.decode(result, (bytes32));

        assertEq(actual, keccak256("bar"));
    }

    function test_executeFromPluginNotAllowed() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.ExecFromPluginNotPermitted.selector,
                address(efpCallerPlugin),
                ResultCreatorPlugin.bar.selector
            )
        );
        EFPCallerPlugin(address(account)).useEFPPermissionNotAllowed();
    }

    function test_executeFromPluginExternal_Allowed_IndividualSelectors() public {
        EFPCallerPlugin(address(account)).setNumberCounter1(17);
        uint256 retrievedNumber = EFPCallerPlugin(address(account)).getNumberCounter1();

        assertEq(retrievedNumber, 17);
    }

    function test_executeFromPluginExternal_NotAlowed_IndividualSelectors() public {
        EFPCallerPlugin(address(account)).setNumberCounter1(17);

        // Call to increment should fail
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.ExecFromPluginExternalNotPermitted.selector,
                address(efpCallerPlugin),
                address(counter1),
                0,
                abi.encodePacked(Counter.increment.selector)
            )
        );
        EFPCallerPlugin(address(account)).incrementCounter1();

        uint256 retrievedNumber = EFPCallerPlugin(address(account)).getNumberCounter1();

        assertEq(retrievedNumber, 17);
    }

    function test_executeFromPluginExternal_Allowed_AllSelectors() public {
        EFPCallerPlugin(address(account)).setNumberCounter2(17);
        EFPCallerPlugin(address(account)).incrementCounter2();
        uint256 retrievedNumber = EFPCallerPlugin(address(account)).getNumberCounter2();

        assertEq(retrievedNumber, 18);
    }

    function test_executeFromPluginExternal_NotAllowed_AllSelectors() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.ExecFromPluginExternalNotPermitted.selector,
                address(efpCallerPlugin),
                address(counter3),
                0,
                abi.encodeWithSelector(Counter.setNumber.selector, uint256(17))
            )
        );
        EFPCallerPlugin(address(account)).setNumberCounter3(17);

        // Call to increment should fail
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.ExecFromPluginExternalNotPermitted.selector,
                address(efpCallerPlugin),
                address(counter3),
                0,
                abi.encodePacked(Counter.increment.selector)
            )
        );
        EFPCallerPlugin(address(account)).incrementCounter3();

        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.ExecFromPluginExternalNotPermitted.selector,
                address(efpCallerPlugin),
                address(counter3),
                0,
                abi.encodePacked(bytes4(keccak256("number()")))
            )
        );
        EFPCallerPlugin(address(account)).getNumberCounter3();

        // Validate no state changes
        assert(counter3.number() == 0);
    }

    function test_executeFromPluginExternal_Allowed_AnyContract() public {
        // Run full workflow for counter 1

        EFPCallerPluginAnyExternal(address(account)).passthroughExecute(
            address(counter1), 0, abi.encodeCall(Counter.setNumber, (17))
        );
        uint256 retrievedNumber = counter1.number();
        assertEq(retrievedNumber, 17);

        EFPCallerPluginAnyExternal(address(account)).passthroughExecute(
            address(counter1), 0, abi.encodeCall(Counter.increment, ())
        );
        retrievedNumber = counter1.number();
        assertEq(retrievedNumber, 18);

        bytes memory result = EFPCallerPluginAnyExternal(address(account)).passthroughExecute(
            address(counter1), 0, abi.encodePacked(bytes4(keccak256("number()")))
        );
        retrievedNumber = abi.decode(result, (uint256));
        assertEq(retrievedNumber, 18);

        // Run full workflow for counter 2

        EFPCallerPluginAnyExternal(address(account)).passthroughExecute(
            address(counter2), 0, abi.encodeCall(Counter.setNumber, (17))
        );
        retrievedNumber = counter2.number();
        assertEq(retrievedNumber, 17);

        EFPCallerPluginAnyExternal(address(account)).passthroughExecute(
            address(counter2), 0, abi.encodeCall(Counter.increment, ())
        );
        retrievedNumber = counter2.number();
        assertEq(retrievedNumber, 18);

        result = EFPCallerPluginAnyExternal(address(account)).passthroughExecute(
            address(counter2), 0, abi.encodePacked(bytes4(keccak256("number()")))
        );
        retrievedNumber = abi.decode(result, (uint256));
        assertEq(retrievedNumber, 18);
    }

    function test_executeFromPlugin_PermittedCallHooks() public {
        assertFalse(efpPermittedCallHookPlugin.preExecHookCalled());
        assertFalse(efpPermittedCallHookPlugin.postExecHookCalled());

        bytes memory result = EFPPermittedCallHookPlugin(address(account)).performEFPCall();

        bytes32 actual = abi.decode(result, (bytes32));

        assertEq(actual, keccak256("bar"));

        assertTrue(efpPermittedCallHookPlugin.preExecHookCalled());
        assertTrue(efpPermittedCallHookPlugin.postExecHookCalled());
    }

    function test_executeFromPluginExternal_PermittedCallHooks() public {
        counter1.setNumber(17);

        assertFalse(efpExternalPermittedCallHookPlugin.preExecHookCalled());
        assertFalse(efpExternalPermittedCallHookPlugin.postExecHookCalled());

        EFPExternalPermittedCallHookPlugin(address(account)).performIncrement();

        assertTrue(efpExternalPermittedCallHookPlugin.preExecHookCalled());
        assertTrue(efpExternalPermittedCallHookPlugin.postExecHookCalled());

        uint256 retrievedNumber = counter1.number();
        assertEq(retrievedNumber, 18);
    }
}
