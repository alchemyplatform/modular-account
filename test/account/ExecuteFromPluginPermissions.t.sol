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

import {Test, console} from "forge-std/Test.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {IPlugin} from "modular-account-libs/interfaces/IPlugin.sol";
import {FunctionReference} from "modular-account-libs/interfaces/IPluginManager.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerModularAccountFactory} from "../../src/factory/MultiOwnerModularAccountFactory.sol";
import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";
import {Counter} from "../mocks/Counter.sol";
import {
    EFPCallerPlugin,
    EFPCallerPluginAnyExternal,
    EFPCallerPluginAnyExternalCanSpendNativeToken,
    EFPExecutionHookPlugin
} from "../mocks/plugins/ExecFromPluginPermissionsMocks.sol";
import {ResultCreatorPlugin} from "../mocks/plugins/ReturnDataPluginMocks.sol";

contract ExecuteFromPluginPermissionsTest is Test {
    Counter public counter1;
    Counter public counter2;
    Counter public counter3;
    ResultCreatorPlugin public resultCreatorPlugin;

    IEntryPoint public entryPoint; // Just to be able to construct the factory
    MultiOwnerPlugin public multiOwnerPlugin;
    MultiOwnerModularAccountFactory public factory;
    UpgradeableModularAccount public account;

    EFPCallerPlugin public efpCallerPlugin;
    EFPCallerPluginAnyExternal public efpCallerPluginAnyExternal;
    EFPCallerPluginAnyExternalCanSpendNativeToken public efpCallerPluginAnyExternalCanSpendNativeToken;
    EFPExecutionHookPlugin public efpExecutionHookPlugin;

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

        factory = new MultiOwnerModularAccountFactory(
            address(this),
            address(multiOwnerPlugin),
            impl,
            keccak256(abi.encode(multiOwnerPlugin.pluginManifest())),
            entryPoint
        );

        // Initialize the EFP caller plugins, which will attempt to use the permissions system to authorize calls.
        efpCallerPlugin = new EFPCallerPlugin();
        efpCallerPluginAnyExternal = new EFPCallerPluginAnyExternal();
        efpCallerPluginAnyExternalCanSpendNativeToken = new EFPCallerPluginAnyExternalCanSpendNativeToken();
        efpExecutionHookPlugin = new EFPExecutionHookPlugin();

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
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
        // Add the EFP caller plugin to the account
        bytes32 efpCallerManifestHash = keccak256(abi.encode(efpCallerPlugin.pluginManifest()));
        account.installPlugin({
            plugin: address(efpCallerPlugin),
            manifestHash: efpCallerManifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });

        // Add the EFP caller plugin with any external permissions to the account
        bytes32 efpCallerAnyExternalManifestHash =
            keccak256(abi.encode(efpCallerPluginAnyExternal.pluginManifest()));
        account.installPlugin({
            plugin: address(efpCallerPluginAnyExternal),
            manifestHash: efpCallerAnyExternalManifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });

        // Add the EFP caller plugin with any external permissions and native token spend permission to the account
        bytes32 efpCallerAnyExternalCanSpendNativeTokenManifestHash =
            keccak256(abi.encode(efpCallerPluginAnyExternalCanSpendNativeToken.pluginManifest()));
        account.installPlugin({
            plugin: address(efpCallerPluginAnyExternalCanSpendNativeToken),
            manifestHash: efpCallerAnyExternalCanSpendNativeTokenManifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });

        // Add the EFP caller plugin with execution hooks to the account
        bytes32 efpExecutionHookPluginManifestHash = keccak256(abi.encode(efpExecutionHookPlugin.pluginManifest()));
        account.installPlugin({
            plugin: address(efpExecutionHookPlugin),
            manifestHash: efpExecutionHookPluginManifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
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

    function test_executeFromPluginUnrecognizedFunction() public {
        // Permitted but uninstalled selector
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.UnrecognizedFunction.selector, bytes4(keccak256("baz()"))
            )
        );
        EFPCallerPlugin(address(account)).passthroughExecuteFromPlugin(
            abi.encodeWithSelector(bytes4(keccak256("baz()")))
        );

        // Invalid selector < 4 bytes
        vm.expectRevert(
            abi.encodeWithSelector(UpgradeableModularAccount.UnrecognizedFunction.selector, bytes4(hex"11"))
        );
        EFPCallerPlugin(address(account)).passthroughExecuteFromPlugin(hex"11");
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

    function test_executeFromPluginExternal_Allowed_AnyContractButSelf() public {
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

        // Should fail to call account self
        bytes memory encodedCall =
            abi.encodeCall(UpgradeableModularAccount.upgradeToAndCall, (address(efpCallerPlugin), ""));
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.ExecFromPluginExternalNotPermitted.selector,
                address(efpCallerPluginAnyExternal),
                address(account),
                0,
                encodedCall
            )
        );
        EFPCallerPluginAnyExternal(address(account)).passthroughExecute(address(account), 0, encodedCall);
    }

    function test_executeFromPluginExternal_NotAllowed_NativeTokenSpending() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.NativeTokenSpendingNotPermitted.selector,
                address(efpCallerPluginAnyExternal)
            )
        );
        EFPCallerPluginAnyExternal(address(account)).passthroughExecute(address(counter1), 1 ether, "");

        address recipient = makeAddr("recipient");
        vm.deal(address(efpCallerPluginAnyExternal), 1 ether);
        // This function forwards 1 eth from the plugin to the account and tries to send 2 eth to the recipient.
        // This is not allowed because there would be a net decrease of the balance on the account.
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.NativeTokenSpendingNotPermitted.selector,
                address(efpCallerPluginAnyExternal)
            )
        );
        EFPCallerPluginAnyExternal(address(account)).passthroughExecuteWith1Eth(address(recipient), 2 ether, "");
    }

    function test_executeFromPluginExternal_Allowed_NativeTokenSpending() public {
        address recipient = makeAddr("recipient");

        vm.deal(address(efpCallerPluginAnyExternal), 1 ether);
        assertEq(address(recipient).balance, 0);
        // This function forwards 1 eth from the plugin to the account and sends 1 eth to the recipient. This is
        // allowed because there is no net change to the balance on the account.
        EFPCallerPluginAnyExternal(address(account)).passthroughExecuteWith1Eth(address(recipient), 1 ether, "");
        assertEq(address(efpCallerPluginAnyExternal).balance, 0);
        assertEq(address(recipient).balance, 1 ether);

        vm.deal(address(account), 1 ether);
        EFPCallerPluginAnyExternalCanSpendNativeToken(address(account))
            .passthroughExecuteWithNativeTokenSpendPermission(address(recipient), 1 ether, "");
        assertEq(address(recipient).balance, 2 ether);
    }

    function test_executeFromPlugin_ExecutionHooks() public {
        // Expect the pre hook to be called just once.
        vm.expectCall(
            address(efpExecutionHookPlugin),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                1,
                address(efpExecutionHookPlugin), // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(ResultCreatorPlugin.foo.selector)
            ),
            1
        );
        // Expect the post hook to be called twice, with the expected data.
        vm.expectCall(
            address(efpExecutionHookPlugin),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                2,
                abi.encode(1) // preExecHookData
            ),
            1
        );
        vm.expectCall(
            address(efpExecutionHookPlugin),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                2,
                "" // preExecHookData (none for this post only hook)
            ),
            1
        );
        EFPExecutionHookPlugin(address(account)).performEFPCallWithExecHooks();
    }
}
