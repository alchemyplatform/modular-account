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
import {FunctionReference} from "modular-account-libs/interfaces/IPluginManager.sol";
import {Call} from "modular-account-libs/interfaces/IStandardExecutor.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerModularAccountFactory} from "../../src/factory/MultiOwnerModularAccountFactory.sol";
import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";
import {
    RegularResultContract,
    ResultCreatorPlugin,
    ResultConsumerPlugin
} from "../mocks/plugins/ReturnDataPluginMocks.sol";

// Tests all the different ways that return data can be read from plugins through an account
contract AccountReturnDataTest is Test {
    IEntryPoint public entryPoint; // Just to be able to construct the factory
    MultiOwnerPlugin public multiOwnerPlugin;
    MultiOwnerModularAccountFactory public factory;

    RegularResultContract public regularResultContract;
    ResultCreatorPlugin public resultCreatorPlugin;
    ResultConsumerPlugin public resultConsumerPlugin;

    UpgradeableModularAccount public account;

    function setUp() public {
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

        regularResultContract = new RegularResultContract();
        resultCreatorPlugin = new ResultCreatorPlugin();
        resultConsumerPlugin = new ResultConsumerPlugin(resultCreatorPlugin, regularResultContract);

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
        // Add the result consumer plugin to the account
        bytes32 resultConsumerManifestHash = keccak256(abi.encode(resultConsumerPlugin.pluginManifest()));
        account.installPlugin({
            plugin: address(resultConsumerPlugin),
            manifestHash: resultConsumerManifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    // Tests the ability to read the result of plugin execution functions via the account's fallback
    function test_returnData_fallback() public {
        bytes32 result = ResultCreatorPlugin(address(account)).foo();

        assertEq(result, keccak256("bar"));
    }

    // Tests the ability to read the results of contracts called via IStandardExecutor.execute
    function test_returnData_singular_execute() public {
        bytes memory returnData =
            account.execute(address(regularResultContract), 0, abi.encodeCall(RegularResultContract.foo, ()));

        bytes32 result = abi.decode(returnData, (bytes32));

        assertEq(result, keccak256("bar"));
    }

    // Tests the ability to read the results of multiple contract calls via IStandardExecutor.executeBatch
    function test_returnData_executeBatch() public {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(regularResultContract),
            value: 0,
            data: abi.encodeCall(RegularResultContract.foo, ())
        });
        calls[1] = Call({
            target: address(regularResultContract),
            value: 0,
            data: abi.encodeCall(RegularResultContract.bar, ())
        });

        bytes[] memory returnDatas = account.executeBatch(calls);

        bytes32 result1 = abi.decode(returnDatas[0], (bytes32));
        bytes32 result2 = abi.decode(returnDatas[1], (bytes32));

        assertEq(result1, keccak256("bar"));
        assertEq(result2, keccak256("foo"));
    }

    // Tests the ability to read data via executeFromPlugin routing to fallback functions
    function test_returnData_execFromPlugin_fallback() public {
        bool result = ResultConsumerPlugin(address(account)).checkResultEFPFallback(keccak256("bar"));

        assertTrue(result);
    }

    // Tests the ability to read data via executeFromPluginExternal
    function test_returnData_execFromPlugin_execute() public {
        bool result = ResultConsumerPlugin(address(account)).checkResultEFPExternal(
            address(regularResultContract), keccak256("bar")
        );

        assertTrue(result);
    }
}
