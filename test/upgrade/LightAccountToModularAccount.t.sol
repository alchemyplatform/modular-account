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
import {LightAccount} from "@alchemy/light-account/src/LightAccount.sol";
import {LightAccountFactory} from "@alchemy/light-account/src/LightAccountFactory.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {IEntryPoint as I4337EntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";
import {MockERC20} from "../mocks/tokens/MockERC20.sol";

contract LightAccountToModularAccountTest is Test {
    I4337EntryPoint public entryPoint;
    IEntryPoint public maEntryPoint;

    MockERC20 public token1;

    address public owner;
    address[] public owners;
    LightAccount public lightAccount;

    MultiOwnerPlugin public multiOwnerPlugin;
    address public maImpl;

    event ModularAccountInitialized(IEntryPoint indexed entryPoint);

    function setUp() public {
        entryPoint = I4337EntryPoint(address(new EntryPoint()));
        maEntryPoint = IEntryPoint(address(entryPoint));
        (owner,) = makeAddrAndKey("owner");

        // set up light account
        LightAccountFactory lightAccountFactory = new LightAccountFactory(entryPoint);
        lightAccount = lightAccountFactory.createAccount(owner, 1);
        vm.deal(address(lightAccount), 2 ether);

        // setup mock tokens
        token1 = new MockERC20("T1");
        token1.mint(address(lightAccount), 1 ether);

        // setup modular account
        multiOwnerPlugin = new MultiOwnerPlugin();
        maImpl = address(new UpgradeableModularAccount(maEntryPoint));
    }

    function test_verifySetup() public {
        assertEq(token1.balanceOf(address(lightAccount)), 1 ether);
        assertEq(token1.balanceOf(owner), 0 ether);

        address[] memory returnedOwners = multiOwnerPlugin.ownersOf(address(lightAccount));
        assertEq(returnedOwners, new address[](0));
        assertEq(payable(lightAccount).balance, 2 ether);
        assertEq(payable(owner).balance, 0);
    }

    function test_upgrade() public {
        // setup data for modular account upgrade
        owners = new address[](1);
        owners[0] = owner;
        address[] memory plugins = new address[](1);
        plugins[0] = address(multiOwnerPlugin);
        bytes32[] memory manifestHashes = new bytes32[](1);
        manifestHashes[0] = keccak256(abi.encode(multiOwnerPlugin.pluginManifest()));
        bytes[] memory pluginInitBytes = new bytes[](1);
        pluginInitBytes[0] = abi.encode(owners);

        // upgrade to modular account
        vm.startPrank(owner);
        vm.expectEmit(true, true, true, true);
        emit ModularAccountInitialized(maEntryPoint);
        lightAccount.upgradeToAndCall(
            maImpl,
            abi.encodeCall(
                UpgradeableModularAccount.initialize, (plugins, abi.encode(manifestHashes, pluginInitBytes))
            )
        );

        // verify upgrade success
        address[] memory returnedOwners = multiOwnerPlugin.ownersOf(address(lightAccount));
        assertEq(returnedOwners, owners);
        assertEq(token1.balanceOf(address(lightAccount)), 1 ether);

        // verify can do basic transaction
        lightAccount.execute(owner, 1 ether, "");
        assertEq(payable(lightAccount).balance, 1 ether);
        assertEq(payable(owner).balance, 1 ether);
    }
}
