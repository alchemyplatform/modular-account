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

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerTokenReceiverMSCAFactory} from "../../src/factory/MultiOwnerTokenReceiverMSCAFactory.sol";
import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";
import {Call} from "../../src/interfaces/IStandardExecutor.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";
import {TokenReceiverPlugin} from "../../src/plugins/TokenReceiverPlugin.sol";
import {MockERC20} from "../mocks/tokens/MockERC20.sol";
import {Utils} from "../Utils.sol";

contract MSCAToMSCATest is Test {
    IEntryPoint public entryPoint;

    MockERC20 public token1;

    address[] public owners;
    UpgradeableModularAccount public msca;

    MultiOwnerPlugin public multiOwnerPlugin;
    TokenReceiverPlugin public tokenReceiverPlugin;
    address public mscaImpl1;
    address public mscaImpl2;

    event Upgraded(address indexed implementation);

    function setUp() public {
        owners.push(makeAddr("owner2"));
        owners.push(makeAddr("owner1"));
        entryPoint = IEntryPoint(address(new EntryPoint()));
        mscaImpl1 = address(new UpgradeableModularAccount(entryPoint));
        mscaImpl2 = address(new UpgradeableModularAccount(entryPoint));
        multiOwnerPlugin = new MultiOwnerPlugin();
        tokenReceiverPlugin = new TokenReceiverPlugin();
        bytes32 ownerManifestHash = keccak256(abi.encode(multiOwnerPlugin.pluginManifest()));
        bytes32 tokenReceiverManifestHash = keccak256(abi.encode(tokenReceiverPlugin.pluginManifest()));
        MultiOwnerTokenReceiverMSCAFactory factory = new MultiOwnerTokenReceiverMSCAFactory(
            address(this),
            address(multiOwnerPlugin),
            address(tokenReceiverPlugin),
            mscaImpl1,
            ownerManifestHash,
            tokenReceiverManifestHash,
            entryPoint
        );
        msca = UpgradeableModularAccount(payable(factory.createAccount(0, owners)));
        vm.deal(address(msca), 2 ether);

        // setup mock tokens
        token1 = new MockERC20("T1");
        token1.mint(address(msca), 1 ether);
    }

    function test_sameStorageSlot_upgradeToAndCall() public {
        vm.startPrank(owners[0]);

        // upgrade to mscaImpl2
        vm.expectEmit(true, true, true, true);
        emit Upgraded(mscaImpl2);
        msca.upgradeToAndCall(mscaImpl2, "");

        // verify account storage is the same
        (, bytes memory returnData) = address(multiOwnerPlugin).call(
            abi.encodeWithSelector(MultiOwnerPlugin.ownersOf.selector, address(msca))
        );
        address[] memory returnedOwners = abi.decode(returnData, (address[]));
        assertEq(Utils.reverseAddressArray(returnedOwners), owners);
        assertEq(token1.balanceOf(address(msca)), 1 ether);

        // verify can do basic transaction
        msca.execute(owners[0], 1 ether, "");
        assertEq(payable(msca).balance, 1 ether);
        assertEq(payable(owners[0]).balance, 1 ether);

        vm.stopPrank();
    }

    function test_sameStorageSlot_reinstallUpgradeToAndCall() public {
        vm.startPrank(owners[0]);

        Call[] memory calls = new Call[](2);
        calls[0] = Call(
            address(msca),
            0,
            abi.encodeCall(
                UpgradeableModularAccount.uninstallPlugin, (address(multiOwnerPlugin), bytes(""), bytes(""))
            )
        );

        calls[1] =
            Call(address(msca), 0, abi.encodeCall(UpgradeableModularAccount.upgradeToAndCall, (mscaImpl2, "")));

        emit Upgraded(mscaImpl2);
        // In practice, you would want upgradeToAndCall to call `initialize`.
        // But that fails when we use the same storage slot for both MSCAs
        // This test is still useful in proving that `upgradeToAndCall` succeeded with no installed plugins
        msca.executeBatch(calls);
    }
}
