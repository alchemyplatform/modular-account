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
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerModularAccountFactory} from "../../src/factory/MultiOwnerModularAccountFactory.sol";
import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";

contract MultiOwnerModularAccountFactoryTest is Test {
    using ECDSA for bytes32;

    EntryPoint public entryPoint;
    MultiOwnerModularAccountFactory public factory;
    MultiOwnerPlugin public multiOwnerPlugin;
    address public impl;

    address public notOwner = address(1);
    address public owner1 = address(2);
    address public owner2 = address(3);
    address public badImpl = address(4);

    address[] public owners;
    address[] public largeOwners;

    bytes32 internal constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    uint256 internal constant _MAX_OWNERS_ON_CREATION = 100;

    function setUp() public {
        owners.push(owner1);
        owners.push(owner2);
        entryPoint = new EntryPoint();
        impl = address(new UpgradeableModularAccount(IEntryPoint(address(entryPoint))));
        multiOwnerPlugin = new MultiOwnerPlugin();
        bytes32 manifestHash = keccak256(abi.encode(multiOwnerPlugin.pluginManifest()));
        factory = new MultiOwnerModularAccountFactory(
            address(this), address(multiOwnerPlugin), impl, manifestHash, IEntryPoint(address(entryPoint))
        );
        for (uint160 i = 0; i < _MAX_OWNERS_ON_CREATION; i++) {
            largeOwners.push(address(i + 1));
        }
        vm.deal(address(this), 100 ether);
    }

    function test_addressMatch() public {
        address predicted = factory.getAddress(0, owners);
        address deployed = factory.createAccount(0, owners);
        assertEq(predicted, deployed);
    }

    function test_deploy() public {
        address deployed = factory.createAccount(0, owners);

        // test that the deployed account is initialized
        assertEq(address(UpgradeableModularAccount(payable(deployed)).entryPoint()), address(entryPoint));

        // test that the deployed account installed owner plugin correctly
        address[] memory actualOwners = multiOwnerPlugin.ownersOf(deployed);
        assertEq(actualOwners.length, 2);
        assertEq(actualOwners[0], owner2);
        assertEq(actualOwners[1], owner1);
    }

    function test_deployCollision() public {
        address deployed = factory.createAccount(0, owners);

        uint256 gasStart = gasleft();

        // deploy 2nd time which should short circuit
        // test for short circuit -> call should cost less than a CREATE2, or 32000 gas
        address secondDeploy = factory.createAccount(0, owners);

        assertApproxEqAbs(gasleft(), gasStart, 31999);
        assertEq(deployed, secondDeploy);
    }

    function test_deployedAccountHasCorrectPlugins() public {
        address deployed = factory.createAccount(0, owners);

        // check installed plugins on account
        address[] memory plugins = UpgradeableModularAccount(payable(deployed)).getInstalledPlugins();
        assertEq(plugins.length, 1);
        assertEq(plugins[0], address(multiOwnerPlugin));
    }

    function test_badOwnersArray() public {
        vm.expectRevert(MultiOwnerModularAccountFactory.OwnersArrayEmpty.selector);
        factory.getAddress(0, new address[](0));

        address[] memory badOwners = new address[](2);

        vm.expectRevert(MultiOwnerModularAccountFactory.InvalidOwner.selector);
        factory.getAddress(0, badOwners);

        badOwners[0] = address(1);
        badOwners[1] = address(1);

        vm.expectRevert(MultiOwnerModularAccountFactory.InvalidOwner.selector);
        factory.getAddress(0, badOwners);
    }

    function test_addStake() public {
        assertEq(entryPoint.balanceOf(address(factory)), 0);
        vm.deal(address(this), 100 ether);
        factory.addStake{value: 10 ether}(10 hours, 10 ether);
        assertEq(entryPoint.getDepositInfo(address(factory)).stake, 10 ether);
    }

    function test_unlockStake() public {
        test_addStake();
        factory.unlockStake();
        assertEq(entryPoint.getDepositInfo(address(factory)).withdrawTime, block.timestamp + 10 hours);
    }

    function test_withdrawStake() public {
        test_unlockStake();
        vm.warp(10 hours);
        vm.expectRevert("Stake withdrawal is not due");
        factory.withdrawStake(payable(address(this)));
        assertEq(address(this).balance, 90 ether);
        vm.warp(10 hours + 1);
        factory.withdrawStake(payable(address(this)));
        assertEq(address(this).balance, 100 ether);
    }

    function test_withdraw() public {
        factory.addStake{value: 10 ether}(10 hours, 1 ether);
        assertEq(address(factory).balance, 9 ether);
        factory.withdraw(payable(address(this)), address(0), 0); // amount = balance if native currency
        assertEq(address(factory).balance, 0);
    }

    function test_2StepOwnershipTransfer() public {
        assertEq(factory.owner(), address(this));
        factory.transferOwnership(owner1);
        assertEq(factory.owner(), address(this));
        vm.prank(owner1);
        factory.acceptOwnership();
        assertEq(factory.owner(), owner1);
    }

    function test_getAddressWithMaxOwnersAndDeploy() public {
        address addr = factory.getAddress(0, largeOwners);
        assertEq(addr, factory.createAccount(0, largeOwners));
    }

    function test_getAddressWithTooManyOwners() public {
        largeOwners.push(address(101));
        vm.expectRevert(MultiOwnerModularAccountFactory.OwnersLimitExceeded.selector);
        factory.getAddress(0, largeOwners);
    }

    function test_getAddressWithUnsortedOwners() public {
        address[] memory tempOwners = new address[](2);
        tempOwners[0] = address(2);
        tempOwners[1] = address(1);
        vm.expectRevert(MultiOwnerModularAccountFactory.InvalidOwner.selector);
        factory.getAddress(0, tempOwners);
    }

    function test_deployWithDuplicateOwners() public {
        address[] memory tempOwners = new address[](2);
        tempOwners[0] = address(1);
        tempOwners[1] = address(1);
        vm.expectRevert(MultiOwnerModularAccountFactory.InvalidOwner.selector);
        factory.createAccount(0, tempOwners);
    }

    function test_deployWithUnsortedOwners() public {
        address[] memory tempOwners = new address[](2);
        tempOwners[0] = address(2);
        tempOwners[1] = address(1);
        vm.expectRevert(MultiOwnerModularAccountFactory.InvalidOwner.selector);
        factory.createAccount(0, tempOwners);
    }

    // to receive funds from withdraw
    receive() external payable {}
}
