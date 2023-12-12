// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {MultiOwnerMSCAFactory} from "../../src/factory/MultiOwnerMSCAFactory.sol";
import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";

contract MultiOwnerMSCAFactoryTest is Test {
    using ECDSA for bytes32;

    EntryPoint public entryPoint;
    MultiOwnerMSCAFactory public factory;
    MultiOwnerPlugin public multiOwnerPlugin;
    address public impl;

    address public notOwner = address(1);
    address public owner1 = address(2);
    address public owner2 = address(3);
    address public badImpl = address(4);

    address[] public owners;

    bytes32 internal constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function setUp() public {
        owners.push(owner1);
        owners.push(owner2);
        entryPoint = new EntryPoint();
        impl = address(new UpgradeableModularAccount(IEntryPoint(address(entryPoint))));
        multiOwnerPlugin = new MultiOwnerPlugin();
        bytes32 manifestHash = keccak256(abi.encode(multiOwnerPlugin.pluginManifest()));
        factory = new MultiOwnerMSCAFactory(
            address(this), address(multiOwnerPlugin), impl, manifestHash, IEntryPoint(address(entryPoint))
        );
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
        vm.expectRevert(MultiOwnerMSCAFactory.OwnersArrayEmpty.selector);
        factory.createAccount(0, new address[](0));

        address[] memory badOwners = new address[](2);

        vm.expectRevert(MultiOwnerMSCAFactory.ZeroAddressOwner.selector);
        factory.createAccount(0, badOwners);

        badOwners[0] = address(1);
        badOwners[1] = address(1);

        vm.expectRevert(MultiOwnerMSCAFactory.DuplicateOwner.selector);
        factory.createAccount(0, badOwners);
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

    // to receive funds from withdraw
    receive() external payable {}
}
