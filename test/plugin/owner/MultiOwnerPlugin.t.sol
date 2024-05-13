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
import {UserOperation} from "modular-account-libs/interfaces/UserOperation.sol";
import {PluginManifest} from "modular-account-libs/interfaces/IPlugin.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {IEntryPoint} from "../../../src/interfaces/erc4337/IEntryPoint.sol";
import {BasePlugin} from "../../../src/plugins/BasePlugin.sol";
import {IMultiOwnerPlugin} from "../../../src/plugins/owner/IMultiOwnerPlugin.sol";
import {MultiOwnerPlugin} from "../../../src/plugins/owner/MultiOwnerPlugin.sol";
import {ContractOwner} from "../../mocks/ContractOwner.sol";
import {Utils} from "../../Utils.sol";

contract MultiOwnerPluginTest is Test {
    using ECDSA for bytes32;

    MultiOwnerPlugin public plugin;
    IEntryPoint public entryPoint;

    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    address public accountA;
    address public b;

    address public owner1;
    address public owner2;
    address public owner3;
    address public ownerofContractOwner;
    uint256 public ownerofContractOwnerKey;
    ContractOwner public contractOwner;
    address[] public ownerArray;

    // Re-declare events for vm.expectEmit
    event OwnerUpdated(address indexed account, address[] addedOwners, address[] removedOwners);

    function setUp() public {
        plugin = new MultiOwnerPlugin();
        entryPoint = IEntryPoint(address(new EntryPoint()));

        accountA = address(new EntryPoint());
        b = makeAddr("b");
        owner1 = makeAddr("owner1");
        owner2 = makeAddr("owner2");
        owner3 = makeAddr("owner3");
        (ownerofContractOwner, ownerofContractOwnerKey) = makeAddrAndKey("ownerofContractOwner");
        contractOwner = new ContractOwner(ownerofContractOwner);

        // set up owners for accountA
        ownerArray = new address[](3);
        ownerArray[0] = owner2;
        ownerArray[1] = owner3;
        ownerArray[2] = owner1;

        vm.expectEmit(true, true, true, true);
        emit OwnerUpdated(accountA, ownerArray, new address[](0));
        vm.startPrank(accountA);
        plugin.onInstall(abi.encode(ownerArray));
    }

    function test_pluginManifest() public {
        PluginManifest memory manifest = plugin.pluginManifest();
        // 3 execution functions
        assertEq(3, manifest.executionFunctions.length);
        // 5 native + 1 plugin exec func
        assertEq(6, manifest.userOpValidationFunctions.length);
        // 5 native + 1 plugin exec func + 2 plugin view func
        assertEq(8, manifest.runtimeValidationFunctions.length);
    }

    function test_onUninstall_success() public {
        // Populate the expected event using `plugin.ownersOf` instead of `ownerArray` to reverse the order of
        // owners.
        vm.expectEmit(true, true, true, true);
        emit OwnerUpdated(accountA, new address[](0), plugin.ownersOf(accountA));

        plugin.onUninstall(abi.encode(""));
        address[] memory returnedOwners = plugin.ownersOf(accountA);
        assertEq(0, returnedOwners.length);
    }

    function test_onInstall_success() public {
        address[] memory owners = new address[](1);
        owners[0] = owner1;

        vm.startPrank(address(contractOwner));
        plugin.onInstall(abi.encode(owners));
        address[] memory returnedOwners = plugin.ownersOf(address(contractOwner));
        assertEq(returnedOwners.length, 1);
        assertEq(returnedOwners[0], owner1);
        vm.stopPrank();
    }

    function test_eip712Domain() public {
        assertEq(true, plugin.isOwnerOf(accountA, owner2));
        assertEq(false, plugin.isOwnerOf(accountA, address(contractOwner)));

        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        ) = plugin.eip712Domain();
        assertEq(fields, hex"1f");
        assertEq(name, "Multi Owner Plugin");
        assertEq(version, "1.0.0");
        assertEq(chainId, block.chainid);
        assertEq(verifyingContract, accountA);
        assertEq(salt, bytes32(bytes20(address(plugin))));
        assertEq(extensions.length, 0);
    }

    function test_updateOwners_failWithEmptyOwners() public {
        vm.expectRevert(IMultiOwnerPlugin.EmptyOwnersNotAllowed.selector);
        plugin.updateOwners(new address[](0), ownerArray);
    }

    function test_updateOwners_failWithZeroAddressOwner() public {
        address[] memory ownersToAdd = new address[](2);

        vm.expectRevert(abi.encodeWithSelector(IMultiOwnerPlugin.InvalidOwner.selector, address(0)));
        plugin.updateOwners(ownersToAdd, new address[](0));
    }

    function test_updateOwners_failWithDuplicatedAddresses() public {
        address[] memory ownersToAdd = new address[](2);
        ownersToAdd[0] = ownerofContractOwner;
        ownersToAdd[1] = ownerofContractOwner;

        vm.expectRevert(abi.encodeWithSelector(IMultiOwnerPlugin.InvalidOwner.selector, ownerofContractOwner));
        plugin.updateOwners(ownersToAdd, new address[](0));
    }

    function test_updateOwners_success() public {
        (address[] memory owners) = plugin.ownersOf(accountA);
        assertEq(Utils.reverseAddressArray(ownerArray), owners);

        // remove should also work
        address[] memory ownersToRemove = new address[](2);
        ownersToRemove[0] = owner1;
        ownersToRemove[1] = owner2;

        vm.expectEmit(true, true, true, true);
        emit OwnerUpdated(accountA, new address[](0), ownersToRemove);

        plugin.updateOwners(new address[](0), ownersToRemove);

        (address[] memory newOwnerList) = plugin.ownersOf(accountA);
        assertEq(newOwnerList.length, 1);
        assertEq(newOwnerList[0], owner3);
    }

    function test_updateOwners_failWithNotExist() public {
        address[] memory ownersToRemove = new address[](1);
        ownersToRemove[0] = address(contractOwner);

        vm.expectRevert(
            abi.encodeWithSelector(IMultiOwnerPlugin.OwnerDoesNotExist.selector, address(contractOwner))
        );
        plugin.updateOwners(new address[](0), ownersToRemove);
    }

    function testFuzz_isValidSignature_EOAOwner(string memory salt, bytes32 digest) public {
        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey(salt);
        bytes32 messageDigest = plugin.getMessageHash(address(accountA), abi.encode(digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageDigest);

        address[] memory ownersToAdd = new address[](1);
        ownersToAdd[0] = signer;

        if (!plugin.isOwnerOf(accountA, signer)) {
            // sig check should fail
            assertEq(bytes4(0xFFFFFFFF), plugin.isValidSignature(digest, abi.encodePacked(r, s, v)));

            plugin.updateOwners(ownersToAdd, new address[](0));
        }

        // sig check should pass
        assertEq(_1271_MAGIC_VALUE, plugin.isValidSignature(digest, abi.encodePacked(r, s, v)));
    }

    function testFuzz_isValidSignature_ContractOwner(bytes32 digest) public {
        address[] memory ownersToAdd = new address[](1);
        ownersToAdd[0] = address(contractOwner);
        plugin.updateOwners(ownersToAdd, new address[](0));

        bytes32 messageDigest = plugin.getMessageHash(address(accountA), abi.encode(digest));
        bytes memory signature = contractOwner.sign(messageDigest);
        assertEq(_1271_MAGIC_VALUE, plugin.isValidSignature(digest, signature));
    }

    function testFuzz_isValidSignature_ContractOwnerWithEOAOwner(bytes32 digest) public {
        address[] memory ownersToAdd = new address[](1);
        ownersToAdd[0] = address(contractOwner);
        plugin.updateOwners(ownersToAdd, new address[](0));

        bytes32 messageDigest = plugin.getMessageHash(address(accountA), abi.encode(digest));
        // owner3 is the EOA Owner of the contractOwner
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerofContractOwnerKey, messageDigest);
        bytes memory signature = abi.encodePacked(r, s, v);
        assertEq(_1271_MAGIC_VALUE, plugin.isValidSignature(digest, signature));
    }

    function test_runtimeValidationFunction_OwnerOrSelf() public {
        // should pass with owner as sender
        plugin.runtimeValidationFunction(
            uint8(IMultiOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF), owner1, 0, ""
        );

        // should fail without owner as sender
        vm.expectRevert(IMultiOwnerPlugin.NotAuthorized.selector);
        plugin.runtimeValidationFunction(
            uint8(IMultiOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF), address(contractOwner), 0, ""
        );
    }

    function test_multiOwnerPlugin_sentinelIsNotOwner() public {
        assertFalse(plugin.isOwnerOf(accountA, address(1)));
    }

    function testFuzz_userOpValidationFunction_ContractOwner(UserOperation memory userOp) public {
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        userOp.signature = contractOwner.sign(userOpHash);

        // should fail without owner access
        uint256 resFail = plugin.userOpValidationFunction(
            uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
        );
        assertEq(resFail, 1);

        address[] memory ownersToAdd = new address[](1);
        ownersToAdd[0] = address(contractOwner);
        plugin.updateOwners(ownersToAdd, new address[](0));

        // should pass with owner access
        uint256 resSuccess = plugin.userOpValidationFunction(
            uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
        );
        assertEq(resSuccess, 0);
    }

    function testFuzz_userOpValidationFunction_ContractOwnerWithEOAOwner(UserOperation memory userOp) public {
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerofContractOwnerKey, userOpHash);

        // sig cannot cover the whole userop struct since userop struct has sig field
        userOp.signature = abi.encodePacked(r, s, v);

        // should fail without owner access
        uint256 resFail = plugin.userOpValidationFunction(
            uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
        );
        assertEq(resFail, 1);

        address[] memory ownersToAdd = new address[](1);
        ownersToAdd[0] = address(contractOwner);
        plugin.updateOwners(ownersToAdd, new address[](0));

        // should pass with owner access
        uint256 resSuccess = plugin.userOpValidationFunction(
            uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
        );
        assertEq(resSuccess, 0);
    }

    function testFuzz_userOpValidationFunction_EOAOwner(string memory salt, UserOperation memory userOp) public {
        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey(salt);
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash.toEthSignedMessageHash());

        // sig cannot cover the whole userop struct since userop struct has sig field
        userOp.signature = abi.encodePacked(r, s, v);

        address[] memory ownersToAdd = new address[](1);
        ownersToAdd[0] = signer;

        // Only check that the signature should fail if the signer is not already an owner
        if (!plugin.isOwnerOf(accountA, signer)) {
            // should fail without owner access
            uint256 resFail = plugin.userOpValidationFunction(
                uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
            );
            assertEq(resFail, 1);
            // add signer to owner
            plugin.updateOwners(ownersToAdd, new address[](0));
        }

        // should pass with owner access
        uint256 resSuccess = plugin.userOpValidationFunction(
            uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
        );
        assertEq(resSuccess, 0);
    }

    function test_pluginInitializeGuards() public {
        plugin.onUninstall(bytes(""));

        address[] memory addrArr = new address[](1);
        addrArr[0] = address(this);

        // can't transfer owner if not initialized yet
        vm.expectRevert(abi.encodeWithSelector(BasePlugin.NotInitialized.selector));
        plugin.updateOwners(addrArr, new address[](0));

        // can't oninstall twice
        plugin.onInstall(abi.encode(addrArr, new address[](0)));
        vm.expectRevert(abi.encodeWithSelector(BasePlugin.AlreadyInitialized.selector));
        plugin.onInstall(abi.encode(addrArr, new address[](0)));
    }
}
