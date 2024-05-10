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
import {FunctionReference} from "modular-account-libs/interfaces/IPluginManager.sol";
import {Call} from "modular-account-libs/interfaces/IStandardExecutor.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {UpgradeableModularAccount} from "../../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerModularAccountFactory} from "../../../src/factory/MultiOwnerModularAccountFactory.sol";
import {IEntryPoint} from "../../../src/interfaces/erc4337/IEntryPoint.sol";
import {IMultiOwnerPlugin} from "../../../src/plugins/owner/IMultiOwnerPlugin.sol";
import {MultiOwnerPlugin} from "../../../src/plugins/owner/MultiOwnerPlugin.sol";
import {Counter} from "../../mocks/Counter.sol";
import {Utils} from "../../Utils.sol";

contract MultiOwnerPluginIntegration is Test {
    using ECDSA for bytes32;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant _1271_MAGIC_VALUE_FAILURE = 0xffffffff;

    IEntryPoint public entryPoint;
    MultiOwnerPlugin public multiOwnerPlugin;
    MultiOwnerModularAccountFactory public factory;

    Counter public counter;
    address payable public beneficiary;
    address public user1;
    uint256 public user1Key;

    address public owner1;
    uint256 public owner1Key;
    UpgradeableModularAccount public account;

    address public owner2;
    uint256 public owner2Key;

    address[] public owners;

    function setUp() public {
        // setup dependencies and helper contract
        counter = new Counter();
        entryPoint = IEntryPoint(address(new EntryPoint()));
        beneficiary = payable(makeAddr("beneficiary"));
        (user1, user1Key) = makeAddrAndKey("user1");
        (owner1, owner1Key) = makeAddrAndKey("owner1");
        (owner2, owner2Key) = makeAddrAndKey("owner2");

        // setup plugins and factory
        multiOwnerPlugin = new MultiOwnerPlugin();
        factory = new MultiOwnerModularAccountFactory(
            address(this),
            address(multiOwnerPlugin),
            address(new UpgradeableModularAccount(IEntryPoint(address(entryPoint)))),
            keccak256(abi.encode(multiOwnerPlugin.pluginManifest())),
            entryPoint
        );

        // setup account with MultiOwnerModularAccountFactory
        owners = new address[](2);
        owners[0] = owner1 > owner2 ? owner2 : owner1;
        owners[1] = owner2 > owner1 ? owner2 : owner1;
        account = UpgradeableModularAccount(payable(factory.getAddress(0, owners)));
        vm.deal(address(account), 100 ether);
        factory.createAccount(0, owners);
    }

    function test_ownerPlugin_successInstallation() public {
        assertTrue(multiOwnerPlugin.isOwnerOf(address(account), owner1));
        assertTrue(multiOwnerPlugin.isOwnerOf(address(account), owner2));
        assertEq(Utils.reverseAddressArray(owners), multiOwnerPlugin.ownersOf(address(account)));
    }

    function test_runtimeValidation_alwaysAllow_isValidSignature() public {
        bytes32 digest = bytes32("digest");
        bytes32 messageDigest = multiOwnerPlugin.getMessageHash(address(account), abi.encode(digest));
        bytes memory signature;

        {
            // should fail for sig from owner1 due to wrongly encode message
            bytes32 messageDigestBad = keccak256(
                abi.encodePacked("\x19\x01", keccak256(abi.encode(user1, block.chainid)), abi.encode(digest))
            );
            (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(owner1Key, messageDigestBad);
            signature = abi.encodePacked(r0, s0, v0);
            assertEq(_1271_MAGIC_VALUE_FAILURE, IERC1271(address(account)).isValidSignature(digest, signature));
        }

        // should pass for sig from owner1
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, messageDigest);
        signature = abi.encodePacked(r, s, v);
        assertEq(_1271_MAGIC_VALUE, IERC1271(address(account)).isValidSignature(digest, signature));

        // should pass for sig from owner2
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(owner1Key, messageDigest);
        signature = abi.encodePacked(r1, s1, v1);
        assertEq(_1271_MAGIC_VALUE, IERC1271(address(account)).isValidSignature(digest, signature));

        // should fail for sig NOT from owner
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(user1Key, messageDigest);
        signature = abi.encodePacked(r2, s2, v2);
        assertEq(_1271_MAGIC_VALUE_FAILURE, IERC1271(address(account)).isValidSignature(digest, signature));
    }

    function test_runtimeValidation_ownerOrSelf_standardExecute() public {
        // should send 1 ETH to user1 by owner
        uint256 startBal = user1.balance;
        vm.startPrank(owner1);
        account.execute(user1, 1 ether, "");
        assertEq(1 ether, user1.balance - startBal);

        // should NOT send 1 ETH to user1 by non-owner
        startBal = user1.balance;
        vm.startPrank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.RuntimeValidationFunctionReverted.selector,
                multiOwnerPlugin,
                IMultiOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF,
                abi.encodeWithSelector(IMultiOwnerPlugin.NotAuthorized.selector)
            )
        );
        account.execute(user1, 1 ether, "");
        assertEq(0 ether, user1.balance - startBal);
    }

    function test_userOpValidation_owner_standardExecute() public {
        UserOperation memory userOp = UserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(account.execute, (user1, 1 ether, "")),
            callGasLimit: 50000,
            verificationGasLimit: 1200000,
            preVerificationGas: 0,
            maxFeePerGas: 1,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        // should send 1 ETH to user1 by owner
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);
        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;
        uint256 startBal = user1.balance;
        entryPoint.handleOps(userOps, beneficiary);
        assertEq(1 ether, user1.balance - startBal);

        // should NOT send 1 ETH to user1 by non-owner
        userOp.nonce++;
        bytes32 userOpHash2 = entryPoint.getUserOpHash(userOp);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(user1Key, userOpHash2.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r2, s2, v2);
        UserOperation[] memory userOps2 = new UserOperation[](1);
        userOps2[0] = userOp;
        startBal = user1.balance;
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entryPoint.handleOps(userOps2, beneficiary);
        assertEq(0 ether, user1.balance - startBal);
    }
}
