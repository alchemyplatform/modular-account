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
import {SimpleAccount} from "@eth-infinitism/account-abstraction/samples/SimpleAccount.sol";
import {SimpleAccountFactory} from "@eth-infinitism/account-abstraction/samples/SimpleAccountFactory.sol";
import {UserOperation} from "modular-account-libs/interfaces/UserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";
import {Counter} from "../mocks/Counter.sol";

contract CompareSimpleAccountTest is Test {
    using ECDSA for bytes32;

    IEntryPoint public entryPoint;
    address payable public beneficiary;

    SimpleAccountFactory public factory;

    // Owner 1 deploys account contract in the same transaction
    address public owner1;
    uint256 public owner1Key;
    address public account1;

    // owner 2 pre-deploys account contract
    address public owner2;
    uint256 public owner2Key;
    address public account2;

    Counter public counter;

    function setUp() public {
        EntryPoint ep = new EntryPoint();
        entryPoint = IEntryPoint(address(ep));
        (owner1, owner1Key) = makeAddrAndKey("owner1");
        beneficiary = payable(makeAddr("beneficiary"));
        vm.deal(beneficiary, 1 wei);

        factory = new SimpleAccountFactory(ep);
        account1 = factory.getAddress(owner1, 0);
        vm.deal(account1, 100 ether);

        counter = new Counter();
        counter.increment();

        // Pre-generate account 2
        (owner2, owner2Key) = makeAddrAndKey("owner2");
        account2 = address(factory.createAccount(owner2, 0));
        vm.deal(account2, 100 ether);
        vm.prank(account2);
        entryPoint.depositTo{value: 1 wei}(account2);
    }

    function test_SimpleAccount_deploy_basicSend() public {
        UserOperation memory userOp = UserOperation({
            sender: account1,
            nonce: 0,
            initCode: abi.encodePacked(address(factory), abi.encodeCall(factory.createAccount, (owner1, 0))),
            callData: abi.encodeCall(SimpleAccount.execute, (beneficiary, 1, "")),
            callGasLimit: 5000000,
            verificationGasLimit: 5000000,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_SimpleAccount_deploy_empty() public {
        UserOperation memory userOp = UserOperation({
            sender: account1,
            nonce: 0,
            initCode: abi.encodePacked(address(factory), abi.encodeCall(factory.createAccount, (owner1, 0))),
            callData: "",
            callGasLimit: 5000000,
            verificationGasLimit: 5000000,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_SimpleAccount_postDeploy_basicSend() public {
        UserOperation memory userOp = UserOperation({
            sender: account2,
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(SimpleAccount.execute, (beneficiary, 1, "")),
            callGasLimit: 5000000,
            verificationGasLimit: 5000000,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_SimpleAccount_postDeploy_contractInteraction() public {
        UserOperation memory userOp = UserOperation({
            sender: account2,
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(
                SimpleAccount.execute, (address(counter), 0, abi.encodeCall(Counter.increment, ()))
            ),
            callGasLimit: 5000000,
            verificationGasLimit: 5000000,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(counter.number(), 2);
    }
}
