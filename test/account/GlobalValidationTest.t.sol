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

pragma solidity ^0.8.26;

import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract GlobalValidationTest is AccountTestBase {
    using MessageHashUtils for bytes32;

    address public ethRecipient;

    // A separate account and owner that isn't deployed yet, used to test initcode
    address public owner2;
    uint256 public owner2Key;
    ModularAccount public account2;

    function setUp() public override {
        _revertSnapshot = vm.snapshotState();
        (owner2, owner2Key) = makeAddrAndKey("owner2");

        // Compute counterfactual address
        account2 = ModularAccount(payable(factory.getAddress(owner2, 0, TEST_DEFAULT_VALIDATION_ENTITY_ID)));
        vm.deal(address(account2), 100 ether);

        _signerValidation =
            ModuleEntityLib.pack(address(singleSignerValidationModule), TEST_DEFAULT_VALIDATION_ENTITY_ID);

        ethRecipient = makeAddr("ethRecipient");
        vm.deal(ethRecipient, 1 wei);
    }

    function test_globalValidation_userOp_simple() public withSMATest {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account2),
            nonce: 0,
            initCode: abi.encodePacked(
                address(factory), abi.encodeCall(factory.createAccount, (owner2, 0, TEST_DEFAULT_VALIDATION_ENTITY_ID))
            ),
            callData: abi.encodeCall(ModularAccountBase.execute, (ethRecipient, 1 wei, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, userOpHash.toEthSignedMessageHash());
        userOp.signature =
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(ethRecipient.balance, 2 wei);
    }

    function test_globalValidation_runtime_simple() public withSMATest {
        // Deploy the account first
        factory.createAccount(owner2, 0, TEST_DEFAULT_VALIDATION_ENTITY_ID);

        vm.prank(owner2);
        account2.executeWithRuntimeValidation(
            abi.encodeCall(ModularAccountBase.execute, (ethRecipient, 1 wei, "")),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
        );

        assertEq(ethRecipient.balance, 2 wei);
    }

    function test_globalValidation_failsOnSelectorApplicability() public withSMATest {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account2),
            nonce: 0,
            initCode: abi.encodePacked(
                address(factory), abi.encodeCall(factory.createAccount, (owner2, 0, TEST_DEFAULT_VALIDATION_ENTITY_ID))
            ),
            callData: abi.encodeCall(ModularAccountBase.execute, (ethRecipient, 1 wei, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, userOpHash.toEthSignedMessageHash());
        // Use the wrong checking mode - SELECTOR_ASSOCIATED_VALIDATION
        userOp.signature = _encodeSignature(
            _signerValidation, SELECTOR_ASSOCIATED_VALIDATION, abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v)
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(
                    ModularAccountBase.ValidationFunctionMissing.selector, ModularAccountBase.execute.selector
                )
            )
        );
        entryPoint.handleOps(userOps, beneficiary);
    }
}
