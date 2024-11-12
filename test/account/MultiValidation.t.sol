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

import {IModularAccount, ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {ExecutionLib} from "../../src/libraries/ExecutionLib.sol";
import {SingleSignerValidationModule} from "../../src/modules/validation/SingleSignerValidationModule.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";
import {CODELESS_ADDRESS} from "../utils/TestConstants.sol";

contract MultiValidationTest is AccountTestBase {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    SingleSignerValidationModule public validator2;

    uint32 public constant ENTITY_ID_1 = 1;

    address public owner2;
    uint256 public owner2Key;

    function setUp() public override {
        validator2 = new SingleSignerValidationModule();

        (owner2, owner2Key) = makeAddrAndKey("owner2");
    }

    function test_overlappingValidationInstall() public withSMATest {
        vm.prank(address(entryPoint));
        account1.installValidation(
            ValidationConfigLib.pack(address(validator2), ENTITY_ID_1, true, true, true),
            new bytes4[](0),
            abi.encode(ENTITY_ID_1, owner2),
            new bytes[](0)
        );

        ModuleEntity[] memory validations = new ModuleEntity[](2);
        validations[0] = _signerValidation;
        validations[1] = ModuleEntityLib.pack(address(validator2), ENTITY_ID_1);

        bytes4[] memory selectors0 = account1.getValidationData(validations[0]).selectors;
        bytes4[] memory selectors1 = account1.getValidationData(validations[1]).selectors;
        assertEq(selectors0.length, selectors1.length);
        for (uint256 i = 0; i < selectors0.length; i++) {
            assertEq(selectors0[i], selectors1[i]);
        }
    }

    function test_runtimeValidation_specify() public withSMATest {
        test_overlappingValidationInstall();

        // Assert that the runtime validation can be specified.

        vm.prank(owner1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionLib.RuntimeValidationFunctionReverted.selector,
                ModuleEntityLib.pack(address(validator2), ENTITY_ID_1),
                abi.encodeWithSignature("NotAuthorized()")
            )
        );
        account1.executeWithRuntimeValidation(
            abi.encodeCall(IModularAccount.execute, (CODELESS_ADDRESS, 0, "")),
            _encodeSignature(ModuleEntityLib.pack(address(validator2), ENTITY_ID_1), GLOBAL_VALIDATION, "")
        );

        vm.prank(owner2);
        account1.executeWithRuntimeValidation(
            abi.encodeCall(IModularAccount.execute, (CODELESS_ADDRESS, 0, "")),
            _encodeSignature(ModuleEntityLib.pack(address(validator2), ENTITY_ID_1), GLOBAL_VALIDATION, "")
        );
    }

    function test_userOpValidation_specify() public withSMATest {
        test_overlappingValidationInstall();

        // Assert that the userOp validation can be specified.

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: _encodeNonce(ModuleEntityLib.pack(address(validator2), ENTITY_ID_1), GLOBAL_V, 0),
            initCode: "",
            callData: abi.encodeCall(ModularAccountBase.execute, (CODELESS_ADDRESS, 0, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = _encodeSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        // Sign with owner 1, expect fail

        userOp.nonce = _encodeNonce(ModuleEntityLib.pack(address(validator2), ENTITY_ID_1), GLOBAL_V, 1);
        userOpHash = entryPoint.getUserOpHash(userOp);
        (v, r, s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = _encodeSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        userOps[0] = userOp;
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entryPoint.handleOps(userOps, beneficiary);
    }
}
