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

import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {ExecutionLib} from "../../src/libraries/ExecutionLib.sol";
import {ModuleBase} from "../../src/modules/ModuleBase.sol";
import {PaymasterGuardModule} from "../../src/modules/permissions/PaymasterGuardModule.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract PaymasterGuardModuleTest is AccountTestBase {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    PaymasterGuardModule public module = new PaymasterGuardModule();

    address public account;
    address public paymaster1;
    address public paymaster2;
    uint32 public constant ENTITY_ID = TEST_DEFAULT_VALIDATION_ENTITY_ID;

    function setUp() public override {
        _revertSnapshot = vm.snapshotState();
        account = payable(makeAddr("account"));
        paymaster1 = payable(makeAddr("paymaster1"));
        paymaster2 = payable(makeAddr("paymaster2"));

        // setup account installed with a validation and paymaster guard hook
        bytes[] memory hooks = new bytes[](1);
        hooks[0] = abi.encodePacked(
            HookConfigLib.packValidationHook({_module: address(module), _entityId: ENTITY_ID}),
            abi.encode(ENTITY_ID, paymaster1)
        );
        vm.prank(address(account1));
        account1.installValidation(
            ValidationConfigLib.pack(address(singleSignerValidationModule), ENTITY_ID, true, true, true),
            new bytes4[](0),
            "",
            hooks
        );
    }

    // ------ Unit tests starts here ------

    function test_onInstall() public withSMATest {
        vm.prank(address(account));
        module.onInstall(abi.encode(ENTITY_ID, paymaster1));

        assertEq(paymaster1, module.paymasters(ENTITY_ID, account));
    }

    function test_onUninstall() public withSMATest {
        vm.prank(address(account));
        module.onUninstall(abi.encode(ENTITY_ID));

        assertEq(address(0), module.paymasters(ENTITY_ID, account));
    }

    function test_preUserOpValidationHook_success() public withSMATest {
        PackedUserOperation memory uo = _packUO(account, abi.encodePacked(paymaster1, ""));

        vm.startPrank(address(account));
        // install the right paymaster
        module.onInstall(abi.encode(ENTITY_ID, paymaster1));
        uint256 res = module.preUserOpValidationHook(ENTITY_ID, uo, bytes32(0));

        assertEq(res, 0);
        vm.stopPrank();
    }

    function test_preUserOpValidationHook_failWithInvalidData() public withSMATest {
        PackedUserOperation memory uo = _packUO(account, "");

        vm.startPrank(address(account));
        module.onInstall(abi.encode(ENTITY_ID, paymaster1));

        vm.expectRevert();
        module.preUserOpValidationHook(ENTITY_ID, uo, bytes32(0));
        vm.stopPrank();
    }

    function test_preUserOpValidationHook_failWithValidationData() public withSMATest {
        PackedUserOperation memory uo = _packUO(account, abi.encodePacked(paymaster1, ""));

        vm.startPrank(address(account));
        // install the right paymaster
        module.onInstall(abi.encode(ENTITY_ID, paymaster1));

        // Assert that it would succeed

        uint256 stateSnapshot = vm.snapshotState();

        uint256 res = module.preUserOpValidationHook(ENTITY_ID, uo, bytes32(0));

        assertEq(res, 0);

        vm.revertToState(stateSnapshot);

        // Now, test with validation hook data, and expect failure

        uo.signature = hex"1234";

        vm.expectRevert(abi.encodeWithSelector(ModuleBase.UnexpectedDataPassed.selector));
        module.preUserOpValidationHook(ENTITY_ID, uo, bytes32(0));
        vm.stopPrank();
    }

    function test_preUserOpValidationHook_fail() public withSMATest {
        PackedUserOperation memory uo = _packUO(account, abi.encodePacked(paymaster1, ""));

        vm.prank(address(account));
        // install the wrong paymaster
        module.onInstall(abi.encode(ENTITY_ID, paymaster2));

        vm.expectRevert(abi.encodeWithSelector(PaymasterGuardModule.BadPaymasterSpecified.selector));
        module.preUserOpValidationHook(ENTITY_ID, uo, bytes32(0));
    }

    function test_preRuntimeValidationHook_success() public withSMATest {
        vm.prank(address(account));

        module.preRuntimeValidationHook(ENTITY_ID, address(0), 0, "", "");
    }

    function _packUO(address accountAddr, bytes memory paymasterAndData)
        internal
        view
        returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: accountAddr,
            nonce: _encodeNonce(ModuleEntityLib.pack(address(singleSignerValidationModule), ENTITY_ID), GLOBAL_V, 0),
            initCode: "",
            callData: abi.encodePacked(
                ModularAccountBase.executeUserOp.selector, abi.encodeCall(account1.execute, (owner1, 0, hex""))
            ),
            accountGasLimits: bytes32(bytes16(uint128(200_000))) | bytes32(uint256(200_000)),
            preVerificationGas: 200_000,
            gasFees: bytes32(uint256(uint128(0))),
            paymasterAndData: paymasterAndData,
            signature: ""
        });
    }

    // ------ Unit tests ends here ------

    // ------ Integration tests ends here ------

    function test_install_i() public withSMATest {
        assertEq(paymaster1, module.paymasters(ENTITY_ID, address(account1)));
    }

    function test_userOp_success_i() public withSMATest {
        PackedUserOperation memory userOp = _packUO(address(account1), abi.encodePacked(paymaster1, ""));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = _encodeSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));
        vm.prank(address(entryPoint));
        account1.validateUserOp(userOp, userOpHash, 0);
    }

    function test_userOp_fail_i() public withSMATest {
        PackedUserOperation memory userOp = _packUO(address(account1), abi.encodePacked(paymaster2, ""));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = _encodeSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionLib.PreUserOpValidationHookReverted.selector,
                ModuleEntityLib.pack(address(module), ENTITY_ID),
                abi.encodeWithSelector(PaymasterGuardModule.BadPaymasterSpecified.selector)
            )
        );
        vm.prank(address(entryPoint));
        account1.validateUserOp(userOp, userOpHash, 0);
    }
}
