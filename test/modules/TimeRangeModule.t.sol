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

import {ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {
    HookConfig, ValidationDataView
} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {_packValidationData} from "@eth-infinitism/account-abstraction/core/Helpers.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {ExecutionLib} from "../../src/libraries/ExecutionLib.sol";
import {ModuleBase} from "../../src/modules/ModuleBase.sol";
import {TimeRangeModule} from "../../src/modules/permissions/TimeRangeModule.sol";

import {CustomValidationTestBase} from "../utils/CustomValidationTestBase.sol";

contract TimeRangeModuleTest is CustomValidationTestBase {
    TimeRangeModule public timeRangeModule;

    uint32 public constant HOOK_ENTITY_ID = 0;

    HookConfig internal _hookEntity;

    uint48 public validUntil;
    uint48 public validAfter;

    function setUp() public override {
        _signerValidation =
            ModuleEntityLib.pack(address(singleSignerValidationModule), TEST_DEFAULT_VALIDATION_ENTITY_ID);

        timeRangeModule = new TimeRangeModule();

        _hookEntity = HookConfigLib.packValidationHook(address(timeRangeModule), HOOK_ENTITY_ID);
    }

    function test_timeRangeModule_moduleId() public view {
        assertEq(timeRangeModule.moduleId(), "alchemy.time-range-module.1.0.0");
    }

    function test_timeRangeModule_install() public withSMATest {
        validUntil = 1000;
        validAfter = 100;

        _customValidationSetup();

        // Verify that it is installed
        ValidationDataView memory validationData = account1.getValidationData(_signerValidation);

        assertTrue(validationData.isGlobal);
        assertTrue(validationData.isSignatureValidation);
        assertTrue(validationData.isUserOpValidation);

        assertEq(validationData.validationHooks.length, 1);
        assertEq(HookConfig.unwrap(validationData.validationHooks[0]), HookConfig.unwrap(_hookEntity));

        assertEq(validationData.executionHooks.length, 0);
        assertEq(validationData.selectors.length, 0);

        // Verify that the time range is set
        (uint48 retrievedValidUntil, uint48 retrievedValidAfter) =
            timeRangeModule.timeRanges(HOOK_ENTITY_ID, address(account1));
        assertEq(retrievedValidUntil, validUntil);
        assertEq(retrievedValidAfter, validAfter);
    }

    function test_timeRangeModule_uninstall() public withSMATest {
        test_timeRangeModule_install();

        // Uninstall the module
        bytes[] memory hookUninstallDatas = new bytes[](1);
        hookUninstallDatas[0] = abi.encode(HOOK_ENTITY_ID);

        vm.expectCall({
            callee: address(timeRangeModule),
            data: abi.encodeCall(TimeRangeModule.onUninstall, (hookUninstallDatas[0]))
        });
        vm.prank(address(account1));
        account1.uninstallValidation(_signerValidation, "", hookUninstallDatas);

        // Verify that the time range data is unset
        (uint48 retrievedValidUntil, uint48 retrievedValidAfter) =
            timeRangeModule.timeRanges(HOOK_ENTITY_ID, address(account1));

        assertEq(retrievedValidUntil, 0);
        assertEq(retrievedValidAfter, 0);
    }

    function test_timeRangeModule_setBadTime() public withSMATest {
        validUntil = 1000;
        validAfter = 100;

        _customValidationSetup();

        vm.startPrank(address(account1));
        vm.expectRevert(TimeRangeModule.TimeRangeNotValid.selector);
        timeRangeModule.setTimeRange(TEST_DEFAULT_VALIDATION_ENTITY_ID, validUntil, validUntil);

        vm.expectRevert(TimeRangeModule.TimeRangeNotValid.selector);
        timeRangeModule.setTimeRange(TEST_DEFAULT_VALIDATION_ENTITY_ID, validUntil, validUntil + 1);
        vm.stopPrank();
    }

    function testFuzz_timeRangeModule_userOp(uint48 time1, uint48 time2) public {
        vm.assume(time1 != time2);
        validUntil = time1 > time2 ? time1 : time2;
        validAfter = time1 < time2 ? time1 : time2;

        _customValidationSetup();

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: hex"",
            callData: abi.encodeCall(ModularAccountBase.execute, (makeAddr("recipient"), 0 wei, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));

        userOp.signature =
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        vm.prank(address(entryPoint));
        uint256 validationData = account1.validateUserOp(userOp, userOpHash, 0);

        uint48 expectedValidUntil = validUntil == 0 ? type(uint48).max : validUntil;

        assertEq(
            validationData,
            _packValidationData({sigFailed: false, validUntil: expectedValidUntil, validAfter: validAfter})
        );
    }

    function testFuzz_timeRangeModule_userOp_fail(uint48 time1, uint48 time2) public {
        vm.assume(time1 != time2);
        validUntil = time1 > time2 ? time1 : time2;
        validAfter = time1 < time2 ? time1 : time2;

        _customValidationSetup();

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: hex"",
            callData: abi.encodeCall(ModularAccountBase.execute, (makeAddr("recipient"), 0 wei, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: hex""
        });
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        // Generate a bad signature
        userOp.signature =
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, abi.encodePacked(EOA_TYPE_SIGNATURE, "abcd"));

        vm.prank(address(entryPoint));
        uint256 validationData = account1.validateUserOp(userOp, userOpHash, 0);

        uint48 expectedValidUntil = validUntil == 0 ? type(uint48).max : validUntil;

        assertEq(
            validationData,
            _packValidationData({sigFailed: true, validUntil: expectedValidUntil, validAfter: validAfter})
        );
    }

    function test_timeRangeModule_runtime_before() public withSMATest {
        validUntil = 1000;
        validAfter = 100;

        _customValidationSetup();

        // Attempt from before the valid time range, expect fail
        vm.warp(1);

        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionLib.PreRuntimeValidationHookReverted.selector,
                ModuleEntityLib.pack(address(timeRangeModule), HOOK_ENTITY_ID),
                abi.encodeWithSelector(TimeRangeModule.TimeRangeNotValid.selector)
            )
        );
        vm.prank(owner1);
        account1.executeWithRuntimeValidation(
            abi.encodeCall(ModularAccountBase.execute, (makeAddr("recipient"), 0 wei, "")),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
        );
    }

    function test_timeRangeModule_runtime_during() public withSMATest {
        validUntil = 1000;
        validAfter = 100;

        _customValidationSetup();

        // Attempt during the valid time range, expect success
        vm.warp(101);

        vm.expectCall({callee: makeAddr("recipient"), msgValue: 0 wei, data: ""});
        vm.prank(owner1);
        account1.executeWithRuntimeValidation(
            abi.encodeCall(ModularAccountBase.execute, (makeAddr("recipient"), 0 wei, "")),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
        );
    }

    function test_timeRangeModule_runtime_after() public withSMATest {
        validUntil = 1000;
        validAfter = 100;

        _customValidationSetup();

        // Attempt after the valid time range, expect fail
        vm.warp(1001);

        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionLib.PreRuntimeValidationHookReverted.selector,
                ModuleEntityLib.pack(address(timeRangeModule), HOOK_ENTITY_ID),
                abi.encodeWithSelector(TimeRangeModule.TimeRangeNotValid.selector)
            )
        );
        vm.prank(owner1);
        account1.executeWithRuntimeValidation(
            abi.encodeCall(ModularAccountBase.execute, (makeAddr("recipient"), 0 wei, "")),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
        );
    }

    function test_timeRangeModule_userOp_fails_extraValidationData() public withSMATest {
        validUntil = 1000;
        validAfter = 100;

        _customValidationSetup();

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: hex"",
            callData: abi.encodeCall(ModularAccountBase.execute, (makeAddr("recipient"), 0 wei, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        // Pass the module validation hook data.
        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({index: uint8(0), validationData: "abcd"});

        userOp.signature = _encodeSignature(_signerValidation, GLOBAL_VALIDATION, preValidationHookData, "");

        vm.prank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionLib.PreUserOpValidationHookReverted.selector,
                ModuleEntityLib.pack(address(timeRangeModule), HOOK_ENTITY_ID),
                abi.encodeWithSelector(ModuleBase.UnexpectedDataPassed.selector)
            )
        );
        account1.validateUserOp(userOp, userOpHash, 0);
    }

    function _initialValidationConfig()
        internal
        virtual
        override
        returns (ModuleEntity, bool, bool, bool, bytes4[] memory, bytes memory, bytes[] memory)
    {
        bytes[] memory hooks = new bytes[](1);
        hooks[0] = abi.encodePacked(
            HookConfigLib.packValidationHook(address(timeRangeModule), HOOK_ENTITY_ID),
            abi.encode(HOOK_ENTITY_ID, validUntil, validAfter)
        );
        // patched to also work during SMA tests by differentiating the validation
        _signerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), type(uint32).max - 1);
        return
            (_signerValidation, true, true, true, new bytes4[](0), abi.encode(type(uint32).max - 1, owner1), hooks);
    }
}
