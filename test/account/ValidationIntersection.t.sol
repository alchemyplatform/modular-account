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
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";

import {
    MockBaseUserOpValidationModule,
    MockUserOpValidation1HookModule,
    MockUserOpValidation2HookModule,
    MockUserOpValidationModule
} from "../mocks/modules/ValidationModuleMocks.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract ValidationIntersectionTest is AccountTestBase {
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    MockUserOpValidationModule public noHookModule;
    MockUserOpValidation1HookModule public oneHookModule;
    MockUserOpValidation2HookModule public twoHookModule;

    ModuleEntity public noHookValidation;
    ModuleEntity public oneHookValidation;
    ModuleEntity public twoHookValidation;

    function setUp() public override {
        _revertSnapshot = vm.snapshotState();
        noHookModule = new MockUserOpValidationModule();
        oneHookModule = new MockUserOpValidation1HookModule();
        twoHookModule = new MockUserOpValidation2HookModule();

        noHookValidation = ModuleEntityLib.pack({addr: address(noHookModule), entityId: uint32(1)});

        oneHookValidation = ModuleEntityLib.pack({addr: address(oneHookModule), entityId: uint32(2)});

        twoHookValidation = ModuleEntityLib.pack({addr: address(twoHookModule), entityId: uint32(3)});

        bytes4[] memory validationSelectors = new bytes4[](1);
        validationSelectors[0] = MockUserOpValidationModule.foo.selector;

        vm.startPrank(address(entryPoint));
        // Install noHookValidation
        account1.installValidation(
            ValidationConfigLib.pack(noHookValidation, true, true, true),
            validationSelectors,
            bytes(""),
            new bytes[](0)
        );

        // Install oneHookValidation
        validationSelectors[0] = MockUserOpValidation1HookModule.bar.selector;
        bytes[] memory hooks = new bytes[](1);
        hooks[0] = abi.encodePacked(
            HookConfigLib.packValidationHook(
                address(oneHookModule), uint32(MockBaseUserOpValidationModule.EntityId.PRE_VALIDATION_HOOK_1)
            )
        );
        account1.installValidation(
            ValidationConfigLib.pack(oneHookValidation, true, true, true), validationSelectors, bytes(""), hooks
        );

        // Install twoHookValidation
        validationSelectors[0] = MockUserOpValidation2HookModule.baz.selector;
        hooks = new bytes[](2);
        hooks[0] = abi.encodePacked(
            HookConfigLib.packValidationHook(
                address(twoHookModule), uint32(MockBaseUserOpValidationModule.EntityId.PRE_VALIDATION_HOOK_1)
            )
        );
        hooks[1] = abi.encodePacked(
            HookConfigLib.packValidationHook(
                address(twoHookModule), uint32(MockBaseUserOpValidationModule.EntityId.PRE_VALIDATION_HOOK_2)
            )
        );
        account1.installValidation(
            ValidationConfigLib.pack(twoHookValidation, true, true, true), validationSelectors, bytes(""), hooks
        );
        vm.stopPrank();
    }

    function testFuzz_validationIntersect_single(uint256 validationData) public {
        noHookModule.setValidationData(validationData);

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(noHookModule.foo.selector);
        userOp.nonce = _encodeNonce(noHookValidation, SELECTOR_ASSOCIATED_V, 0);
        userOp.signature = _encodeSignature("");
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(returnedValidationData, validationData);
    }

    function test_validationIntersect_authorizer_sigfail_validationFunction() public withSMATest {
        oneHookModule.setValidationData(
            _SIG_VALIDATION_FAILED,
            0 // returns OK
        );

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookModule.bar.selector);
        userOp.nonce = _encodeNonce(oneHookValidation, SELECTOR_ASSOCIATED_V, 0);
        userOp.signature = _encodeSignature("");
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        // Down-cast to only check the authorizer
        assertEq(uint160(returnedValidationData), _SIG_VALIDATION_FAILED);
    }

    function test_validationIntersect_authorizer_sigfail_hook() public withSMATest {
        oneHookModule.setValidationData(
            0, // returns OK
            _SIG_VALIDATION_FAILED
        );

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookModule.bar.selector);
        userOp.nonce = _encodeNonce(oneHookValidation, SELECTOR_ASSOCIATED_V, 0);
        userOp.signature = _encodeSignature("");
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        // Down-cast to only check the authorizer
        assertEq(uint160(returnedValidationData), _SIG_VALIDATION_FAILED);
    }

    function test_validationIntersect_timeBounds_intersect_1() public withSMATest {
        uint48 start1 = uint48(10);
        uint48 end1 = uint48(20);

        uint48 start2 = uint48(15);
        uint48 end2 = uint48(25);

        oneHookModule.setValidationData(
            _packValidationRes(address(0), start1, end1), _packValidationRes(address(0), start2, end2)
        );

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookModule.bar.selector);
        userOp.nonce = _encodeNonce(oneHookValidation, SELECTOR_ASSOCIATED_V, 0);
        userOp.signature = _encodeSignature("");
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(returnedValidationData, _packValidationRes(address(0), start2, end1));
    }

    function test_validationIntersect_timeBounds_intersect_2() public withSMATest {
        uint48 start1 = uint48(10);
        uint48 end1 = uint48(20);

        uint48 start2 = uint48(15);
        uint48 end2 = uint48(25);

        oneHookModule.setValidationData(
            _packValidationRes(address(0), start2, end2), _packValidationRes(address(0), start1, end1)
        );

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookModule.bar.selector);
        userOp.nonce = _encodeNonce(oneHookValidation, SELECTOR_ASSOCIATED_V, 0);
        userOp.signature = _encodeSignature("");
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(returnedValidationData, _packValidationRes(address(0), start2, end1));
    }

    function test_validationIntersect_revert_unexpectedAuthorizer() public withSMATest {
        address badAuthorizer = makeAddr("badAuthorizer");

        oneHookModule.setValidationData(
            0, // returns OK
            uint256(uint160(badAuthorizer)) // returns an aggregator, which preValidation hooks are not allowed to
                // do.
        );

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookModule.bar.selector);
        userOp.nonce = _encodeNonce(oneHookValidation, SELECTOR_ASSOCIATED_V, 0);
        userOp.signature = _encodeSignature("");
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                ModularAccountBase.UnexpectedAggregator.selector,
                ModuleEntityLib.pack(
                    address(oneHookModule), uint32(MockBaseUserOpValidationModule.EntityId.PRE_VALIDATION_HOOK_1)
                ),
                badAuthorizer
            )
        );
        account1.validateUserOp(userOp, uoHash, 1 wei);
    }

    function test_validationIntersect_validAuthorizer() public withSMATest {
        address goodAuthorizer = makeAddr("goodAuthorizer");

        oneHookModule.setValidationData(
            uint256(uint160(goodAuthorizer)), // returns a valid aggregator
            0 // returns OK
        );

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookModule.bar.selector);
        userOp.nonce = _encodeNonce(oneHookValidation, SELECTOR_ASSOCIATED_V, 0);
        userOp.signature = _encodeSignature("");
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(address(uint160(returnedValidationData)), goodAuthorizer);
    }

    function test_validationIntersect_authorizerAndTimeRange() public withSMATest {
        uint48 start1 = uint48(10);
        uint48 end1 = uint48(20);

        uint48 start2 = uint48(15);
        uint48 end2 = uint48(25);

        address goodAuthorizer = makeAddr("goodAuthorizer");

        oneHookModule.setValidationData(
            _packValidationRes(goodAuthorizer, start1, end1), _packValidationRes(address(0), start2, end2)
        );

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookModule.bar.selector);
        userOp.nonce = _encodeNonce(oneHookValidation, SELECTOR_ASSOCIATED_V, 0);
        userOp.signature = _encodeSignature("");
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);
        assertEq(returnedValidationData, _packValidationRes(goodAuthorizer, start2, end1));
    }

    function test_validationIntersect_multiplePreValidationHooksIntersect() public withSMATest {
        uint48 start1 = uint48(10);
        uint48 end1 = uint48(20);

        uint48 start2 = uint48(15);
        uint48 end2 = uint48(25);

        twoHookModule.setValidationData(
            0, // returns OK
            _packValidationRes(address(0), start1, end1),
            _packValidationRes(address(0), start2, end2)
        );

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(twoHookModule.baz.selector);
        userOp.nonce = _encodeNonce(twoHookValidation, SELECTOR_ASSOCIATED_V, 0);
        userOp.signature = _encodeSignature("");
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(returnedValidationData, _packValidationRes(address(0), start2, end1));
    }

    function test_validationIntersect_multiplePreValidationHooksSigFail() public withSMATest {
        twoHookModule.setValidationData(
            0, // returns OK
            0, // returns OK
            _SIG_VALIDATION_FAILED
        );

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(twoHookModule.baz.selector);
        userOp.nonce = _encodeNonce(twoHookValidation, SELECTOR_ASSOCIATED_V, 0);
        userOp.signature = _encodeSignature("");
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        // Down-cast to only check the authorizer
        assertEq(uint160(returnedValidationData), _SIG_VALIDATION_FAILED);
    }

    function _unpackValidationData(uint256 validationData)
        internal
        pure
        returns (address authorizer, uint48 validAfter, uint48 validUntil)
    {
        authorizer = address(uint160(validationData));
        validUntil = uint48(validationData >> 160);
        if (validUntil == 0) {
            validUntil = type(uint48).max;
        }
        validAfter = uint48(validationData >> (48 + 160));
    }

    function _packValidationRes(address authorizer, uint48 validAfter, uint48 validUntil)
        internal
        pure
        returns (uint256)
    {
        return uint160(authorizer) | (uint256(validUntil) << 160) | (uint256(validAfter) << (160 + 48));
    }

    function _intersectTimeRange(uint48 validafter1, uint48 validuntil1, uint48 validafter2, uint48 validuntil2)
        internal
        pure
        returns (uint48 validAfter, uint48 validUntil)
    {
        if (validafter1 < validafter2) {
            validAfter = validafter2;
        } else {
            validAfter = validafter1;
        }
        if (validuntil1 > validuntil2) {
            validUntil = validuntil2;
        } else {
            validUntil = validuntil1;
        }
    }
}
