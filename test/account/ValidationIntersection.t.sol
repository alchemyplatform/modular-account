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
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_PASSED} from "modular-account-libs/libraries/Constants.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerModularAccountFactory} from "../../src/factory/MultiOwnerModularAccountFactory.sol";
import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";
import {
    MockBaseUserOpValidationPlugin,
    MockUserOpValidation1HookPlugin,
    MockUserOpValidation2HookPlugin,
    MockUserOpValidationPlugin
} from "../mocks/plugins/ValidationPluginMocks.sol";

contract ValidationIntersectionTest is Test {
    IEntryPoint public entryPoint;

    address public owner1;
    uint256 public owner1Key;
    UpgradeableModularAccount public account1;
    MockUserOpValidationPlugin public noHookPlugin;
    MockUserOpValidation1HookPlugin public oneHookPlugin;
    MockUserOpValidation2HookPlugin public twoHookPlugin;

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));
        owner1 = makeAddr("owner1");

        MultiOwnerPlugin multiOwnerPlugin = new MultiOwnerPlugin();
        address impl = address(new UpgradeableModularAccount(entryPoint));

        MultiOwnerModularAccountFactory factory = new MultiOwnerModularAccountFactory(
            address(this),
            address(multiOwnerPlugin),
            impl,
            keccak256(abi.encode(multiOwnerPlugin.pluginManifest())),
            entryPoint
        );

        address[] memory owners1 = new address[](1);
        owners1[0] = owner1;
        account1 = UpgradeableModularAccount(payable(factory.createAccount(0, owners1)));
        vm.deal(address(account1), 1 ether);

        noHookPlugin = new MockUserOpValidationPlugin();
        oneHookPlugin = new MockUserOpValidation1HookPlugin();
        twoHookPlugin = new MockUserOpValidation2HookPlugin();

        vm.startPrank(address(owner1));
        account1.installPlugin({
            plugin: address(noHookPlugin),
            manifestHash: keccak256(abi.encode(noHookPlugin.pluginManifest())),
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
        account1.installPlugin({
            plugin: address(oneHookPlugin),
            manifestHash: keccak256(abi.encode(oneHookPlugin.pluginManifest())),
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
        account1.installPlugin({
            plugin: address(twoHookPlugin),
            manifestHash: keccak256(abi.encode(twoHookPlugin.pluginManifest())),
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
        vm.stopPrank();
    }

    function testFuzz_validationIntersect_single(uint256 validationData) public {
        noHookPlugin.setValidationData(validationData);

        UserOperation memory userOp;
        userOp.callData = bytes.concat(noHookPlugin.foo.selector);
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(returnedValidationData, validationData);
    }

    function test_validationIntersect_authorizer_sigfail_validationFunction() public {
        oneHookPlugin.setValidationData(
            SIG_VALIDATION_FAILED,
            SIG_VALIDATION_PASSED // returns OK
        );

        UserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookPlugin.bar.selector);
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        // Down-cast to only check the authorizer
        assertEq(uint160(returnedValidationData), SIG_VALIDATION_FAILED);
    }

    function test_validationIntersect_authorizer_sigfail_hook() public {
        oneHookPlugin.setValidationData(
            SIG_VALIDATION_PASSED, // returns OK
            SIG_VALIDATION_FAILED
        );

        UserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookPlugin.bar.selector);
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        // Down-cast to only check the authorizer
        assertEq(uint160(returnedValidationData), SIG_VALIDATION_FAILED);
    }

    function test_validationIntersect_timeBounds_intersect_1() public {
        uint48 start1 = uint48(10);
        uint48 end1 = uint48(20);

        uint48 start2 = uint48(15);
        uint48 end2 = uint48(25);

        oneHookPlugin.setValidationData(
            _packValidationData(address(0), start1, end1), _packValidationData(address(0), start2, end2)
        );

        UserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookPlugin.bar.selector);
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(returnedValidationData, _packValidationData(address(0), start2, end1));
    }

    function test_validationIntersect_timeBounds_intersect_2() public {
        uint48 start1 = uint48(10);
        uint48 end1 = uint48(20);

        uint48 start2 = uint48(15);
        uint48 end2 = uint48(25);

        oneHookPlugin.setValidationData(
            _packValidationData(address(0), start2, end2), _packValidationData(address(0), start1, end1)
        );

        UserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookPlugin.bar.selector);
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(returnedValidationData, _packValidationData(address(0), start2, end1));
    }

    function test_validationIntersect_revert_unexpectedAuthorizer() public {
        address badAuthorizer = makeAddr("badAuthorizer");

        oneHookPlugin.setValidationData(
            SIG_VALIDATION_PASSED, // returns OK
            uint256(uint160(badAuthorizer)) // returns an aggregator, which preValidation hooks are not allowed to
                // do.
        );

        UserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookPlugin.bar.selector);
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.UnexpectedAggregator.selector,
                address(oneHookPlugin),
                MockBaseUserOpValidationPlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK_1,
                badAuthorizer
            )
        );
        account1.validateUserOp(userOp, uoHash, 1 wei);
    }

    function test_validationIntersect_validAuthorizer() public {
        address goodAuthorizer = makeAddr("goodAuthorizer");

        oneHookPlugin.setValidationData(
            uint256(uint160(goodAuthorizer)), // returns a valid aggregator
            SIG_VALIDATION_PASSED // returns OK
        );

        UserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookPlugin.bar.selector);
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(address(uint160(returnedValidationData)), goodAuthorizer);
    }

    function test_validationIntersect_authorizerAndTimeRange() public {
        uint48 start1 = uint48(10);
        uint48 end1 = uint48(20);

        uint48 start2 = uint48(15);
        uint48 end2 = uint48(25);

        address goodAuthorizer = makeAddr("goodAuthorizer");

        oneHookPlugin.setValidationData(
            _packValidationData(goodAuthorizer, start1, end1), _packValidationData(address(0), start2, end2)
        );

        UserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookPlugin.bar.selector);
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(returnedValidationData, _packValidationData(goodAuthorizer, start2, end1));
    }

    function test_validationIntersect_multiplePreValidationHooksIntersect() public {
        uint48 start1 = uint48(10);
        uint48 end1 = uint48(20);

        uint48 start2 = uint48(15);
        uint48 end2 = uint48(25);

        twoHookPlugin.setValidationData(
            SIG_VALIDATION_PASSED, // returns OK
            _packValidationData(address(0), start1, end1),
            _packValidationData(address(0), start2, end2)
        );

        UserOperation memory userOp;
        userOp.callData = bytes.concat(twoHookPlugin.baz.selector);
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(returnedValidationData, _packValidationData(address(0), start2, end1));
    }

    function test_validationIntersect_multiplePreValidationHooksSigFail() public {
        twoHookPlugin.setValidationData(
            SIG_VALIDATION_PASSED, // returns OK
            SIG_VALIDATION_PASSED, // returns OK
            SIG_VALIDATION_FAILED
        );

        UserOperation memory userOp;
        userOp.callData = bytes.concat(twoHookPlugin.baz.selector);

        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        // Down-cast to only check the authorizer
        assertEq(uint160(returnedValidationData), SIG_VALIDATION_FAILED);
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

    function _packValidationData(address authorizer, uint48 validAfter, uint48 validUntil)
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
