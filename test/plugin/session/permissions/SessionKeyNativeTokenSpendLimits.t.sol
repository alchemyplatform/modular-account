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

import {Test, console} from "forge-std/Test.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {FunctionReferenceLib} from "modular-account-libs/libraries/FunctionReferenceLib.sol";
import {UserOperation} from "modular-account-libs/interfaces/UserOperation.sol";
import {FunctionReference} from "modular-account-libs/interfaces/IPluginManager.sol";
import {Call} from "modular-account-libs/interfaces/IStandardExecutor.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {ISessionKeyPermissionsUpdates} from
    "../../../../src/plugins/session/permissions/ISessionKeyPermissionsUpdates.sol";
import {UpgradeableModularAccount} from "../../../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerModularAccountFactory} from "../../../../src/factory/MultiOwnerModularAccountFactory.sol";
import {IEntryPoint} from "../../../../src/interfaces/erc4337/IEntryPoint.sol";
import {IMultiOwnerPlugin} from "../../../../src/plugins/owner/IMultiOwnerPlugin.sol";
import {MultiOwnerPlugin} from "../../../../src/plugins/owner/MultiOwnerPlugin.sol";
import {ISessionKeyPlugin} from "../../../../src/plugins/session/ISessionKeyPlugin.sol";
import {SessionKeyPlugin} from "../../../../src/plugins/session/SessionKeyPlugin.sol";

contract SessionKeyNativeTokenSpendLimitsTest is Test {
    using ECDSA for bytes32;

    IEntryPoint entryPoint;
    address payable beneficiary;

    MultiOwnerPlugin multiOwnerPlugin;
    MultiOwnerModularAccountFactory factory;
    SessionKeyPlugin sessionKeyPlugin;

    address owner1;
    uint256 owner1Key;
    UpgradeableModularAccount account1;

    address sessionKey1;
    uint256 sessionKey1Private;

    address recipient1;
    address recipient2;
    address recipient3;

    // Constants for running user ops
    uint256 constant CALL_GAS_LIMIT = 300000;
    uint256 constant VERIFICATION_GAS_LIMIT = 1000000;

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));
        (owner1, owner1Key) = makeAddrAndKey("owner1");
        beneficiary = payable(makeAddr("beneficiary"));

        vm.deal(beneficiary, 1 wei);

        multiOwnerPlugin = new MultiOwnerPlugin();
        bytes32 multiOwnerPluginManifestHash = keccak256(abi.encode(multiOwnerPlugin.pluginManifest()));
        factory = new MultiOwnerModularAccountFactory(
            address(this),
            address(multiOwnerPlugin),
            address(new UpgradeableModularAccount(entryPoint)),
            multiOwnerPluginManifestHash,
            entryPoint
        );

        sessionKeyPlugin = new SessionKeyPlugin();

        address[] memory owners1 = new address[](1);
        owners1[0] = owner1;
        account1 = UpgradeableModularAccount(payable(factory.createAccount(0, owners1)));
        vm.deal(address(account1), 100 ether);

        bytes32 manifestHash = keccak256(abi.encode(sessionKeyPlugin.pluginManifest()));
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReferenceLib.pack(
            address(multiOwnerPlugin), uint8(IMultiOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] = FunctionReferenceLib.pack(
            address(multiOwnerPlugin), uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER)
        );
        vm.prank(owner1);
        account1.installPlugin({
            plugin: address(sessionKeyPlugin),
            manifestHash: manifestHash,
            pluginInstallData: abi.encode(new address[](0), new bytes32[](0), new bytes[][](0)),
            dependencies: dependencies
        });

        // Create and add a session key
        (sessionKey1, sessionKey1Private) = makeAddrAndKey("sessionKey1");

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKey1, bytes32(0), new bytes[](0));

        // Remove the allowlist
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.setAccessListType,
            (ISessionKeyPlugin.ContractAccessControlType.ALLOW_ALL_ACCESS)
        );
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Create recipient addresses to receive ether
        recipient1 = makeAddr("recipient1");
        recipient2 = makeAddr("recipient2");
        recipient3 = makeAddr("recipient3");
    }

    function test_sessionKeyNativeTokenSpendLimits_validateSetUp() public {
        // Check that the session key is registered
        assertTrue(sessionKeyPlugin.isSessionKeyOf(address(account1), sessionKey1));

        // Check that the session key is registered with the permissions plugin and has its allowlist set up
        // correctly
        assertTrue(
            sessionKeyPlugin.getAccessControlType(address(account1), sessionKey1)
                == ISessionKeyPlugin.ContractAccessControlType.ALLOW_ALL_ACCESS
        );
    }

    function testFuzz_sessionKeyNativeTokenSpendLimits_setLimits(uint256 limit, uint48 interval, uint48 timestamp)
        public
    {
        vm.warp(timestamp);

        // Assert that the limit starts out set, and at zero
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getNativeTokenSpendLimitInfo(address(account1), sessionKey1);

        assertTrue(spendLimitInfo.hasLimit);
        assertEq(spendLimitInfo.limit, 0);
        assertEq(spendLimitInfo.refreshInterval, 0);
        assertEq(spendLimitInfo.limitUsed, 0);

        // Set the limit
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setNativeTokenSpendLimit, (limit, interval));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Verify the limit can be retrieved
        spendLimitInfo = sessionKeyPlugin.getNativeTokenSpendLimitInfo(address(account1), sessionKey1);

        if (limit == type(uint256).max) {
            // If the limit is "set" to this value, it is just removed.
            // verify that the values are still as they were before.
            assertEq(spendLimitInfo.limit, 0);
            assertEq(spendLimitInfo.refreshInterval, 0);
            assertEq(spendLimitInfo.limitUsed, 0);
        } else {
            // The limit is actually set, verify that the values are as expected.
            assertTrue(spendLimitInfo.hasLimit);
            assertEq(spendLimitInfo.limit, limit);
            assertEq(spendLimitInfo.refreshInterval, interval);
            assertEq(spendLimitInfo.limitUsed, 0);
            if (interval == 0) {
                assertEq(spendLimitInfo.lastUsedTime, 0);
            } else {
                assertEq(spendLimitInfo.lastUsedTime, timestamp);
            }
        }
    }

    function test_sessionKeyNativeTokenSpendLimits_enforceLimit_none() public {
        // The limit starts out at zero

        // Run a user op that spends 1 wei, should fail
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: recipient1, value: 1 wei, data: ""});

        _runSessionKeyUserOp(
            calls,
            sessionKey1Private,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA23 reverted (or OOG)")
        );

        // Run a user op that spends 0 wei, should succeed
        calls[0] = Call({target: recipient1, value: 0, data: "somedata"});

        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Run a multi-execution user op that spends 0 wei, should succeed
        calls = new Call[](2);
        calls[0] = Call({target: recipient1, value: 0, data: "somedata1"});
        calls[1] = Call({target: recipient2, value: 0, data: "somedata2"});

        _runSessionKeyUserOp(calls, sessionKey1Private, "");
    }

    function test_sessionKeyNativeTokenSpendLimits_basic_single() public {
        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setNativeTokenSpendLimit, (1 ether, 0));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends 1 wei, should succeed
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: recipient1, value: 1 wei, data: ""});

        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is now updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getNativeTokenSpendLimitInfo(address(account1), sessionKey1);

        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 wei);
        assertEq(spendLimitInfo.refreshInterval, 0);
        // Assert that the last used time is not updated when the interval is unset.
        assertEq(spendLimitInfo.lastUsedTime, 0);

        // Run a user op that spends 1 ether, should fail

        calls[0] = Call({target: recipient1, value: 1 ether, data: ""});

        _runSessionKeyUserOp(
            calls,
            sessionKey1Private,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA23 reverted (or OOG)")
        );
    }

    function test_sessionKeyNativeTokenSpendLimits_overflowState() public {
        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setNativeTokenSpendLimit, (1 ether, 0));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends 1 wei, should succeed
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: recipient1, value: 1 wei, data: ""});
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Attempt to run a user op that spends type(uint256).max (causing an overflow). Should fail.
        calls[0] = Call({target: recipient1, value: type(uint256).max, data: ""});

        // Assert that the failure happens during validation.
        // We would like to assert here that the pre user op validation hook itself does not revert, but since the
        // account catches those reverts internally and returns SIG_FAIL, we can't assert it from here easily.
        _runSessionKeyUserOp(
            calls,
            sessionKey1Private,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA23 reverted (or OOG)")
        );
    }

    function test_sessionKeyNativeTokenSpendLimits_overflowBatch() public {
        // NOTE: overflows that happen within a single batch are not gracefully caught and returned as `SIG_FAIL`,
        // instead the pre exec hook reverts. However, the modular account will catch that revert.

        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setNativeTokenSpendLimit, (1 ether, 0));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Attempt to run a user op that spends > type(uint256).max (causing an overflow). Should fail.
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: recipient1, value: 1 wei, data: ""});
        calls[1] = Call({target: recipient1, value: type(uint256).max, data: ""});
        _runSessionKeyUserOp(
            calls,
            sessionKey1Private,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA23 reverted (or OOG)")
        );
    }

    function test_sessionKeyNativeTokenSpendLimits_exceedLimit_single() public {
        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setNativeTokenSpendLimit, (1 ether, 0));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends 1 wei, should succeed
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: recipient1, value: 1 wei, data: ""});

        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Attempt to run an execution spending 1 ether, should fail
        calls[0] = Call({target: recipient1, value: 1 ether, data: ""});

        _runSessionKeyUserOp(
            calls,
            sessionKey1Private,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA23 reverted (or OOG)")
        );

        // Assert that the limit is NOT updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getNativeTokenSpendLimitInfo(address(account1), sessionKey1);

        assertTrue(spendLimitInfo.hasLimit);
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 wei);
        assertEq(spendLimitInfo.refreshInterval, 0);
        // Assert that the last used time is not updated when the interval is unset.
        assertEq(spendLimitInfo.lastUsedTime, 0);
    }

    // Tests basic enforcement of spend limits when using more than one execution in a user op.
    function test_sessionKeyNativeTokenSpendLimits_basic_multi() public {
        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setNativeTokenSpendLimit, (1 ether, 0));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a multi execution user op spending 3 wei, should succeed
        Call[] memory calls = new Call[](3);
        calls[0] = Call({target: recipient1, value: 1 wei, data: ""});
        calls[1] = Call({target: recipient2, value: 1 wei, data: ""});
        calls[2] = Call({target: recipient3, value: 1 wei, data: ""});

        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is now updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getNativeTokenSpendLimitInfo(address(account1), sessionKey1);

        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 3 wei);
        assertEq(spendLimitInfo.refreshInterval, 0);
        // Assert that the last used time is not updated when the interval is unset.
        assertEq(spendLimitInfo.lastUsedTime, 0);
    }

    function test_sessionKeyNativeTokenSpendLimits_exceedLimit_multi() public {
        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setNativeTokenSpendLimit, (1 ether, 0));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Attempt to run a multi execution user op spending 1.5 ether, should fail
        Call[] memory calls = new Call[](3);
        calls[0] = Call({target: recipient1, value: 0.5 ether, data: ""});
        calls[1] = Call({target: recipient2, value: 0.5 ether, data: ""});
        calls[2] = Call({target: recipient3, value: 0.5 ether, data: ""});

        _runSessionKeyUserOp(
            calls,
            sessionKey1Private,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA23 reverted (or OOG)")
        );

        // Assert that the limit is NOT updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getNativeTokenSpendLimitInfo(address(account1), sessionKey1);

        assertTrue(spendLimitInfo.hasLimit);
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 0);
        assertEq(spendLimitInfo.refreshInterval, 0);
        // Assert that the last used time is not updated when the interval is unset.
        assertEq(spendLimitInfo.lastUsedTime, 0);
    }

    function test_sessionKeyNativeTokenSpendLimits_refreshInterval_single() public {
        // Set the time to the current unix timestamp as of writing
        uint256 time0 = 1698708080;
        vm.warp(time0);

        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setNativeTokenSpendLimit, (1 ether, 1 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends 1 wei, should succeed
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: recipient1, value: 1 wei, data: ""});

        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is now updated and the last used timestamp is set.
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getNativeTokenSpendLimitInfo(address(account1), sessionKey1);

        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 wei);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0);

        // Run a user op that spends 1 ether, should fail
        calls[0] = Call({target: recipient1, value: 1 ether, data: ""});

        _runSessionKeyUserOp(
            calls,
            sessionKey1Private,
            // The execution will be valid at a later time when the interval resets, but not right now.
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA22 expired or not due")
        );

        // Assert that the limit is NOT updated
        spendLimitInfo = sessionKeyPlugin.getNativeTokenSpendLimitInfo(address(account1), sessionKey1);

        assertTrue(spendLimitInfo.hasLimit);
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 wei);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, block.timestamp);

        // warp to when the interval resets
        vm.warp(time0 + 1 days);

        // Run a user op that spends 1 ether, should succeed
        calls[0] = Call({target: recipient1, value: 1 ether, data: ""});

        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is now updated and the last used timestamp is set.
        spendLimitInfo = sessionKeyPlugin.getNativeTokenSpendLimitInfo(address(account1), sessionKey1);

        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 ether);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0 + 1 days);
    }

    function test_sessionKeyNativeTokenSpendLimits_refreshInterval_multi() public {
        // Set the time to the current unix timestamp as of writing
        uint256 time0 = 1698708080;
        vm.warp(time0);

        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setNativeTokenSpendLimit, (1 ether, 1 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends 1 wei, should succeed
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: recipient1, value: 1 wei, data: ""});

        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is now updated and the last used timestamp is set.
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getNativeTokenSpendLimitInfo(address(account1), sessionKey1);

        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 wei);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0);

        // Run a user op that spends 1 ether, should fail
        calls = new Call[](2);
        calls[0] = Call({target: recipient1, value: 0.5 ether, data: ""});
        calls[1] = Call({target: recipient2, value: 0.5 ether, data: ""});

        _runSessionKeyUserOp(
            calls,
            sessionKey1Private,
            // The execution will be valid at a later time when the interval resets, but not right now.
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA22 expired or not due")
        );

        // Assert that the limit is NOT updated
        spendLimitInfo = sessionKeyPlugin.getNativeTokenSpendLimitInfo(address(account1), sessionKey1);

        assertTrue(spendLimitInfo.hasLimit);
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 wei);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, block.timestamp);

        // warp to when the interval resets
        vm.warp(time0 + 1 days);

        // Run the previous user op that spends 1 ether, should succeed
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is now updated and the last used timestamp is set.
        spendLimitInfo = sessionKeyPlugin.getNativeTokenSpendLimitInfo(address(account1), sessionKey1);

        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 ether);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0 + 1 days);
    }

    function test_sessionKeyNativeTokenSpendLimits_basic_refreshInterval_takeMaxStartTime() public {
        // Tests the behavior of the session key spending limits to return the higher starting time between the
        // key's time and the spending limit's time.

        // Set the time to the current unix timestamp as of writing
        uint256 time0 = 1698708080;
        vm.warp(time0);

        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setNativeTokenSpendLimit, (1 ether, 1 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends 1 wei, should succeed
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: recipient1, value: 1 wei, data: ""});

        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is now updated and the last used timestamp is set.
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getNativeTokenSpendLimitInfo(address(account1), sessionKey1);

        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 wei);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0);

        // Assert that if we try to run a user op sending 1 ether,
        // then it will return the current time + the interval.

        calls[0] = Call({target: recipient1, value: 1 ether, data: ""});

        UserOperation memory uo = UserOperation({
            sender: address(account1),
            nonce: entryPoint.getNonce(address(account1), 0),
            initCode: "",
            callData: abi.encodeCall(ISessionKeyPlugin.executeWithSessionKey, (calls, sessionKey1)),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(uo);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKey1Private, userOpHash.toEthSignedMessageHash());
        uo.signature = abi.encodePacked(r, s, v);

        vm.prank(address(entryPoint));
        uint256 result = account1.validateUserOp(uo, userOpHash, 0);
        uint48 expectedStartTime = uint48(time0 + 1 days);
        uint48 actualStartTime = uint48(result >> 208);
        assertEq(actualStartTime, expectedStartTime);

        // Set the key's time limit to a value greater than the limit's start time.
        uint256 keyStartTime = time0 + 2 days;

        bytes[] memory updates2 = new bytes[](1);
        updates2[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.updateTimeRange, (uint48(keyStartTime), 0));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates2);

        // Assert that the later start time is returned (key time range)
        vm.prank(address(entryPoint));
        result = account1.validateUserOp(uo, userOpHash, 0);

        expectedStartTime = uint48(keyStartTime);
        actualStartTime = uint48(result >> 208);
        assertEq(actualStartTime, expectedStartTime);

        // Set the key's time limit to a value less than the limit's start time.
        keyStartTime = time0 + 12 hours;

        updates2[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.updateTimeRange, (uint48(keyStartTime), 0));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates2);

        // Assert that the later start time is returned (spend limit)
        vm.prank(address(entryPoint));
        result = account1.validateUserOp(uo, userOpHash, 0);

        expectedStartTime = uint48(time0 + 1 days);
        actualStartTime = uint48(result >> 208);
        assertEq(actualStartTime, expectedStartTime);
    }

    // This test protects against an attack vector where a staked account can submit multiple user operations to
    // the same bundle, and because of the evaluation order of the user op validations and calls, can get two
    // user ops to pass the spend limit validation when by the limit amount, only one should be able to execute.
    // This is why the pre execution hook in the permission checker plugin re-checks the amounts being spent, and
    // may revert.
    function test_sessionKeyNativeTokenSpendLimits_multiUserOpBundle_check_noInterval() public {
        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setNativeTokenSpendLimit, (1 ether, 0 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Prepare a user op bundle that attempts to spend 1 ether twice.
        // The second call should revert because the first call will have updated the limit.
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: recipient1, value: 1 ether, data: ""});

        UserOperation memory userOp1 = UserOperation({
            sender: address(account1),
            nonce: entryPoint.getNonce(address(account1), 0),
            initCode: "",
            callData: abi.encodeCall(ISessionKeyPlugin.executeWithSessionKey, (calls, sessionKey1)),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKey1Private, userOpHash.toEthSignedMessageHash());
        userOp1.signature = abi.encodePacked(r, s, v);

        UserOperation memory userOp2 = UserOperation({
            sender: address(account1),
            nonce: entryPoint.getNonce(address(account1), 1),
            initCode: "",
            callData: abi.encodeCall(ISessionKeyPlugin.executeWithSessionKey, (calls, sessionKey1)),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        userOpHash = entryPoint.getUserOpHash(userOp2);
        (v, r, s) = vm.sign(sessionKey1Private, userOpHash.toEthSignedMessageHash());
        userOp2.signature = abi.encodePacked(r, s, v);

        // Since handleOps will succeed because nothing will revert during validation, we have to make assertions
        // about world state using the recipient's balance.
        assertEq(recipient1.balance, 0);

        UserOperation[] memory userOps = new UserOperation[](2);
        userOps[0] = userOp1;
        userOps[1] = userOp2;

        // The second one should revert during execution, via the re-check phase in pre exec hooks.
        // We don't have a good way to check this from a Foundry test without almost fully reimplementing the
        // EntryPoint's logic, so instead we will just assert that the call to handleOps succeeds and the
        // recipient's balance is only 1 eth after the fact.
        entryPoint.handleOps(userOps, beneficiary);

        assertEq(recipient1.balance, 1 ether);

        // Assert that the spend limit is maxed out now.
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getNativeTokenSpendLimitInfo(address(account1), sessionKey1);

        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 ether);
        assertEq(spendLimitInfo.refreshInterval, 0);
        assertEq(spendLimitInfo.lastUsedTime, 0);
    }

    function test_sessionKeyNativeTokenSpendLimits_refreshInterval_exceedNewInterval() public {
        // Set the time to the current unix timestamp as of writing
        uint256 time0 = 1698708080;
        vm.warp(time0);

        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setNativeTokenSpendLimit, (1 ether, 1 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends 1 wei, should succeed
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: recipient1, value: 1 wei, data: ""});

        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is now updated and the last used timestamp is set.
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getNativeTokenSpendLimitInfo(address(account1), sessionKey1);

        assertTrue(spendLimitInfo.hasLimit);
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 wei);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0);

        skip(1 days + 1 minutes);

        // Attempt to run a user op that spends 1.1 ether, should fail.
        calls[0] = Call({target: recipient1, value: 1.1 ether, data: ""});
        _runSessionKeyUserOp(
            calls,
            sessionKey1Private,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA23 reverted (or OOG)")
        );

        // Assert that limits are NOT updated
        spendLimitInfo = sessionKeyPlugin.getNativeTokenSpendLimitInfo(address(account1), sessionKey1);

        assertTrue(spendLimitInfo.hasLimit);
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 wei);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0);
    }

    // There's an additional pre exec revert that I haven't been able to trigger in a real example, when a
    // usage of a session key with a native token spend limit reaches the "new time interval" section, but the
    // amount being spent exceeds the new limit. This seems to be impossible to reach because any prior usage would
    // reset the last used timestamp, and any call to `setNativeTokenSpendLimit` would also reset the last used
    // timestamp. I'm leaving this note here for now in case someone can find a way to trigger it.
    //
    // There's also the possibility that this is impossible to trigger, and the check is redundant. But I don't
    // want to remove it for now, since it's a fairly cheap check that may prevent a dangerous issue.
    //
    // function test_sessionKeyNativeTokenSpendLimits_multiUserOpBundle_check_interval()
    //
    // Updated note since the addition of ERC-20 spend limits: this code branch is reachable from there, and was
    // handled correctly. However, I still cannot reach it from the native token spend limit checking.

    function _runSessionKeyUserOp(Call[] memory calls, uint256 sessionKeyPrivate, bytes memory expectedError)
        internal
    {
        address sessionKey = vm.addr(sessionKeyPrivate);

        UserOperation memory userOp = UserOperation({
            sender: address(account1),
            nonce: entryPoint.getNonce(address(account1), 0),
            initCode: "",
            callData: abi.encodeCall(ISessionKeyPlugin.executeWithSessionKey, (calls, sessionKey)),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPrivate, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        if (expectedError.length > 0) {
            vm.expectRevert(expectedError);
        }
        entryPoint.handleOps(userOps, beneficiary);
    }
}
