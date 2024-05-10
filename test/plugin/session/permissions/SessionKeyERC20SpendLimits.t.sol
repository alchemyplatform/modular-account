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
import {MockERC20} from "../../../mocks/tokens/MockERC20.sol";

contract SessionKeyERC20SpendLimitsTest is Test {
    using ECDSA for bytes32;

    IEntryPoint entryPoint;
    address payable beneficiary;

    MultiOwnerPlugin public multiOwnerPlugin;
    MultiOwnerModularAccountFactory public factory;
    SessionKeyPlugin sessionKeyPlugin;

    address owner1;
    uint256 owner1Key;
    UpgradeableModularAccount account1;

    address sessionKey1;
    uint256 sessionKey1Private;

    address recipient1;
    address recipient2;

    MockERC20 token1;
    MockERC20 token2;
    MockERC20 token3;

    // Constants for running user ops
    uint256 constant CALL_GAS_LIMIT = 300000;
    uint256 constant VERIFICATION_GAS_LIMIT = 1000000;

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));
        (owner1, owner1Key) = makeAddrAndKey("owner1");
        beneficiary = payable(makeAddr("beneficiary"));

        vm.deal(beneficiary, 1 wei);

        multiOwnerPlugin = new MultiOwnerPlugin();
        factory = new MultiOwnerModularAccountFactory(
            address(this),
            address(multiOwnerPlugin),
            address(new UpgradeableModularAccount(entryPoint)),
            keccak256(abi.encode(multiOwnerPlugin.pluginManifest())),
            entryPoint
        );
        owner1 = makeAddr("owner");
        address[] memory owners = new address[](1);
        owners[0] = owner1;
        account1 = UpgradeableModularAccount(payable(factory.createAccount(0, owners)));

        vm.deal(address(account1), 100 ether);

        sessionKeyPlugin = new SessionKeyPlugin();

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

        // Disable the allowlist
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.setAccessListType,
            (ISessionKeyPlugin.ContractAccessControlType.ALLOW_ALL_ACCESS)
        );
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Create recipients' addresses to receive the tokens
        recipient1 = makeAddr("recipient1");
        recipient2 = makeAddr("recipient2");

        // Create the mock token contracts
        token1 = new MockERC20("T1");
        token2 = new MockERC20("T2");
        token3 = new MockERC20("T3");
    }

    function test_sessionKeyERC20SpendLimits_validateSetUp() public {
        // Check that the session key is registered
        assertTrue(sessionKeyPlugin.isSessionKeyOf(address(account1), sessionKey1));

        // Check that the session key is registered with the permissions plugin and has its allowlist set up
        // correctly
        assertTrue(
            sessionKeyPlugin.getAccessControlType(address(account1), sessionKey1)
                == ISessionKeyPlugin.ContractAccessControlType.ALLOW_ALL_ACCESS
        );
    }

    function testFuzz_sessionKeyERC20SpendLimits_setLimits(
        address token,
        uint256 limit,
        uint48 refreshInterval,
        uint48 timestamp
    ) public {
        // The zero address is not allowed as a token addr. The next test asserts this.
        vm.assume(token != address(0));

        // Pick a timestamp to warp to
        vm.warp(timestamp);

        // Assert that the limit starts out unset
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, token);

        assertFalse(spendLimitInfo.hasLimit);
        assertEq(spendLimitInfo.limit, 0);
        assertEq(spendLimitInfo.refreshInterval, 0);
        assertEq(spendLimitInfo.limitUsed, 0);

        // Set the limit
        bytes[] memory updates = new bytes[](1);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (token, limit, refreshInterval));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Verify the limit can be retrieved
        spendLimitInfo = sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, token);

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
            assertEq(spendLimitInfo.refreshInterval, refreshInterval);
            assertEq(spendLimitInfo.limitUsed, 0);
            if (refreshInterval == 0) {
                assertEq(spendLimitInfo.lastUsedTime, 0);
            } else {
                assertEq(spendLimitInfo.lastUsedTime, timestamp);
            }
        }
    }

    function test_sessionKeyERC20SpendLimits_tokenAddressZeroFails() public {
        bytes[] memory updates = new bytes[](1);
        address token;
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (token, 1000, 0));
        vm.expectRevert(abi.encodeWithSelector(ISessionKeyPlugin.InvalidToken.selector, token));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);
    }

    function test_sessionKeyERC20SpendLimits_unknownSelectorFails() public {
        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);

        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 1 ether, 0 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that tries to call name(), a non-allowed selector.
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(token1), data: abi.encodeCall(token1.name, ()), value: 0});

        _runSessionKeyUserOp(
            calls,
            sessionKey1Private,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA23 reverted (or OOG)")
        );
    }

    function test_sessionKeyERC20SpendLimits_enforceLimit_none_basic() public {
        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);

        // Set the limit to zero
        bytes[] memory updates = new bytes[](1);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 0 ether, 0 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends 1 wei, should fail
        Call[] memory calls = new Call[](1);
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 wei)), value: 0});

        // Since the revert happens during execution, we can't check it using vm.expectRevert, since the underlyng
        // call to handleOps does not revert.
        // Instead, we assert that the transfer call did NOT happen via vm.expectCall with the count set to zero.
        vm.expectCall(address(token1), 0 wei, calls[0].data, 0);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Run a user op that spends 0 wei, should succeed
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 0 wei)), value: 0});
        vm.expectCall(address(token1), 0 wei, calls[0].data, 1);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");
    }

    // Expands on the previous test to cover the case where the spend is batched via multiple method types.
    function test_sessionKeyERC20SpendLimits_enforceLimit_none_batch() public {
        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);

        // Set the limit to zero
        bytes[] memory updates = new bytes[](1);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 0 ether, 0 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // run a multi-execution user op that spends 0 wei, should succeed.
        Call[] memory calls = new Call[](3);
        calls = new Call[](3);
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 0 wei)), value: 0});
        calls[1] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 0 wei)), value: 0});
        calls[2] =
            Call({target: address(token1), data: abi.encodeCall(token1.approve, (recipient1, 0 wei)), value: 0});

        vm.expectCall(address(token1), 0 wei, calls[0].data);
        vm.expectCall(address(token1), 0 wei, calls[1].data);
        vm.expectCall(address(token1), 0 wei, calls[2].data);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");
    }

    function test_sessionKeyERC20SpendLimits_basic_single() public {
        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);

        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 1 ether, 0 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends 1 wei, should succeed
        Call[] memory calls = new Call[](1);
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 wei)), value: 0});

        vm.expectCall(address(token1), 0 wei, calls[0].data, 1);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));

        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 wei);
        assertEq(spendLimitInfo.refreshInterval, 0);
        // Assert that the last used time is not updated when the interval is unset.
        assertEq(spendLimitInfo.lastUsedTime, 0);
    }

    // Almost a duplicate of the previous test, but asserts that subsequent calls that exceed the budget cause it
    // to fail.
    function test_sessionKeyERC20SpendLimits_exceedLimit_single() public {
        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);

        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 1 ether, 0 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends 1 wei, should succeed
        Call[] memory calls = new Call[](1);
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 wei)), value: 0});

        vm.expectCall(address(token1), 0 wei, calls[0].data, 1);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));

        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 wei);
        assertEq(spendLimitInfo.refreshInterval, 0);
        // Assert that the last used time is not updated when the interval is unset.
        assertEq(spendLimitInfo.lastUsedTime, 0);

        // Run a user op that spends 1 ether, should fail

        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 ether)), value: 0});
        vm.expectCall(address(token1), 0 wei, calls[0].data, 0);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is not updated, and remains the same as before
        spendLimitInfo = sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));

        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 wei);
        assertEq(spendLimitInfo.refreshInterval, 0);
        // Assert that the last used time is not updated when the interval is unset.
        assertEq(spendLimitInfo.lastUsedTime, 0);
    }

    function test_executeWithSessionKey_success_multipleTransfer() public {
        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);

        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 1 ether, 0 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends 3 wei, should succeed
        Call[] memory calls = new Call[](3);
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 wei)), value: 0});
        calls[1] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 wei)), value: 0});
        calls[2] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient2, 1 wei)), value: 0});

        vm.expectCall(address(token1), 0 wei, calls[0].data, 2);
        vm.expectCall(address(token1), 0 wei, calls[2].data, 1);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 3 wei);
        assertEq(spendLimitInfo.refreshInterval, 0);
        // Assert that the last used time is not updated when the interval is unset.
        assertEq(spendLimitInfo.lastUsedTime, 0);
    }

    function test_executeWithSessionKey_approveOnlyCountsIncrease() public {
        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);

        // Preemptively approve the recipient for 0.5 ether
        vm.prank(address(account1));
        token1.approve(recipient1, 0.5 ether);

        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 1 ether, 0 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends 1 ether, should succeed
        Call[] memory calls = new Call[](1);
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.approve, (recipient1, 1 ether)), value: 0});

        vm.expectCall(address(token1), 0 wei, calls[0].data, 1);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 ether);
        assertEq(spendLimitInfo.refreshInterval, 0);
        // Assert that the last used time is not updated when the interval is unset.
        assertEq(spendLimitInfo.lastUsedTime, 0);
    }

    function test_executeWithSessionKey_success_multipleApprove() public {
        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);

        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 1 ether, 0 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends 3 wei, should succeed
        Call[] memory calls = new Call[](3);
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.approve, (recipient1, 3 wei)), value: 0});
        calls[1] =
            Call({target: address(token1), data: abi.encodeCall(token1.approve, (recipient1, 2 wei)), value: 0});
        calls[2] =
            Call({target: address(token1), data: abi.encodeCall(token1.approve, (recipient2, 1 wei)), value: 0});

        vm.expectCall(address(token1), 0 wei, calls[0].data, 1);
        vm.expectCall(address(token1), 0 wei, calls[1].data, 1);
        vm.expectCall(address(token1), 0 wei, calls[2].data, 1);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 6 wei);
        assertEq(spendLimitInfo.refreshInterval, 0);
        // Assert that the last used time is not updated when the interval is unset.
        assertEq(spendLimitInfo.lastUsedTime, 0);
    }

    function test_executeWithSessionKey_success_multipleSpendFunctions() public {
        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);

        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 1 ether, 0 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends 3 wei, should succeed
        Call[] memory calls = new Call[](3);
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 wei)), value: 0});
        calls[1] = Call({
            target: address(token1),
            data: abi.encodeCall(token1.approve, (address(account1), 1 wei)),
            value: 0
        });
        calls[2] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient2, 1 wei)), value: 0});
        vm.expectCall(address(token1), 0 wei, calls[0].data, 1);
        vm.expectCall(address(token1), 0 wei, calls[1].data, 1);
        vm.expectCall(address(token1), 0 wei, calls[2].data, 1);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 3 wei);
        assertEq(spendLimitInfo.refreshInterval, 0);
        // Assert that the last used time is not updated when the interval is unset.
        assertEq(spendLimitInfo.lastUsedTime, 0);
    }

    function test_executeWithSessionKey_success_multipleTokens() public {
        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);
        token2.mint(address(account1), 100 ether);

        // Set spending limit
        bytes[] memory updates = new bytes[](2);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 1 ether, 0 days));
        updates[1] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token2), 1 ether, 0 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends 3 wei, should succeed
        Call[] memory calls = new Call[](3);
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 wei)), value: 0});
        calls[1] = Call({
            target: address(token2),
            data: abi.encodeCall(token2.approve, (address(account1), 1 wei)),
            value: 0
        });
        calls[2] =
            Call({target: address(token2), data: abi.encodeCall(token2.transfer, (recipient2, 1 wei)), value: 0});
        vm.expectCall(address(token1), 0 wei, calls[0].data, 1);
        vm.expectCall(address(token2), 0 wei, calls[1].data, 1);
        vm.expectCall(address(token2), 0 wei, calls[2].data, 1);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo1 =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo2 =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token2));
        assertEq(spendLimitInfo1.limit, 1 ether);
        assertEq(spendLimitInfo1.limitUsed, 1 wei);
        assertEq(spendLimitInfo2.limit, 1 ether);
        assertEq(spendLimitInfo2.limitUsed, 2 wei);
    }

    function test_executeWithSessionKey_failWithExceedLimit_multipleTransfer() public {
        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);

        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 1 wei, 0 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that should fail due to exceeding limit
        Call[] memory calls = new Call[](2);
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 wei)), value: 0});
        calls[1] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient2, 1 wei)), value: 0});
        // should not call due to revert on ERC20SpendLimitExceeded
        vm.expectCall(address(token1), 0 wei, calls[0].data, 0);
        vm.expectCall(address(token1), 0 wei, calls[1].data, 0);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is NOT updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 wei);
        // limit used should be 0 as all action failed.
        assertEq(spendLimitInfo.limitUsed, 0 wei);
    }

    function test_executeWithSessionKey_failWithExceedLimit_multipleSpendFunctions() public {
        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);

        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 1 wei, 0 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that should fail due to exceeding limit
        Call[] memory calls = new Call[](3);
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 wei)), value: 0});
        calls[1] = Call({
            target: address(token1),
            data: abi.encodeCall(token1.approve, (address(account1), 1 wei)),
            value: 0
        });
        calls[2] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient2, 1 wei)), value: 0});
        // should not call due to revert on ERC20SpendLimitExceeded
        vm.expectCall(address(token1), 0 wei, calls[0].data, 0);
        vm.expectCall(address(token1), 0 wei, calls[1].data, 0);
        vm.expectCall(address(token1), 0 wei, calls[2].data, 0);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");
        // Assert that the limit is NOT updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 wei);
        // limit used should be 0 as all action failed.
        assertEq(spendLimitInfo.limitUsed, 0 wei);
    }

    function test_executeWithSessionKey_failWithExceedLimit_overflow() public {
        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);

        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 1 wei, 0 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that should fail due to exceeding limit
        Call[] memory calls = new Call[](3);
        calls[0] = Call({
            target: address(token1),
            data: abi.encodeCall(token1.transfer, (recipient1, type(uint256).max)),
            value: 0
        });
        calls[1] = Call({
            target: address(token1),
            data: abi.encodeCall(token1.approve, (address(account1), type(uint256).max)),
            value: 0
        });
        // should not call due to revert on ERC20SpendLimitExceeded
        vm.expectCall(address(token1), 0 wei, calls[0].data, 0);
        vm.expectCall(address(token1), 0 wei, calls[1].data, 0);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");
        // Assert that the limit is NOT updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 wei);
        // limit used should be 0 as all action failed.
        assertEq(spendLimitInfo.limitUsed, 0 wei);
    }

    function test_executeWithSessionKey_failWithExceedLimit_multipleTokens() public {
        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);
        token2.mint(address(account1), 100 ether);

        // Set spending limit
        bytes[] memory updates = new bytes[](2);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 1 wei, 0 days));
        updates[1] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token2), 1 wei, 0 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that should fail due to exceeding limit
        Call[] memory calls = new Call[](3);
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 2 wei)), value: 0});
        calls[1] = Call({
            target: address(token2),
            data: abi.encodeCall(token2.approve, (address(account1), 2 wei)),
            value: 0
        });
        calls[2] =
            Call({target: address(token2), data: abi.encodeCall(token2.transfer, (recipient2, 1 wei)), value: 0});
        vm.expectCall(address(token1), 0 wei, calls[0].data, 0);
        vm.expectCall(address(token2), 0 wei, calls[1].data, 0);
        vm.expectCall(address(token2), 0 wei, calls[2].data, 0);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is NOT updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo1 =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo2 =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token2));
        assertEq(spendLimitInfo1.limit, 1 wei);
        // limit used should be 0 as all action failed.
        assertEq(spendLimitInfo1.limitUsed, 0 wei);
        assertEq(spendLimitInfo2.limit, 1 wei);
        // limit used should be 0 as all action failed.
        assertEq(spendLimitInfo2.limitUsed, 0 wei);
    }

    function test_executeWithSessionKey_refreshInterval_singleTransfer() public {
        // Set the time to the a unix timestamp
        uint256 time0 = 1698708080;
        vm.warp(time0);

        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);

        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 1 ether, 1 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends 1 wei, should succeed
        Call[] memory calls = new Call[](1);
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 wei)), value: 0});
        vm.expectCall(address(token1), 0 wei, calls[0].data, 1);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit and last used time is updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 wei);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0);

        // Run a user op that spends 1 ETH, should fail due to over spending
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.approve, (recipient1, 1 ether)), value: 0});
        vm.expectCall(address(token1), 0 wei, calls[0].data, 0);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit and last used time is NOT updated
        spendLimitInfo = sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 wei);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0);

        // warp to when the interval resets
        vm.warp(time0 + 1 days);

        // Run a user op that spends 1 ether, should succeed
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 ether)), value: 0});
        vm.expectCall(address(token1), 0 wei, calls[0].data, 1);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is now updated and the last used timestamp is set.
        spendLimitInfo = sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 ether);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0 + 1 days);
    }

    function test_executeWithSessionKey_refreshInterval_multipleTransfer() public {
        // Set the time to the a unix timestamp
        uint256 time0 = 1698708080;
        vm.warp(time0);

        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);

        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 1 ether, 1 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends 1 wei, should succeed
        Call[] memory calls = new Call[](2);
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 wei)), value: 0});
        calls[1] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 wei)), value: 0});
        vm.expectCall(address(token1), 0 wei, calls[0].data, 2);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit and last used time is updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 2 wei);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0);

        // Run a user op that spends 1 ETH, should fail due to over spending
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 ether)), value: 0});
        vm.expectCall(address(token1), 0 wei, calls[0].data, 0);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit and last used time is NOT updated
        spendLimitInfo = sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 2 wei);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0);

        // warp to when the interval resets
        vm.warp(time0 + 1 days);

        // Run a user op that spends 1 ether, should succeed
        calls[0] = Call({
            target: address(token1),
            data: abi.encodeCall(token1.transfer, (recipient1, 0.5 ether)),
            value: 0
        });
        calls[1] = Call({
            target: address(token1),
            data: abi.encodeCall(token1.transfer, (recipient1, 0.5 ether)),
            value: 0
        });
        vm.expectCall(address(token1), 0 wei, calls[0].data, 2);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is now updated and the last used timestamp is set.
        spendLimitInfo = sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 ether);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0 + 1 days);
    }

    function test_executeWithSessionKey_refreshInterval_multipleApprove() public {
        // Set the time to the a unix timestamp
        uint256 time0 = 1698708080;
        vm.warp(time0);

        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);

        // Set the limit to 1 ether
        bytes[] memory updates = new bytes[](1);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 1 ether, 1 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends 1 wei and approve 1 wei, should succeed
        Call[] memory calls = new Call[](2);
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 wei)), value: 0});
        calls[1] =
            Call({target: address(token1), data: abi.encodeCall(token1.approve, (recipient1, 1 wei)), value: 0});
        vm.expectCall(address(token1), 0 wei, calls[0].data, 1);
        vm.expectCall(address(token1), 0 wei, calls[1].data, 1);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");
        // Assert that the limit and last used time is updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 2 wei);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0);

        // Run a user op that spends 1 ETH, should fail due to over spending
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 ether)), value: 0});
        vm.expectCall(address(token1), 0 wei, calls[0].data, 0);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");
        // Assert that the limit and last used time is NOT updated
        spendLimitInfo = sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 2 wei);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0);

        // warp to when the interval resets
        vm.warp(time0 + 1 days);

        // Run a user op that spends 1 ether, should succeed
        calls[0] = Call({
            target: address(token1),
            data: abi.encodeCall(token1.approve, (recipient1, 0.5 ether)),
            value: 0
        });
        calls[1] = Call({
            target: address(token1),
            // previous approved 1 wei should not matter to limitUsed
            data: abi.encodeCall(token1.approve, (recipient1, 0.5 ether)),
            value: 0
        });
        vm.expectCall(address(token1), 0 wei, calls[0].data, 2);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");
        // Assert that the limit is now updated and the last used timestamp is set.
        spendLimitInfo = sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 ether);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0 + 1 days);
    }

    function test_executeWithSessionKey_refreshInterval_multipleSpendFunctions() public {
        // Set the time to the a unix timestamp
        uint256 time0 = 1698708080;
        vm.warp(time0);

        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);

        // Set the limit to 1 ether over 1 day
        bytes[] memory updates = new bytes[](1);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 1 ether, 1 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends within limit, should succeed
        Call[] memory calls = new Call[](2);
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 wei)), value: 0});
        calls[1] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 2 wei)), value: 0});
        vm.expectCall(address(token1), 0 wei, calls[0].data, 1);
        vm.expectCall(address(token1), 0 wei, calls[1].data, 1);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");
        // Assert that the limit and last used time is updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 3 wei);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0);

        // Run a user op that spends 1 ETH, should fail due to over spending
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.approve, (recipient1, 1 ether)), value: 0});
        vm.expectCall(address(token1), 0 wei, calls[0].data, 0);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");
        // Assert that the limit and last used time is NOT updated
        spendLimitInfo = sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 3 wei);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0);

        // warp to when the interval resets
        vm.warp(time0 + 1 days);

        // Run a user op that spends 1 ether, should succeed
        calls[0] = Call({
            target: address(token1),
            data: abi.encodeCall(token1.transfer, (recipient1, 0.5 ether)),
            value: 0
        });
        calls[1] = Call({
            target: address(token1),
            data: abi.encodeCall(token1.approve, (recipient1, 0.5 ether)),
            value: 0
        });
        vm.expectCall(address(token1), 0 wei, calls[0].data, 1);
        vm.expectCall(address(token1), 0 wei, calls[1].data, 1);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");
        // Assert that the limit is now updated and the last used timestamp is set.
        spendLimitInfo = sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 1 ether);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0 + 1 days);
    }

    function test_executeWithSessionKey_refreshInterval_failWithSomeTokenLimit() public {
        // Set the time to the a unix timestamp
        uint256 time0 = 1698708080;
        vm.warp(time0);

        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);
        token2.mint(address(account1), 100 ether);

        // Set the limit to 1 ether, over 1 day and 10 days, respectively
        bytes[] memory updates = new bytes[](2);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 1 ether, 1 days));
        updates[1] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token2), 1 ether, 10 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends max limit in interval, should succeed
        Call[] memory calls = new Call[](2);
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 ether)), value: 0});
        calls[1] =
            Call({target: address(token2), data: abi.encodeCall(token2.transfer, (recipient1, 1 ether)), value: 0});
        vm.expectCall(address(token1), 0 wei, calls[0].data, 1);
        vm.expectCall(address(token2), 0 wei, calls[1].data, 1);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit and last used time is updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo1 =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo2 =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token2));
        assertEq(spendLimitInfo1.limit, 1 ether);
        assertEq(spendLimitInfo1.limitUsed, 1 ether);
        assertEq(spendLimitInfo2.limit, 1 ether);
        assertEq(spendLimitInfo2.limitUsed, 1 ether);

        // warp to when the interval resets
        vm.warp(time0 + 1 days);

        // Run a user op that spends within limit for token 2, exceed limit for token 2 , should fail due to over
        // spending on token2
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.transfer, (recipient1, 1 wei)), value: 0});
        calls[1] =
            Call({target: address(token2), data: abi.encodeCall(token2.transfer, (recipient1, 1 wei)), value: 0});
        vm.expectCall(address(token1), 0 wei, calls[0].data, 0);
        vm.expectCall(address(token2), 0 wei, calls[1].data, 0);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit and last used time is NOT updated
        spendLimitInfo1 = sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        spendLimitInfo2 = sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token2));
        assertEq(spendLimitInfo1.limit, 1 ether);
        assertEq(spendLimitInfo1.limitUsed, 1 ether);
        assertEq(spendLimitInfo1.lastUsedTime, time0);
        assertEq(spendLimitInfo2.limit, 1 ether);
        assertEq(spendLimitInfo2.limitUsed, 1 ether);
        assertEq(spendLimitInfo2.lastUsedTime, time0);

        // warp to when the interval resets
        vm.warp(time0 + 10 days);

        // Enough time passed, run a user op that spends max limit in interval, should succeed
        calls[0] =
            Call({target: address(token1), data: abi.encodeCall(token1.approve, (recipient1, 1 ether)), value: 0});
        calls[1] =
            Call({target: address(token2), data: abi.encodeCall(token2.approve, (recipient1, 1 ether)), value: 0});
        vm.expectCall(address(token1), 0 wei, calls[0].data, 1);
        vm.expectCall(address(token2), 0 wei, calls[1].data, 1);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit is now updated and the last used timestamp is set.
        spendLimitInfo1 = sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        spendLimitInfo2 = sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token2));
        assertEq(spendLimitInfo1.limit, 1 ether);
        assertEq(spendLimitInfo1.limitUsed, 1 ether);
        assertEq(spendLimitInfo1.lastUsedTime, time0 + 10 days);
        assertEq(spendLimitInfo2.limit, 1 ether);
        assertEq(spendLimitInfo2.limitUsed, 1 ether);
        assertEq(spendLimitInfo2.lastUsedTime, time0 + 10 days);
    }

    function test_sessionKeyERC20Limits_refreshInterval_failWithExceedNextLimit() public {
        // Set the time to the a unix timestamp
        uint256 time0 = 1698708080;
        vm.warp(time0);

        // Give the account a starting balance
        token1.mint(address(account1), 100 ether);

        // Set the limit to 1 ether over 1 day
        bytes[] memory updates = new bytes[](1);
        updates[0] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setERC20SpendLimit, (address(token1), 1 ether, 1 days));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Run a user op that spends 0.5 ether, should succeed
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(token1),
            data: abi.encodeCall(token1.transfer, (recipient1, 0.5 ether)),
            value: 0
        });
        vm.expectCall(address(token1), 0 wei, calls[0].data, 1);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that the limit and last used time is updated
        ISessionKeyPlugin.SpendLimitInfo memory spendLimitInfo =
            sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 0.5 ether);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0);

        // Skip forward to the next interval
        skip(1 days + 1 minutes);

        // Attempt a user operation that spends 1.5 ether (Exceeds limit, should fail).
        calls[0] = Call({
            target: address(token1),
            data: abi.encodeCall(token1.transfer, (recipient1, 1.5 ether)),
            value: 0
        });
        vm.expectCall(address(token1), 0 wei, calls[0].data, 0);
        _runSessionKeyUserOp(calls, sessionKey1Private, "");

        // Assert that limits are not updated
        spendLimitInfo = sessionKeyPlugin.getERC20SpendLimitInfo(address(account1), sessionKey1, address(token1));
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 0.5 ether);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0);
    }

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
