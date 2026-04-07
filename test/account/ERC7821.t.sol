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

pragma solidity ^0.8.28;

import {Call, IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {IERC7821} from "../../src/interfaces/IERC7821.sol";

import {Counter} from "../mocks/Counter.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract ERC7821Test is AccountTestBase {
    Counter public counter;
    address public ethRecipient;

    // ERC-7821 execution modes
    bytes32 internal constant MODE_BATCH =
        bytes32(uint256(0x0100000000000000000000000000000000000000000000000000000000000000));
    bytes32 internal constant MODE_BATCH_OPDATA =
        bytes32(uint256(0x0100000000007821000100000000000000000000000000000000000000000000));

    function setUp() public override {
        _revertSnapshot = vm.snapshotState();
        counter = new Counter();
        ethRecipient = makeAddr("ethRecipient");
    }

    // ──────────────────────────────────────────────
    // supportsExecutionMode
    // ──────────────────────────────────────────────

    function test_supportsExecutionMode_batch() external view {
        assertTrue(account1.supportsExecutionMode(MODE_BATCH));
    }

    function test_supportsExecutionMode_batchWithOpData() external view {
        assertTrue(account1.supportsExecutionMode(MODE_BATCH_OPDATA));
    }

    function test_supportsExecutionMode_unsupported() external view {
        // Single call mode (0x00...) is not supported
        assertFalse(account1.supportsExecutionMode(bytes32(0)));
        // Unsupported mode byte
        assertFalse(account1.supportsExecutionMode(bytes32(uint256(1))));
    }

    function test_supportsExecutionMode_freeBytes() external view {
        // Modes with non-zero free bytes [10..31] should still be supported
        bytes32 modeWithFreeBytes = MODE_BATCH | bytes32(uint256(0xdeadbeef));
        assertTrue(account1.supportsExecutionMode(modeWithFreeBytes));
    }

    // ──────────────────────────────────────────────
    // supportsInterface
    // ──────────────────────────────────────────────

    function test_supportsInterface_erc7821() external withSMATest {
        assertTrue(account1.supportsInterface(type(IERC7821).interfaceId));
    }

    // ──────────────────────────────────────────────
    // execute via UserOp (mode 1: batch, no opData)
    // ──────────────────────────────────────────────

    function test_erc7821_singleCall_userOp() external withSMATest {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        bytes memory executionData = abi.encode(calls);
        _runUserOp(abi.encodeCall(IERC7821.execute, (MODE_BATCH, executionData)));

        assertEq(counter.number(), 1);
    }

    function test_erc7821_batchCalls_userOp() external withSMATest {
        Call[] memory calls = new Call[](3);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});
        calls[1] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});
        calls[2] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        bytes memory executionData = abi.encode(calls);
        _runUserOp(abi.encodeCall(IERC7821.execute, (MODE_BATCH, executionData)));

        assertEq(counter.number(), 3);
    }

    function test_erc7821_ethTransfer_userOp() external withSMATest {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: ethRecipient, value: 1 ether, data: ""});

        bytes memory executionData = abi.encode(calls);
        _runUserOp(abi.encodeCall(IERC7821.execute, (MODE_BATCH, executionData)));

        assertEq(ethRecipient.balance, 1 ether);
    }

    // ──────────────────────────────────────────────
    // execute via UserOp (mode 2: batch with opData)
    // ──────────────────────────────────────────────

    function test_erc7821_mode2_userOp() external withSMATest {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        // Mode 2 with opData
        bytes memory executionData = abi.encode(calls, bytes("some opData"));
        _runUserOp(abi.encodeCall(IERC7821.execute, (MODE_BATCH_OPDATA, executionData)));

        assertEq(counter.number(), 1);
    }

    function test_erc7821_mode2_noOpData_userOp() external withSMATest {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        // Mode 2 but without opData (just calls)
        bytes memory executionData = abi.encode(calls);
        _runUserOp(abi.encodeCall(IERC7821.execute, (MODE_BATCH_OPDATA, executionData)));

        assertEq(counter.number(), 1);
    }

    // ──────────────────────────────────────────────
    // address(0) replacement
    // ──────────────────────────────────────────────

    function test_erc7821_addressZeroReplacement_userOp() external withSMATest {
        // address(0) in target should be replaced with address(this) i.e. the account
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(0), value: 0, data: abi.encodeCall(IModularAccount.accountId, ())});

        bytes memory executionData = abi.encode(calls);
        // Should not revert - calls account's own accountId()
        _runUserOp(abi.encodeCall(IERC7821.execute, (MODE_BATCH, executionData)));
    }

    // ──────────────────────────────────────────────
    // execute via runtime validation
    // ──────────────────────────────────────────────

    function test_erc7821_singleCall_runtime() external withSMATest {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        bytes memory executionData = abi.encode(calls);
        _runtimeCall(abi.encodeCall(IERC7821.execute, (MODE_BATCH, executionData)));

        assertEq(counter.number(), 1);
    }

    function test_erc7821_batchCalls_runtime() external withSMATest {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});
        calls[1] = Call({target: ethRecipient, value: 1 ether, data: ""});

        bytes memory executionData = abi.encode(calls);
        _runtimeCall(abi.encodeCall(IERC7821.execute, (MODE_BATCH, executionData)));

        assertEq(counter.number(), 1);
        assertEq(ethRecipient.balance, 1 ether);
    }

    // ──────────────────────────────────────────────
    // reverts
    // ──────────────────────────────────────────────

    function test_erc7821_revert_unsupportedMode() external {
        Call[] memory calls = new Call[](0);
        bytes memory executionData = abi.encode(calls);

        _runtimeCallExpFail(
            abi.encodeCall(IERC7821.execute, (bytes32(0), executionData)),
            abi.encodeWithSelector(ModularAccountBase.UnsupportedExecutionMode.selector)
        );
    }

    function test_erc7821_revert_callFails_runtime() external withSMATest {
        // Batch where the second call fails should revert atomically
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});
        // Second call sends more ETH than the account has
        calls[1] = Call({target: ethRecipient, value: 200 ether, data: ""});

        bytes memory executionData = abi.encode(calls);

        // Should revert - the batch fails atomically. First call's effects are rolled back.
        _runtimeCallExpFail(abi.encodeCall(IERC7821.execute, (MODE_BATCH, executionData)), "");

        // Counter should not have been incremented (atomic revert)
        assertEq(counter.number(), 0);
    }

    function test_erc7821_emptyCalls_userOp() external withSMATest {
        // Empty calls array should succeed
        Call[] memory calls = new Call[](0);
        bytes memory executionData = abi.encode(calls);
        _runUserOp(abi.encodeCall(IERC7821.execute, (MODE_BATCH, executionData)));
    }
}
