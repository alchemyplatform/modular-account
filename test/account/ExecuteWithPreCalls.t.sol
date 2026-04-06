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
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {IAccountExecute} from "@eth-infinitism/account-abstraction/interfaces/IAccountExecute.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {IModularAccountBase} from "../../src/interfaces/IModularAccountBase.sol";

import {Counter} from "../mocks/Counter.sol";
import {ComprehensiveModule} from "../mocks/modules/ComprehensiveModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract ExecuteWithPreCallsTest is AccountTestBase {
    Counter public counter;
    address public ethRecipient;

    event ExecuteWithPreCallsResult(bool indexed success, bytes[] results);

    function setUp() public override {
        _revertSnapshot = vm.snapshotState();
        ethRecipient = makeAddr("ethRecipient");
        counter = new Counter();
        counter.increment(); // amortize zero->nonzero storage cost
    }

    // ─── Happy path: preCalls succeed, calls succeed ───

    function test_executeWithPreCalls_allSucceed_userOp() public withSMATest {
        Call[] memory preCalls = new Call[](1);
        preCalls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        _runUserOp(abi.encodeCall(IModularAccountBase.executeWithPreCalls, (preCalls, calls)));

        // counter started at 1, incremented twice
        assertEq(counter.number(), 3);
    }

    function test_executeWithPreCalls_allSucceed_runtime() public withSMATest {
        Call[] memory preCalls = new Call[](1);
        preCalls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        _runtimeCall(abi.encodeCall(IModularAccountBase.executeWithPreCalls, (preCalls, calls)));

        assertEq(counter.number(), 3);
    }

    // ─── PreCalls succeed, calls revert — should NOT revert overall ───

    function test_executeWithPreCalls_callsRevert_userOp() public withSMATest {
        Call[] memory preCalls = new Call[](1);
        preCalls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        // decrement on a fresh counter (value=0 after setup increment puts it at 1... but we need it to fail)
        // Use setNumber(0) first in preCalls, then decrement in calls to cause underflow
        preCalls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.setNumber, (0))});

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.decrement, ())});

        // This should NOT revert — the calls batch fails but the overall UO succeeds
        _runUserOp(abi.encodeCall(IModularAccountBase.executeWithPreCalls, (preCalls, calls)));

        // preCalls set number to 0, calls reverted so decrement didn't happen
        assertEq(counter.number(), 0);
    }

    function test_executeWithPreCalls_callsRevert_runtime() public withSMATest {
        Call[] memory preCalls = new Call[](1);
        preCalls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.setNumber, (0))});

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.decrement, ())});

        _runtimeCall(abi.encodeCall(IModularAccountBase.executeWithPreCalls, (preCalls, calls)));

        assertEq(counter.number(), 0);
    }

    // ─── Calls revert atomically: state changes in calls batch are rolled back ───

    function test_executeWithPreCalls_callsRevertAtomically_runtime() public withSMATest {
        Call[] memory preCalls = new Call[](1);
        preCalls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        // First call succeeds (increment), second call fails (decrement from 0 via setNumber)
        Call[] memory calls = new Call[](3);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())}); // 3
        calls[1] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.setNumber, (0))}); // 0
        calls[2] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.decrement, ())}); // revert

        _runtimeCall(abi.encodeCall(IModularAccountBase.executeWithPreCalls, (preCalls, calls)));

        // preCalls incremented (1 -> 2), calls batch reverted so all 3 call state changes rolled back
        assertEq(counter.number(), 2);
    }

    // ─── PreCalls revert — entire call reverts ───

    function test_executeWithPreCalls_preCallsRevert_userOp() public withSMATest {
        Call[] memory preCalls = new Call[](2);
        preCalls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.setNumber, (0))});
        preCalls[1] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.decrement, ())});

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        // PreCalls revert during execution phase. The EntryPoint catches this and emits
        // UserOperationRevertReason rather than reverting the whole handleOps.
        // The UO is marked as failed (success=false in UserOperationEvent).
        _runUserOp(abi.encodeCall(IModularAccountBase.executeWithPreCalls, (preCalls, calls)));

        // Counter unchanged from setUp — the entire execution was rolled back by the EntryPoint
        assertEq(counter.number(), 1);
    }

    function test_executeWithPreCalls_preCallsRevert_runtime() public withSMATest {
        Call[] memory preCalls = new Call[](2);
        preCalls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.setNumber, (0))});
        preCalls[1] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.decrement, ())});

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        // Should revert
        _runtimeCallExpFail(
            abi.encodeCall(IModularAccountBase.executeWithPreCalls, (preCalls, calls)),
            abi.encodePacked(hex"4e487b71", abi.encode(uint256(0x11)))
        );

        assertEq(counter.number(), 1);
    }

    // ─── Empty arrays ───

    function test_executeWithPreCalls_emptyCalls_runtime() public withSMATest {
        Call[] memory preCalls = new Call[](1);
        preCalls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        Call[] memory calls = new Call[](0);

        _runtimeCall(abi.encodeCall(IModularAccountBase.executeWithPreCalls, (preCalls, calls)));

        assertEq(counter.number(), 2);
    }

    function test_executeWithPreCalls_emptyPreCalls_runtime() public withSMATest {
        Call[] memory preCalls = new Call[](0);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        _runtimeCall(abi.encodeCall(IModularAccountBase.executeWithPreCalls, (preCalls, calls)));

        assertEq(counter.number(), 2);
    }

    // ─── ETH value forwarding ───

    function test_executeWithPreCalls_ethSend_runtime() public withSMATest {
        Call[] memory preCalls = new Call[](1);
        preCalls[0] = Call({target: ethRecipient, value: 1 wei, data: ""});

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: ethRecipient, value: 2 wei, data: ""});

        _runtimeCall(abi.encodeCall(IModularAccountBase.executeWithPreCalls, (preCalls, calls)));

        assertEq(ethRecipient.balance, 3 wei);
    }

    // ─── Event emission ───

    function test_executeWithPreCalls_emitsEvent_success_runtime() public withSMATest {
        Call[] memory preCalls = new Call[](0);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        // We expect the event with success=true
        vm.expectEmit(true, false, false, false);
        emit ExecuteWithPreCallsResult(true, new bytes[](0)); // topic check only (success=true)

        _runtimeCall(abi.encodeCall(IModularAccountBase.executeWithPreCalls, (preCalls, calls)));
    }

    function test_executeWithPreCalls_emitsEvent_failure_runtime() public withSMATest {
        Call[] memory preCalls = new Call[](1);
        preCalls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.setNumber, (0))});

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.decrement, ())});

        // We expect the event with success=false
        vm.expectEmit(true, false, false, false);
        emit ExecuteWithPreCallsResult(false, new bytes[](0));

        _runtimeCall(abi.encodeCall(IModularAccountBase.executeWithPreCalls, (preCalls, calls)));
    }

    // ─── Self-call re-entrancy protections ───

    function test_executeWithPreCalls_selfCallRecursion_execute_runtime() public withSMATest {
        Call[] memory preCalls = new Call[](1);
        preCalls[0] = Call({
            target: address(account1),
            value: 0,
            data: abi.encodeCall(
                IModularAccount.execute, (address(counter), 0, abi.encodeCall(Counter.increment, ()))
            )
        });

        Call[] memory calls = new Call[](0);

        // Self-call to execute should be blocked
        _runtimeCall(
            abi.encodeCall(IModularAccountBase.executeWithPreCalls, (preCalls, calls)),
            abi.encodeWithSelector(ModularAccountBase.SelfCallRecursionDepthExceeded.selector)
        );
    }

    function test_executeWithPreCalls_selfCallRecursion_executeBatch_runtime() public withSMATest {
        Call[] memory innerCalls = new Call[](1);
        innerCalls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        Call[] memory preCalls = new Call[](1);
        preCalls[0] = Call({
            target: address(account1),
            value: 0,
            data: abi.encodeCall(IModularAccount.executeBatch, (innerCalls))
        });

        Call[] memory calls = new Call[](0);

        _runtimeCall(
            abi.encodeCall(IModularAccountBase.executeWithPreCalls, (preCalls, calls)),
            abi.encodeWithSelector(ModularAccountBase.SelfCallRecursionDepthExceeded.selector)
        );
    }

    function test_executeWithPreCalls_selfCallRecursion_executeWithPreCalls_runtime() public withSMATest {
        Call[] memory innerPreCalls = new Call[](0);
        Call[] memory innerCalls = new Call[](0);

        Call[] memory preCalls = new Call[](1);
        preCalls[0] = Call({
            target: address(account1),
            value: 0,
            data: abi.encodeCall(IModularAccountBase.executeWithPreCalls, (innerPreCalls, innerCalls))
        });

        Call[] memory calls = new Call[](0);

        _runtimeCall(
            abi.encodeCall(IModularAccountBase.executeWithPreCalls, (preCalls, calls)),
            abi.encodeWithSelector(ModularAccountBase.SelfCallRecursionDepthExceeded.selector)
        );
    }

    function test_executeWithPreCalls_selfCallRecursion_inCalls_runtime() public withSMATest {
        Call[] memory preCalls = new Call[](0);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(account1),
            value: 0,
            data: abi.encodeCall(
                IModularAccount.execute, (address(counter), 0, abi.encodeCall(Counter.increment, ()))
            )
        });

        _runtimeCall(
            abi.encodeCall(IModularAccountBase.executeWithPreCalls, (preCalls, calls)),
            abi.encodeWithSelector(ModularAccountBase.SelfCallRecursionDepthExceeded.selector)
        );
    }

    // ─── Nested in executeBatch: executeWithPreCalls blocked as self-call target ───

    function test_executeBatch_nestedExecuteWithPreCalls_blocked_runtime() public withSMATest {
        Call[] memory innerPreCalls = new Call[](0);
        Call[] memory innerCalls = new Call[](0);

        Call[] memory batchCalls = new Call[](1);
        batchCalls[0] = Call({
            target: address(account1),
            value: 0,
            data: abi.encodeCall(IModularAccountBase.executeWithPreCalls, (innerPreCalls, innerCalls))
        });

        _runtimeCall(
            abi.encodeCall(IModularAccount.executeBatch, (batchCalls)),
            abi.encodeWithSelector(ModularAccountBase.SelfCallRecursionDepthExceeded.selector)
        );
    }

    // ─── Self-calls to non-execute functions in preCalls are allowed with proper validation ───

    function test_executeWithPreCalls_selfCallToModuleFunction_runtime() public withSMATest {
        ComprehensiveModule comprehensiveModule = new ComprehensiveModule();

        bytes4[] memory validationSelectors = new bytes4[](2);
        validationSelectors[0] = ComprehensiveModule.foo.selector;
        validationSelectors[1] = IModularAccountBase.executeWithPreCalls.selector;

        vm.startPrank(address(entryPoint));
        account1.installExecution(address(comprehensiveModule), comprehensiveModule.executionManifest(), "");
        account1.installValidation(
            ValidationConfigLib.pack(
                ModuleEntityLib.pack(
                    address(comprehensiveModule), uint32(ComprehensiveModule.EntityId.VALIDATION)
                ),
                false,
                false,
                true
            ),
            validationSelectors,
            "",
            new bytes[](0)
        );
        vm.stopPrank();

        Call[] memory preCalls = new Call[](1);
        preCalls[0] = Call({target: address(account1), value: 0, data: abi.encodeCall(ComprehensiveModule.foo, ())});

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        // Use comprehensive module validation (selector-associated)
        vm.prank(owner1);
        account1.executeWithRuntimeValidation(
            abi.encodeCall(IModularAccountBase.executeWithPreCalls, (preCalls, calls)),
            _encodeSignature(
                ModuleEntityLib.pack(
                    address(comprehensiveModule), uint32(ComprehensiveModule.EntityId.VALIDATION)
                ),
                SELECTOR_ASSOCIATED_VALIDATION,
                ""
            )
        );

        assertEq(counter.number(), 2);
    }
}
