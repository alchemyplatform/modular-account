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

import {DIRECT_CALL_VALIDATION_ENTITY_ID} from "@erc6900/reference-implementation/helpers/Constants.sol";
import {Call, IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {PreCallExecutionModule} from "../../src/modules/execution/PreCallExecutionModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

// ── Helper target contract ───────────────────────────────────────────────────

contract Counter {
    uint256 public count;

    function increment() external {
        count++;
    }

    function requireAbove(uint256 threshold) external view {
        require(count > threshold, "Counter: not above threshold");
    }

    function alwaysReverts() external pure {
        revert("intentional revert");
    }
}

// ── Core tests ───────────────────────────────────────────────────────────────

contract PreCallExecutionModuleTest is AccountTestBase {
    PreCallExecutionModule public module;
    Counter public counter;

    event CallsExecuted(bool indexed success, bytes result);

    function setUp() public override {
        _revertSnapshot = vm.snapshotState();

        module = new PreCallExecutionModule();
        counter = new Counter();

        _installModule();
    }

    // ── Installation ─────────────────────────────────────────────────────

    function _installModule() internal {
        // Install the execution function (registers executeWithPreCalls selector).
        _runtimeCall(
            abi.encodeCall(account1.installExecution, (address(module), module.executionManifest(), ""))
        );

        // Install the module as a global direct-call validator so it can call executeBatch back on the account.
        _runtimeCall(
            abi.encodeCall(
                account1.installValidation,
                (
                    ValidationConfigLib.pack(
                        address(module),
                        DIRECT_CALL_VALIDATION_ENTITY_ID,
                        true, // isGlobal — required to call executeBatch
                        false, // isSignatureValidation
                        false // isUserOpValidation
                    ),
                    new bytes4[](0),
                    "",
                    new bytes[](0)
                )
            )
        );
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    function _executeWithPreCalls(Call[] memory preCalls, Call[] memory calls) internal {
        _runUserOp(abi.encodeCall(PreCallExecutionModule.executeWithPreCalls, (preCalls, calls)));
    }

    // ── Tests: pre-calls and calls both succeed ─────────────────────────

    function test_bothSucceed() public {
        Call[] memory preCalls = new Call[](1);
        preCalls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        vm.expectEmit(true, false, false, false, address(module));
        emit CallsExecuted(true, "");

        _executeWithPreCalls(preCalls, calls);

        assertEq(counter.count(), 2);
    }

    // ── Tests: pre-calls revert → UO inner call fails ───────────────────

    function test_preCallsRevert_uoFails() public {
        Call[] memory preCalls = new Call[](1);
        preCalls[0] =
            Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.alwaysReverts, ())});

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        _executeWithPreCalls(preCalls, calls);

        // The inner call reverted; state changes from neither phase persist.
        assertEq(counter.count(), 0);
    }

    // ── Tests: pre-calls pass, calls revert → UO succeeds ───────────────

    function test_callsRevert_uoSucceeds() public {
        Call[] memory preCalls = new Call[](1);
        preCalls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        Call[] memory calls = new Call[](1);
        calls[0] =
            Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.alwaysReverts, ())});

        vm.expectEmit(true, false, false, false, address(module));
        emit CallsExecuted(false, "");

        _executeWithPreCalls(preCalls, calls);

        // Only the pre-call increment persists.
        assertEq(counter.count(), 1);
    }

    // ── Tests: pre-calls as precondition guard ──────────────────────────

    function test_preCallsAsPreconditionCheck() public {
        // Seed the counter so the precondition passes.
        counter.increment();

        Call[] memory preCalls = new Call[](1);
        preCalls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.requireAbove, (0))});

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        vm.expectEmit(true, false, false, false, address(module));
        emit CallsExecuted(true, "");

        _executeWithPreCalls(preCalls, calls);

        assertEq(counter.count(), 2);
    }

    function test_preconditionFails_uoFails() public {
        // counter is 0, so requireAbove(0) will revert.
        Call[] memory preCalls = new Call[](1);
        preCalls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.requireAbove, (0))});

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        _executeWithPreCalls(preCalls, calls);

        assertEq(counter.count(), 0);
    }

    // ── Tests: edge cases ───────────────────────────────────────────────

    function test_emptyPreCalls_callsSucceed() public {
        Call[] memory preCalls = new Call[](0);

        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});
        calls[1] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        vm.expectEmit(true, false, false, false, address(module));
        emit CallsExecuted(true, "");

        _executeWithPreCalls(preCalls, calls);

        assertEq(counter.count(), 2);
    }

    function test_emptyCallsAndPreCalls() public {
        Call[] memory preCalls = new Call[](0);
        Call[] memory calls = new Call[](0);

        // No event expected — neither branch fires.
        _executeWithPreCalls(preCalls, calls);

        assertEq(counter.count(), 0);
    }

    function test_multiplePreCalls_partialRevert() public {
        // First pre-call succeeds but second reverts — the whole batch reverts,
        // so the first increment does not persist.
        Call[] memory preCalls = new Call[](2);
        preCalls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});
        preCalls[1] =
            Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.alwaysReverts, ())});

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        _executeWithPreCalls(preCalls, calls);

        assertEq(counter.count(), 0);
    }
}

// ── Deferred-action test ─────────────────────────────────────────────────────
// Installs the execution module + direct-call validation via a deferred action
// and uses executeWithPreCalls in the same user operation.

contract PreCallExecutionModuleDeferredTest is AccountTestBase {
    using MessageHashUtils for bytes32;

    PreCallExecutionModule public module;
    Counter public counter;

    event CallsExecuted(bool indexed success, bytes result);

    function setUp() public override {
        _revertSnapshot = vm.snapshotState();
        // Deploy helpers but do NOT install the module — the deferred action will.
        module = new PreCallExecutionModule();
        counter = new Counter();
    }

    function test_deferredInstallAndUse() public {
        // Build the deferred action: executeBatch with two self-calls to install everything in one shot.

        Call[] memory deferredCalls = new Call[](2);

        // a) Install the execution module (registers executeWithPreCalls selector).
        deferredCalls[0] = Call({
            target: address(account1),
            value: 0,
            data: abi.encodeCall(IModularAccount.installExecution, (address(module), module.executionManifest(), ""))
        });

        // b) Install the module as a global direct-call validator.
        deferredCalls[1] = Call({
            target: address(account1),
            value: 0,
            data: abi.encodeCall(
                IModularAccount.installValidation,
                (
                    ValidationConfigLib.pack(
                        address(module),
                        DIRECT_CALL_VALIDATION_ENTITY_ID,
                        true, // isGlobal
                        false, // isSignatureValidation
                        false // isUserOpValidation
                    ),
                    new bytes4[](0),
                    "",
                    new bytes[](0)
                )
            )
        });

        bytes memory deferredAction = abi.encodeCall(IModularAccount.executeBatch, (deferredCalls));

        // Build the UO callData.
        Call[] memory preCalls = new Call[](1);
        preCalls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(counter), value: 0, data: abi.encodeCall(Counter.increment, ())});

        bytes memory uoCallData =
            abi.encodeCall(PreCallExecutionModule.executeWithPreCalls, (preCalls, calls));

        // Assemble the user operation.
        uint256 callGasLimit = 500_000;

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: _encodeNonceDefAction(_signerValidation, GLOBAL_V, 0),
            initCode: "",
            callData: uoCallData,
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, callGasLimit),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        bytes memory uoSig = _packFinalSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        userOp.signature =
            _buildFullDeferredInstallSig(userOp.nonce, 0, deferredAction, account1, owner1Key, uoSig);

        // Execute.
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        vm.expectEmit(true, false, false, false, address(module));
        emit CallsExecuted(true, "");

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(counter.count(), 2);
    }
}
