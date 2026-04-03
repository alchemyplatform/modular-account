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

import {
    ExecutionManifest,
    IExecutionModule,
    ManifestExecutionFunction
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {Call, IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";

import {ModuleBase} from "../ModuleBase.sol";

/// @title Pre-Call Execution Module
/// @author Alchemy
/// @notice Execution module that provides a non-atomic batch execution pattern with precondition checks.
///
/// `executeWithPreCalls(preCalls, calls)` splits execution into two phases:
///   1. **Pre-calls** — run atomically as a batch. If any pre-call reverts, the entire user operation fails.
///      Use these for precondition checks (e.g. on-chain price bounds, state assertions) or setup actions
///      that must succeed for the operation to be valid.
///   2. **Calls** — run atomically as a batch after pre-calls pass. If the calls batch reverts, the revert
///      reason is captured and emitted in a `CallsExecuted` event, but the user operation still succeeds.
///      This guarantees the UO will not revert once pre-calls pass, which is useful for ensuring gas payment
///      and side-effect persistence.
///
/// @dev This module calls back into the account via `executeBatch`, which requires the module to also be
/// installed as a direct-call validator (with `isGlobal = true`) so the account authorizes the callback.
/// Both the execution install and validation install can be batched into a single deferred action.
contract PreCallExecutionModule is IExecutionModule, ModuleBase {
    /// @notice Emitted after the calls batch is attempted.
    /// @param success Whether the calls batch succeeded.
    /// @param result On success: abi-encoded `bytes[]` of individual call return values.
    ///               On failure: the raw revert bytes from `executeBatch`.
    event CallsExecuted(bool indexed success, bytes result);

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @notice Execute calls with precondition checks.
    /// @dev The account's fallback routes here; `msg.sender` is the account.
    /// @param preCalls Batch of calls that must all succeed, or the user operation reverts.
    /// @param calls Batch of calls executed after pre-calls pass. Reverts are caught and emitted.
    function executeWithPreCalls(Call[] calldata preCalls, Call[] calldata calls) external {
        // Phase 1: pre-calls (hard revert).
        // If any pre-call reverts, executeBatch reverts, we don't catch it, and the whole user operation fails.
        if (preCalls.length > 0) {
            IModularAccount(msg.sender).executeBatch(preCalls);
        }

        // Phase 2: calls (soft revert).
        // After pre-calls pass the UO must succeed, so we wrap the batch in try/catch and emit the outcome.
        if (calls.length > 0) {
            try IModularAccount(msg.sender).executeBatch(calls) returns (bytes[] memory results) {
                emit CallsExecuted(true, abi.encode(results));
            } catch (bytes memory reason) {
                emit CallsExecuted(false, reason);
            }
        }
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Module interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IExecutionModule
    function executionManifest() external pure override returns (ExecutionManifest memory) {
        ExecutionManifest memory manifest;

        manifest.executionFunctions = new ManifestExecutionFunction[](1);
        manifest.executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: this.executeWithPreCalls.selector,
            skipRuntimeValidation: false,
            allowGlobalValidation: true
        });

        return manifest;
    }

    /// @inheritdoc IModule
    function moduleId() external pure returns (string memory) {
        return "alchemy.pre-call-execution-module.0.1.0";
    }

    // solhint-disable-next-line no-empty-blocks
    function onInstall(bytes calldata) external override {}

    // solhint-disable-next-line no-empty-blocks
    function onUninstall(bytes calldata) external override {}
}
