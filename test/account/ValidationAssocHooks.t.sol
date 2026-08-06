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

import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {HookConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ValidationDataView} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {ModuleManagerInternals} from "../../src/account/ModuleManagerInternals.sol";

import {MockModule} from "../mocks/modules/MockModule.sol";
import {MockUninstallHookModule} from "../mocks/modules/MockUninstallHookModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract ValidationAssocHooksTest is AccountTestBase {
    using HookConfigLib for HookConfig;

    event ValidationUninstalled(address indexed module, uint32 indexed entityId, bool onUninstallSucceeded);

    MockModule[] public hooks;

    function setUp() public override {
        _allowTestDirectCalls();

        ExecutionManifest memory m; // empty manifest

        for (uint256 i = 0; i < 257; i++) {
            hooks.push(new MockModule(m));
        }
    }

    function test_validationAssocHooks_maxValidationHooks() public withSMATest {
        // Attempt to install 257 validation hooks, expect a revert.

        bytes[] memory hookInstalls = new bytes[](257);

        for (uint256 i = 0; i < 257; i++) {
            hookInstalls[i] = abi.encodePacked(
                HookConfigLib.packValidationHook({_module: address(hooks[i]), _entityId: uint32(i)})
            );
        }

        vm.expectRevert(abi.encodeWithSelector(ModuleManagerInternals.ValidationAssocHookLimitExceeded.selector));
        account1.installValidation(
            ValidationConfigLib.pack({
                _validationFunction: _signerValidation,
                _isGlobal: true,
                _isSignatureValidation: true,
                _isUserOpValidation: true
            }),
            new bytes4[](0),
            "",
            hookInstalls
        );
    }

    function test_validationAssocHooks_maxExecHooks() public withSMATest {
        // Attempt to install 257 exec hooks, expect a revert.

        bytes[] memory hookInstalls = new bytes[](257);

        for (uint256 i = 0; i < 257; i++) {
            hookInstalls[i] = abi.encodePacked(
                HookConfigLib.packExecHook({
                    _module: address(hooks[i]),
                    _entityId: uint32(i),
                    _hasPre: false,
                    _hasPost: false
                })
            );
        }

        vm.expectRevert(abi.encodeWithSelector(ModuleManagerInternals.ValidationAssocHookLimitExceeded.selector));
        account1.installValidation(
            ValidationConfigLib.pack({
                _validationFunction: _signerValidation,
                _isGlobal: true,
                _isSignatureValidation: true,
                _isUserOpValidation: true
            }),
            new bytes4[](0),
            "",
            hookInstalls
        );
    }

    /// @dev Control for the short-circuit test below: with no failing callback, every hook's `onUninstall` runs
    /// and the event reports success. Without this, a zero counter there would not be evidence of anything.
    function test_uninstallValidation_allCallbacksRun() public withSMATest {
        (MockUninstallHookModule[2] memory iterationOrder,) = _installTwoUninstallHooks();

        vm.expectEmit(true, true, false, true);
        emit ValidationUninstalled(_signerValidationModule(), _signerValidationEntityId(), true);
        _uninstallWithHookData();

        assertEq(iterationOrder[0].onUninstallCount(), 1);
        assertEq(iterationOrder[1].onUninstallCount(), 1);
    }

    /// @dev `_uninstallValidation` aggregates callback results with `&&`, so once one callback has failed Solidity
    /// short-circuits and later callbacks are never invoked. Account-side removal still completes and the failure
    /// is reported through `ValidationUninstalled`. Pins the behavior documented in
    /// doc/Module-Lifecycle-Callbacks.md.
    function test_uninstallValidation_failedCallbackSkipsLaterCallbacks() public withSMATest {
        (MockUninstallHookModule[2] memory iterationOrder,) = _installTwoUninstallHooks();

        // Fail the first hook the account will iterate, leaving the second able to record a call if it gets one.
        iterationOrder[0].setShouldRevertOnUninstall(true);

        vm.expectEmit(true, true, false, true);
        emit ValidationUninstalled(_signerValidationModule(), _signerValidationEntityId(), false);
        _uninstallWithHookData();

        // The second hook never ran. It does not revert, so an invocation would have persisted the increment.
        assertEq(iterationOrder[1].onUninstallCount(), 0);

        // Removal completed regardless of the failure.
        ValidationDataView memory data = account1.getValidationData(_signerValidation);
        assertEq(data.validationHooks.length, 0);
        assertEq(data.executionHooks.length, 0);
    }

    /// @dev Installs two pre-validation hooks and returns them in the order `_uninstallValidation` will iterate
    /// them. `getValidationData` reverses the hook array, so the uninstall order is the reverse of the view order.
    /// Deriving it here rather than hardcoding it also pins that reversal.
    function _installTwoUninstallHooks()
        internal
        returns (MockUninstallHookModule[2] memory iterationOrder, MockUninstallHookModule[2] memory installOrder)
    {
        installOrder[0] = new MockUninstallHookModule();
        installOrder[1] = new MockUninstallHookModule();

        bytes[] memory hookInstalls = new bytes[](2);
        for (uint256 i = 0; i < 2; i++) {
            hookInstalls[i] = abi.encodePacked(
                HookConfigLib.packValidationHook({_module: address(installOrder[i]), _entityId: uint32(i)})
            );
        }

        account1.installValidation(
            ValidationConfigLib.pack({
                _validationFunction: _signerValidation,
                _isGlobal: true,
                _isSignatureValidation: true,
                _isUserOpValidation: true
            }),
            new bytes4[](0),
            "",
            hookInstalls
        );

        HookConfig[] memory viewOrder = account1.getValidationData(_signerValidation).validationHooks;
        assertEq(viewOrder.length, 2);

        // Uninstall walks the underlying list, which is the reverse of what the view returns.
        iterationOrder[0] = MockUninstallHookModule(viewOrder[1].module());
        iterationOrder[1] = MockUninstallHookModule(viewOrder[0].module());
    }

    /// @dev Hook uninstall data is ordered pre-validation hooks first, in iteration order, and must be non-empty
    /// for the account to forward the callback at all.
    function _uninstallWithHookData() internal {
        bytes[] memory hookUninstallData = new bytes[](2);
        hookUninstallData[0] = hex"01";
        hookUninstallData[1] = hex"01";

        account1.uninstallValidation(_signerValidation, "", hookUninstallData);
    }

    function _signerValidationModule() internal view returns (address module) {
        (module,) = ModuleEntityLib.unpack(_signerValidation);
    }

    function _signerValidationEntityId() internal view returns (uint32 entityId) {
        (, entityId) = ModuleEntityLib.unpack(_signerValidation);
    }

    function test_revertOnMissingExecuteUserOp() public withSMATest {
        // install a validation-association execution hook, and expect a revert unless called via `executeUserOp`.

        ExecutionManifest memory m; // empty manifest

        hooks.push(new MockModule(m));

        bytes[] memory hookInstalls = new bytes[](1);
        hookInstalls[0] = abi.encodePacked(
            HookConfigLib.packExecHook({_module: address(hooks[0]), _entityId: 0, _hasPre: false, _hasPost: false})
        );

        account1.installValidation(
            ValidationConfigLib.pack({
                _validationFunction: _signerValidation,
                _isGlobal: true,
                _isSignatureValidation: true,
                _isUserOpValidation: true
            }),
            new bytes4[](0),
            "",
            hookInstalls
        );

        _runExecUserOp(
            makeAddr("target"),
            "",
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(ModularAccountBase.RequireUserOperationContext.selector)
            )
        );
    }
}
