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
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {ModuleManagerInternals} from "../../src/account/ModuleManagerInternals.sol";

import {MockModule} from "../mocks/modules/MockModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract ValidationAssocHooksTest is AccountTestBase {
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
