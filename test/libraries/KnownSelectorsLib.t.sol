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

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";

import {IAccount} from "@eth-infinitism/account-abstraction/interfaces/IAccount.sol";
import {IAggregator} from "@eth-infinitism/account-abstraction/interfaces/IAggregator.sol";
import {IPaymaster} from "@eth-infinitism/account-abstraction/interfaces/IPaymaster.sol";
import {Test} from "forge-std/Test.sol";

import {KnownSelectorsLib} from "../../src/libraries/KnownSelectorsLib.sol";

contract KnownSelectorsLibTest is Test {
    function test_isERC4337Function() public pure {
        assertTrue(KnownSelectorsLib.isERC4337Function(uint32(IAggregator.validateSignatures.selector)));
        assertTrue(KnownSelectorsLib.isERC4337Function(uint32(IAggregator.validateUserOpSignature.selector)));
        assertTrue(KnownSelectorsLib.isERC4337Function(uint32(IAggregator.aggregateSignatures.selector)));
        assertTrue(KnownSelectorsLib.isERC4337Function(uint32(IPaymaster.validatePaymasterUserOp.selector)));
        assertTrue(KnownSelectorsLib.isERC4337Function(uint32(IPaymaster.postOp.selector)));

        assertFalse(KnownSelectorsLib.isERC4337Function(uint32(IAccount.validateUserOp.selector)));
    }

    function test_isIModuleFunction() public pure {
        assertTrue(KnownSelectorsLib.isIModuleFunction(uint32(IModule.onInstall.selector)));
        assertTrue(KnownSelectorsLib.isIModuleFunction(uint32(IModule.onUninstall.selector)));
        assertTrue(KnownSelectorsLib.isIModuleFunction(uint32(IModule.moduleId.selector)));
        assertTrue(
            KnownSelectorsLib.isIModuleFunction(uint32(IValidationHookModule.preUserOpValidationHook.selector))
        );
        assertTrue(KnownSelectorsLib.isIModuleFunction(uint32(IValidationModule.validateUserOp.selector)));
        assertTrue(
            KnownSelectorsLib.isIModuleFunction(uint32(IValidationHookModule.preRuntimeValidationHook.selector))
        );
        assertTrue(KnownSelectorsLib.isIModuleFunction(uint32(IValidationModule.validateRuntime.selector)));
        assertTrue(KnownSelectorsLib.isIModuleFunction(uint32(IExecutionHookModule.preExecutionHook.selector)));
        assertTrue(KnownSelectorsLib.isIModuleFunction(uint32(IExecutionHookModule.postExecutionHook.selector)));

        assertFalse(KnownSelectorsLib.isIModuleFunction(uint32(IPaymaster.postOp.selector)));
    }
}
