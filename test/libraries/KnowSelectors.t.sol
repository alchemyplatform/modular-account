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

import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IAccount} from "@eth-infinitism/account-abstraction/interfaces/IAccount.sol";
import {IPaymaster} from "@eth-infinitism/account-abstraction/interfaces/IPaymaster.sol";
import {Test} from "forge-std/src/Test.sol";

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {SemiModularAccountBase} from "../../src/account/SemiModularAccountBase.sol";
import {KnownSelectorsLib} from "../../src/libraries/KnownSelectorsLib.sol";
import {SemiModularKnownSelectorsLib} from "../../src/libraries/SemiModularKnownSelectorsLib.sol";

contract KnownSelectorsTest is Test {
    function test_isNativeFunction() public pure {
        assertTrue(KnownSelectorsLib.isNativeFunction(IAccount.validateUserOp.selector));
        assertTrue(KnownSelectorsLib.isNativeFunction(ModularAccountBase.installValidation.selector));
    }

    function test_sma_isNativeFunction() public pure {
        assertTrue(SemiModularKnownSelectorsLib.isNativeFunction(IAccount.validateUserOp.selector));
        assertTrue(
            SemiModularKnownSelectorsLib.isNativeFunction(SemiModularAccountBase.getFallbackSignerData.selector)
        );
        assertTrue(SemiModularKnownSelectorsLib.isNativeFunction(ModularAccountBase.installValidation.selector));
    }

    function test_isErc4337Function() public pure {
        assertTrue(KnownSelectorsLib.isErc4337Function(IPaymaster.validatePaymasterUserOp.selector));
    }

    function test_isIModuleFunction() public pure {
        assertTrue(KnownSelectorsLib.isIModuleFunction(IModule.moduleId.selector));
    }
}
