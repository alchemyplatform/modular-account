// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IAccount} from "@eth-infinitism/account-abstraction/interfaces/IAccount.sol";
import {IPaymaster} from "@eth-infinitism/account-abstraction/interfaces/IPaymaster.sol";
import {Test} from "forge-std/src/Test.sol";

import {KnownSelectorsLib} from "../../src/libraries/KnownSelectorsLib.sol";

contract KnownSelectorsTest is Test {
    function test_isNativeFunction() public pure {
        assertTrue(KnownSelectorsLib.isNativeFunction(IAccount.validateUserOp.selector));
    }

    function test_isErc4337Function() public pure {
        assertTrue(KnownSelectorsLib.isErc4337Function(IPaymaster.validatePaymasterUserOp.selector));
    }

    function test_isIModuleFunction() public pure {
        assertTrue(KnownSelectorsLib.isIModuleFunction(IModule.moduleId.selector));
    }
}
