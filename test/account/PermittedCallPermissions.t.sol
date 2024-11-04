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

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";

import {PermittedCallerModule} from "../mocks/modules/PermittedCallMocks.sol";
import {ResultCreatorModule} from "../mocks/modules/ReturnDataModuleMocks.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract PermittedCallPermissionsTest is AccountTestBase {
    ResultCreatorModule public resultCreatorModule;

    PermittedCallerModule public permittedCallerModule;

    function setUp() public override {
        _revertSnapshot = vm.snapshotState();
        _transferOwnershipToTest();
        resultCreatorModule = new ResultCreatorModule();

        // Initialize the permitted caller modules, which will attempt to use the permissions system to authorize
        // calls.
        permittedCallerModule = new PermittedCallerModule();

        // Add the result creator module to the account
        vm.startPrank(address(entryPoint));
        account1.installExecution({
            module: address(resultCreatorModule),
            manifest: resultCreatorModule.executionManifest(),
            moduleInstallData: ""
        });
        // Add the permitted caller module to the account
        account1.installExecution({
            module: address(permittedCallerModule),
            manifest: permittedCallerModule.executionManifest(),
            moduleInstallData: ""
        });
        vm.stopPrank();
    }

    function test_permittedCall_Allowed() public withSMATest {
        bytes memory result = PermittedCallerModule(address(account1)).usePermittedCallAllowed();
        bytes32 actual = abi.decode(result, (bytes32));

        assertEq(actual, keccak256("bar"));
    }

    function test_permittedCall_NotAllowed() public withSMATest {
        vm.expectRevert(
            abi.encodeWithSelector(
                ModularAccountBase.ValidationFunctionMissing.selector, ResultCreatorModule.bar.selector
            )
        );
        PermittedCallerModule(address(account1)).usePermittedCallNotAllowed();
    }
}
