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

import {DIRECT_CALL_VALIDATION_ENTITYID} from "@erc6900/reference-implementation/helpers/Constants.sol";
import {Call} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";

import {
    RegularResultContract,
    ResultConsumerModule,
    ResultCreatorModule
} from "../mocks/modules/ReturnDataModuleMocks.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

// Tests all the different ways that return data can be read from modules through an account
contract AccountReturnDataTest is AccountTestBase {
    RegularResultContract public regularResultContract;
    ResultCreatorModule public resultCreatorModule;
    ResultConsumerModule public resultConsumerModule;

    function setUp() public override {
        _revertSnapshot = vm.snapshotState();
        _transferOwnershipToTest();

        regularResultContract = new RegularResultContract();
        resultCreatorModule = new ResultCreatorModule();
        resultConsumerModule = new ResultConsumerModule(resultCreatorModule, regularResultContract);

        // Add the result creator module to the account
        vm.startPrank(address(entryPoint));
        account1.installExecution({
            module: address(resultCreatorModule),
            manifest: resultCreatorModule.executionManifest(),
            moduleInstallData: ""
        });
        // Add the result consumer module to the account
        account1.installExecution({
            module: address(resultConsumerModule),
            manifest: resultConsumerModule.executionManifest(),
            moduleInstallData: ""
        });
        // Allow the result consumer module to perform direct calls to the account
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IModularAccount.execute.selector;
        account1.installValidation(
            ValidationConfigLib.pack(
                address(resultConsumerModule), DIRECT_CALL_VALIDATION_ENTITYID, false, false, true
            ), // todo: does this need UO validation permission?
            selectors,
            "",
            new bytes[](0)
        );
        vm.stopPrank();
    }

    // Tests the ability to read the result of module execution functions via the account's fallback
    function test_returnData_fallback() public withSMATest {
        bytes32 result = ResultCreatorModule(address(account1)).foo();

        assertEq(result, keccak256("bar"));
    }

    // Tests the ability to read the results of contracts called via IModularAccount.execute
    function test_returnData_singular_execute() public withSMATest {
        bytes memory returnData = account1.executeWithRuntimeValidation(
            abi.encodeCall(
                account1.execute,
                (address(regularResultContract), 0, abi.encodeCall(RegularResultContract.foo, ()))
            ),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
        );

        bytes32 result = abi.decode(abi.decode(returnData, (bytes)), (bytes32));

        assertEq(result, keccak256("bar"));
    }

    // Tests the ability to read the results of multiple contract calls via IModularAccount.executeBatch
    function test_returnData_executeBatch() public withSMATest {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(regularResultContract),
            value: 0,
            data: abi.encodeCall(RegularResultContract.foo, ())
        });
        calls[1] = Call({
            target: address(regularResultContract),
            value: 0,
            data: abi.encodeCall(RegularResultContract.bar, ())
        });

        bytes memory retData = account1.executeWithRuntimeValidation(
            abi.encodeCall(account1.executeBatch, (calls)),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
        );

        bytes[] memory returnDatas = abi.decode(retData, (bytes[]));

        bytes32 result1 = abi.decode(returnDatas[0], (bytes32));
        bytes32 result2 = abi.decode(returnDatas[1], (bytes32));

        assertEq(result1, keccak256("bar"));
        assertEq(result2, keccak256("foo"));
    }

    // Tests the ability to read data via routing to fallback functions
    function test_returnData_execFromModule_fallback() public withSMATest {
        bool result = ResultConsumerModule(address(account1)).checkResultFallback(keccak256("bar"));

        assertTrue(result);
    }

    // Tests the ability to read data via executeWithAuthorization
    function test_returnData_authorized_exec() public withSMATest {
        bool result = ResultConsumerModule(address(account1)).checkResultExecuteWithRuntimeValidation(
            address(regularResultContract), keccak256("bar")
        );

        assertTrue(result);
    }
}
