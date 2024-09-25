// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {Call} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {DIRECT_CALL_VALIDATION_ENTITYID} from "../../src/helpers/Constants.sol";
import {ValidationConfigLib} from "../../src/libraries/ValidationConfigLib.sol";

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

    function setUp() public {
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
    function test_returnData_fallback() public view {
        bytes32 result = ResultCreatorModule(address(account1)).foo();

        assertEq(result, keccak256("bar"));
    }

    // Tests the ability to read the results of contracts called via IModularAccount.execute
    function test_returnData_singular_execute() public {
        bytes memory returnData = account1.executeWithAuthorization(
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
    function test_returnData_executeBatch() public {
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

        bytes memory retData = account1.executeWithAuthorization(
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
    function test_returnData_execFromModule_fallback() public view {
        bool result = ResultConsumerModule(address(account1)).checkResultFallback(keccak256("bar"));

        assertTrue(result);
    }

    // Tests the ability to read data via executeWithAuthorization
    function test_returnData_authorized_exec() public {
        bool result = ResultConsumerModule(address(account1)).checkResultExecuteWithAuthorization(
            address(regularResultContract), keccak256("bar")
        );

        assertTrue(result);
    }
}
