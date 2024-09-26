// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";

import {PermittedCallerModule} from "../mocks/modules/PermittedCallMocks.sol";
import {ResultCreatorModule} from "../mocks/modules/ReturnDataModuleMocks.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract PermittedCallPermissionsTest is AccountTestBase {
    ResultCreatorModule public resultCreatorModule;

    PermittedCallerModule public permittedCallerModule;

    function setUp() public {
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

    function test_permittedCall_Allowed() public view {
        bytes memory result = PermittedCallerModule(address(account1)).usePermittedCallAllowed();
        bytes32 actual = abi.decode(result, (bytes32));

        assertEq(actual, keccak256("bar"));
    }

    function test_permittedCall_NotAllowed() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ModularAccountBase.ValidationFunctionMissing.selector, ResultCreatorModule.bar.selector
            )
        );
        PermittedCallerModule(address(account1)).usePermittedCallNotAllowed();
    }
}
