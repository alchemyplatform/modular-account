// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {ModularAccount} from "../../src/account/ModularAccount.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";
import {TEST_DEFAULT_VALIDATION_ENTITY_ID} from "../utils/TestConstants.sol";

contract AccountFactoryTest is AccountTestBase {
    function test_createAccount() public withSMATest {
        ModularAccount account = factory.createAccount(address(this), 100, TEST_DEFAULT_VALIDATION_ENTITY_ID);

        assertEq(address(account.entryPoint()), address(entryPoint));
    }

    function test_createAccountAndGetAddress() public withSMATest {
        ModularAccount account = factory.createAccount(address(this), 100, TEST_DEFAULT_VALIDATION_ENTITY_ID);

        assertEq(
            address(account), address(factory.createAccount(address(this), 100, TEST_DEFAULT_VALIDATION_ENTITY_ID))
        );
    }

    function test_multipleDeploy() public withSMATest {
        ModularAccount account = factory.createAccount(address(this), 100, TEST_DEFAULT_VALIDATION_ENTITY_ID);

        uint256 startGas = gasleft();

        ModularAccount account2 = factory.createAccount(address(this), 100, TEST_DEFAULT_VALIDATION_ENTITY_ID);

        // Assert that the 2nd deployment call cost less than 1 sstore
        // Implies that no deployment was done on the second calls
        assertLe(startGas - 22_000, gasleft());

        // Assert the return addresses are the same
        assertEq(address(account), address(account2));
    }
}
