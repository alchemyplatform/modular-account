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

pragma solidity ^0.8.28;

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {SemiModularAccountBytecode} from "../../src/account/SemiModularAccountBytecode.sol";
import {AccountFactory} from "../../src/factory/AccountFactory.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";
import {TEST_DEFAULT_VALIDATION_ENTITY_ID} from "../utils/TestConstants.sol";

import {MockERC20} from "../mocks/MockERC20.sol";

contract AccountFactoryTest is AccountTestBase {
    MockERC20 public erc20;
    uint256 internal _ownerX = 1;
    uint256 internal _ownerY = 2;

    function test_createAccount() public withSMATest {
        ModularAccount account = factory.createAccount(address(this), 100, TEST_DEFAULT_VALIDATION_ENTITY_ID);

        assertEq(address(account.entryPoint()), address(entryPoint));
    }

    function test_createWebAuthnAccount() public {
        ModularAccount account =
            factory.createWebAuthnAccount(_ownerX, _ownerY, 100, TEST_DEFAULT_VALIDATION_ENTITY_ID);

        assertEq(address(account.entryPoint()), address(entryPoint));
    }

    function test_createAccountAndGetAddress() public withSMATest {
        ModularAccount account = factory.createAccount(address(this), 100, TEST_DEFAULT_VALIDATION_ENTITY_ID);

        assertEq(
            address(account), address(factory.createAccount(address(this), 100, TEST_DEFAULT_VALIDATION_ENTITY_ID))
        );

        assertEq(
            address(account), address(factory.getAddress(address(this), 100, TEST_DEFAULT_VALIDATION_ENTITY_ID))
        );
    }

    function test_createWebAuthnAccountAndGetAddress() public {
        ModularAccount account =
            factory.createWebAuthnAccount(_ownerX, _ownerY, 100, TEST_DEFAULT_VALIDATION_ENTITY_ID);

        assertEq(
            address(account),
            address(factory.createWebAuthnAccount(_ownerX, _ownerY, 100, TEST_DEFAULT_VALIDATION_ENTITY_ID))
        );

        assertEq(
            address(account),
            address(factory.getAddressWebAuthn(_ownerX, _ownerY, 100, TEST_DEFAULT_VALIDATION_ENTITY_ID))
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

    function test_multipleDeployWebAuthn() public {
        ModularAccount account =
            factory.createWebAuthnAccount(_ownerX, _ownerY, 100, TEST_DEFAULT_VALIDATION_ENTITY_ID);

        uint256 startGas = gasleft();

        ModularAccount account2 =
            factory.createWebAuthnAccount(_ownerX, _ownerY, 100, TEST_DEFAULT_VALIDATION_ENTITY_ID);

        // Assert that the 2nd deployment call cost less than 1 sstore
        // Implies that no deployment was done on the second calls
        assertLe(startGas - 22_000, gasleft());

        // Assert the return addresses are the same
        assertEq(address(account), address(account2));
    }

    function test_withdraw() public {
        erc20 = new MockERC20();
        erc20.mint(address(factory), 10 ether);

        assertEq(erc20.balanceOf(address(factory)), 10 ether);
        vm.prank(factoryOwner);
        factory.withdraw(payable(address(this)), address(erc20), 10 ether); // amount = balance if native currency
        assertEq(address(factory).balance, 0);
    }

    function test_fail_createAccountWithoutAccountImpl() public {
        vm.expectRevert(AccountFactory.NoCodeAccountImpl.selector);
        new AccountFactory(
            entryPoint,
            ModularAccount(payable(0)),
            semiModularAccountImplementation,
            address(singleSignerValidationModule),
            address(webAuthnModule),
            factoryOwner
        );
    }

    function test_fail_createAccountWithoutSemiModularImpl() public {
        vm.expectRevert(AccountFactory.NoCodeSemiModularImpl.selector);
        new AccountFactory(
            entryPoint,
            accountImplementation,
            SemiModularAccountBytecode(payable(0)),
            address(singleSignerValidationModule),
            address(webAuthnModule),
            factoryOwner
        );
    }

    function test_fail_createAccountWithoutSingleSignerValidationModule() public {
        vm.expectRevert(AccountFactory.NoCodeSingleSignerValidationModule.selector);
        new AccountFactory(
            entryPoint,
            accountImplementation,
            semiModularAccountImplementation,
            address(0),
            address(webAuthnModule),
            factoryOwner
        );
    }

    function test_fail_createAccountWithoutWebAuthnModule() public {
        vm.expectRevert(AccountFactory.NoCodeWebAuthnModule.selector);
        new AccountFactory(
            entryPoint,
            accountImplementation,
            semiModularAccountImplementation,
            address(singleSignerValidationModule),
            address(0),
            factoryOwner
        );
    }
}
