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

import {ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";

import {AccountTestBase} from "./AccountTestBase.sol";

/// @dev This test contract base is used to test custom validation logic.
/// To use this, override the _initialValidationConfig function to return the desired validation configuration.
/// Then, call _customValidationSetup in the test setup.
/// Make sure to do so after any state variables that `_initialValidationConfig` relies on are set.
abstract contract CustomValidationTestBase is AccountTestBase {
    using ModuleEntityLib for ModuleEntity;

    function _customValidationSetup() internal {
        (
            ModuleEntity validationFunction,
            bool isGlobal,
            bool isSignatureValidation,
            bool isUserOpValidation,
            bytes4[] memory selectors,
            bytes memory installData,
            bytes[] memory hooks
        ) = _initialValidationConfig();

        if (_isSMATest) {
            account1 =
                ModularAccount(payable(new ERC1967Proxy{salt: 0}(address(semiModularAccountImplementation), "")));
            _beforeInstallStep(address(account1));
            // The initializer doesn't work on the SMA.
            vm.prank(address(entryPoint));
            account1.installValidation(
                ValidationConfigLib.pack(validationFunction, isGlobal, isSignatureValidation, isUserOpValidation),
                selectors,
                installData,
                hooks
            );
        } else {
            account1 = ModularAccount(payable(new ERC1967Proxy{salt: 0}(address(accountImplementation), "")));
            _beforeInstallStep(address(account1));
            account1.initializeWithValidation(
                ValidationConfigLib.pack(validationFunction, isGlobal, isSignatureValidation, isUserOpValidation),
                selectors,
                installData,
                hooks
            );
        }

        vm.deal(address(account1), 100 ether);
    }

    function _initialValidationConfig()
        internal
        virtual
        returns (
            ModuleEntity validationFunction,
            bool shared,
            bool isSignatureValidation,
            bool isUserOpValidation,
            bytes4[] memory selectors,
            bytes memory installData,
            bytes[] memory hooks
        );

    // If the test needs to perform any setup or checks after the account is created, but before the call to
    // `initializeWithValidation`,
    // it should override this function.
    function _beforeInstallStep(address accountImpl) internal virtual {
        // Does nothing by default
        (accountImpl);
    }
}
