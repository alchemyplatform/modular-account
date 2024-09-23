// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";

import {ModuleEntity} from "../../src/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "../../src/libraries/ValidationConfigLib.sol";

import {AccountTestBase} from "./AccountTestBase.sol";

/// @dev This test contract base is used to test custom validation logic.
/// To use this, override the _initialValidationConfig function to return the desired validation configuration.
/// Then, call _customValidationSetup in the test setup.
/// Make sure to do so after any state variables that `_initialValidationConfig` relies on are set.
abstract contract CustomValidationTestBase is AccountTestBase {
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

        account1 = ModularAccount(payable(new ERC1967Proxy{salt: 0}(address(accountImplementation), "")));

        if (vm.envOr("SMA_TEST", false)) {
            vm.prank(address(entryPoint));
            // The initializer doesn't work on the SMA
            account1.installValidation(
                ValidationConfigLib.pack(validationFunction, isGlobal, isSignatureValidation, isUserOpValidation),
                selectors,
                installData,
                hooks
            );
        } else {
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
