// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";

import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {DeployStandalonesScript} from "../../script/DeployStandalones.s.sol";

import {ExecutionInstallDelegate} from "../../src/helpers/ExecutionInstallDelegate.sol";
import {AllowlistModule} from "../../src/modules/permissions/AllowlistModule.sol";
import {NativeTokenLimitModule} from "../../src/modules/permissions/NativeTokenLimitModule.sol";
import {PaymasterGuardModule} from "../../src/modules/permissions/PaymasterGuardModule.sol";
import {TimeRangeModule} from "../../src/modules/permissions/TimeRangeModule.sol";
import {SingleSignerValidationModule} from "../../src/modules/validation/SingleSignerValidationModule.sol";
import {WebAuthnValidationModule} from "../../src/modules/validation/WebAuthnValidationModule.sol";

contract DeployStandalonesTest is Test {
    DeployStandalonesScript internal _deployStandalonesScript;

    AllowlistModule internal _allowlistModule;
    NativeTokenLimitModule internal _nativeTokenLimitModule;
    PaymasterGuardModule internal _paymasterGuardModule;
    SingleSignerValidationModule internal _singleSignerValidationModule;
    TimeRangeModule internal _timeRangeModule;
    WebAuthnValidationModule internal _webAuthnValidationModule;
    ExecutionInstallDelegate internal _executionInstallDelegate;

    function setUp() public {
        _deployStandalonesScript = new DeployStandalonesScript();

        bytes32 zeroSalt = bytes32(0);

        _allowlistModule = AllowlistModule(
            Create2.computeAddress(zeroSalt, keccak256(type(AllowlistModule).creationCode), CREATE2_FACTORY)
        );

        _nativeTokenLimitModule = NativeTokenLimitModule(
            Create2.computeAddress(zeroSalt, keccak256(type(NativeTokenLimitModule).creationCode), CREATE2_FACTORY)
        );

        _paymasterGuardModule = PaymasterGuardModule(
            Create2.computeAddress(zeroSalt, keccak256(type(PaymasterGuardModule).creationCode), CREATE2_FACTORY)
        );

        _singleSignerValidationModule = SingleSignerValidationModule(
            Create2.computeAddress(
                zeroSalt, keccak256(type(SingleSignerValidationModule).creationCode), CREATE2_FACTORY
            )
        );

        _timeRangeModule = TimeRangeModule(
            Create2.computeAddress(zeroSalt, keccak256(type(TimeRangeModule).creationCode), CREATE2_FACTORY)
        );

        _webAuthnValidationModule = WebAuthnValidationModule(
            Create2.computeAddress(
                zeroSalt, keccak256(type(WebAuthnValidationModule).creationCode), CREATE2_FACTORY
            )
        );

        _executionInstallDelegate = ExecutionInstallDelegate(
            Create2.computeAddress(
                zeroSalt, keccak256(type(ExecutionInstallDelegate).creationCode), CREATE2_FACTORY
            )
        );

        vm.setEnv("ALLOWLIST_MODULE", vm.toString(address(_allowlistModule)));
        vm.setEnv("NATIVE_TOKEN_LIMIT_MODULE", vm.toString(address(_nativeTokenLimitModule)));
        vm.setEnv("PAYMASTER_GUARD_MODULE", vm.toString(address(_paymasterGuardModule)));
        vm.setEnv("SINGLE_SIGNER_VALIDATION_MODULE", vm.toString(address(_singleSignerValidationModule)));
        vm.setEnv("TIME_RANGE_MODULE", vm.toString(address(_timeRangeModule)));
        vm.setEnv("WEBAUTHN_VALIDATION_MODULE", vm.toString(address(_webAuthnValidationModule)));
        vm.setEnv("EXECUTION_INSTALL_DELEGATE", vm.toString(address(_executionInstallDelegate)));

        string memory zeroSaltString = vm.toString(zeroSalt);

        vm.setEnv("ALLOWLIST_MODULE_SALT", zeroSaltString);
        vm.setEnv("NATIVE_TOKEN_LIMIT_MODULE_SALT", zeroSaltString);
        vm.setEnv("PAYMASTER_GUARD_MODULE_SALT", zeroSaltString);
        vm.setEnv("SINGLE_SIGNER_VALIDATION_MODULE_SALT", zeroSaltString);
        vm.setEnv("TIME_RANGE_MODULE_SALT", zeroSaltString);
        vm.setEnv("WEBAUTHN_VALIDATION_MODULE_SALT", zeroSaltString);
        vm.setEnv("EXECUTION_INSTALL_DELEGATE_SALT", zeroSaltString);

        // Spoof as though the profile is set to "optimized-build".
        vm.setEnv("FOUNDRY_PROFILE", "optimized-build-standalone");
    }

    function test_deployStandalonesScript() public {
        _deployStandalonesScript.setUp();

        _deployStandalonesScript.run();

        // Ensure that the right modules were deployed to the expected addresses.
        assertEq(_allowlistModule.moduleId(), "alchemy.allowlist-module.1.0.0");
        assertEq(_nativeTokenLimitModule.moduleId(), "alchemy.native-token-limit-module.1.0.0");
        assertEq(_paymasterGuardModule.moduleId(), "alchemy.paymaster-guard-module.1.0.0");
        assertEq(_singleSignerValidationModule.moduleId(), "alchemy.single-signer-validation-module.1.0.0");
        assertEq(_timeRangeModule.moduleId(), "alchemy.time-range-module.1.0.0");
        assertEq(_webAuthnValidationModule.moduleId(), "alchemy.webauthn-validation-module.1.0.0");

        // Check that the delegate's in the right place by checking that `installExecution()` can only be called
        // via delegatecall.
        ExecutionManifest memory manifest;
        vm.expectRevert(ExecutionInstallDelegate.OnlyDelegateCall.selector);
        ExecutionInstallDelegate(_executionInstallDelegate).installExecution(address(0), manifest, "");
    }
}
