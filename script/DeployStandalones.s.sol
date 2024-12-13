// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {console} from "forge-std/console.sol";

import {Artifacts} from "./Artifacts.sol";
import {ScriptBase} from "./ScriptBase.sol";

// Deploys all standalone contracts.
// Modules:
// - AllowlistModule
// - NativeTokenLimitModule
// - PaymasterGuardModule
// - SingleSignerValidationModule
// - TimeRangeModule
// - WebAuthnValidationModule
// Account-internal:
// - ExecutionInstallDelegate
contract DeployStandalonesScript is ScriptBase, Artifacts {
    // State vars for expected addresses and salts.

    address public expectedAllowlistModuleAddr;
    uint256 public allowlistModuleSalt;

    address public expectedNativeTokenLimitModuleAddr;
    uint256 public nativeTokenLimitModuleSalt;

    address public expectedPaymasterGuardModuleAddr;
    uint256 public paymasterGuardModuleSalt;

    address public expectedSingleSignerValidationModuleAddr;
    uint256 public singleSignerValidationModuleSalt;

    address public expectedTimeRangeModuleAddr;
    uint256 public timeRangeModuleSalt;

    address public expectedWebAuthnValidationModuleAddr;
    uint256 public webAuthnValidationModuleSalt;

    address public expectedExecutionInstallDelegate;
    uint256 public executionInstallDelegateSalt;

    function setUp() public {
        // Load the expected addresses and salts from env vars.

        expectedAllowlistModuleAddr = vm.envOr("ALLOWLIST_MODULE", address(0));
        allowlistModuleSalt = _getSaltOrZero("ALLOWLIST_MODULE");

        expectedNativeTokenLimitModuleAddr = vm.envOr("NATIVE_TOKEN_LIMIT_MODULE", address(0));
        nativeTokenLimitModuleSalt = _getSaltOrZero("NATIVE_TOKEN_LIMIT_MODULE");

        expectedPaymasterGuardModuleAddr = vm.envOr("PAYMASTER_GUARD_MODULE", address(0));
        paymasterGuardModuleSalt = _getSaltOrZero("PAYMASTER_GUARD_MODULE");

        expectedSingleSignerValidationModuleAddr = vm.envOr("SINGLE_SIGNER_VALIDATION_MODULE", address(0));
        singleSignerValidationModuleSalt = _getSaltOrZero("SINGLE_SIGNER_VALIDATION_MODULE");

        expectedTimeRangeModuleAddr = vm.envOr("TIME_RANGE_MODULE", address(0));
        timeRangeModuleSalt = _getSaltOrZero("TIME_RANGE_MODULE");

        expectedWebAuthnValidationModuleAddr = vm.envOr("WEBAUTHN_VALIDATION_MODULE", address(0));
        webAuthnValidationModuleSalt = _getSaltOrZero("WEBAUTHN_VALIDATION_MODULE");

        expectedExecutionInstallDelegate = _getExecutionInstallDelegate();
        executionInstallDelegateSalt = _getSaltOrZero("EXECUTION_INSTALL_DELEGATE");
    }

    function run() public onlyProfile("optimized-build-standalone") {
        console.log("******** Deploying Modules *********");

        vm.startBroadcast();

        _safeDeploy(
            "Allowlist Module",
            expectedAllowlistModuleAddr,
            allowlistModuleSalt,
            _getAllowlistModuleInitcode(),
            _deployAllowlistModule
        );

        _safeDeploy(
            "Native Token Limit Module",
            expectedNativeTokenLimitModuleAddr,
            nativeTokenLimitModuleSalt,
            _getNativeTokenLimitModuleInitcode(),
            _deployNativeTokenLimitModule
        );

        _safeDeploy(
            "Paymaster Guard Module",
            expectedPaymasterGuardModuleAddr,
            paymasterGuardModuleSalt,
            _getPaymasterGuardModuleInitcode(),
            _deployPaymasterGuardModule
        );

        _safeDeploy(
            "Single Signer Validation Module",
            expectedSingleSignerValidationModuleAddr,
            singleSignerValidationModuleSalt,
            _getSingleSignerValidationModuleInitcode(),
            _deploySingleSignerValidationModule
        );

        _safeDeploy(
            "Time Range Module",
            expectedTimeRangeModuleAddr,
            timeRangeModuleSalt,
            _getTimeRangeModuleInitcode(),
            _deployTimeRangeModule
        );

        _safeDeploy(
            "WebAuthn Validation Module",
            expectedWebAuthnValidationModuleAddr,
            webAuthnValidationModuleSalt,
            _getWebAuthnValidationModuleInitcode(),
            _deployWebAuthnValidationModule
        );

        console.log("******** Modules Deployed *********");

        console.log("******** Deploying Execution Install Delegate *********");

        _safeDeploy(
            "Execution Install Delegate",
            expectedExecutionInstallDelegate,
            executionInstallDelegateSalt,
            _getExecutionInstallDelegateInitcode(),
            _deployExecutionInstallDelegate
        );

        console.log("******** Execution Install Delegate Deployed *********");

        vm.stopBroadcast();
    }
}
