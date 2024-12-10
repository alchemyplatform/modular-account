// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {console} from "forge-std/console.sol";

import {Artifacts} from "./Artifacts.sol";
import {ScriptBase} from "./ScriptBase.sol";

// Deploys all standalone modules.
// - AllowlistModule
// - NativeTokenLimitModule
// - PaymasterGuardModule
// - SingleSignerValidationModule
// - TimeRangeModule
// - WebAuthnValidationModule
contract DeployModulesScript is ScriptBase, Artifacts {
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

    function setUp() public {
        // Load the expected addresses and salts from env vars.

        expectedAllowlistModuleAddr = vm.envOr("ALLOWLIST_MODULE", address(0));
        allowlistModuleSalt = vm.envOr("ALLOWLIST_MODULE_SALT", uint256(0));

        expectedNativeTokenLimitModuleAddr = vm.envOr("NATIVE_TOKEN_LIMIT_MODULE", address(0));
        nativeTokenLimitModuleSalt = vm.envOr("NATIVE_TOKEN_LIMIT_MODULE_SALT", uint256(0));

        expectedPaymasterGuardModuleAddr = vm.envOr("PAYMASTER_GUARD_MODULE", address(0));
        paymasterGuardModuleSalt = vm.envOr("PAYMASTER_GUARD_MODULE_SALT", uint256(0));

        expectedSingleSignerValidationModuleAddr = vm.envOr("SINGLE_SIGNER_VALIDATION_MODULE", address(0));
        singleSignerValidationModuleSalt = vm.envOr("SINGLE_SIGNER_VALIDATION_MODULE_SALT", uint256(0));

        expectedTimeRangeModuleAddr = vm.envOr("TIME_RANGE_MODULE", address(0));
        timeRangeModuleSalt = vm.envOr("TIME_RANGE_MODULE_SALT", uint256(0));

        expectedWebAuthnValidationModuleAddr = vm.envOr("WEBAUTHN_VALIDATION_MODULE", address(0));
        webAuthnValidationModuleSalt = vm.envOr("WEBAUTHN_VALIDATION_MODULE_SALT", uint256(0));
    }

    function run() public onlyProfile("optimized-build") {
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

        vm.stopBroadcast();

        console.log("******** Modules Deployed *********");
    }
}
