// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {console} from "forge-std/console.sol";

import {Artifacts} from "./Artifacts.sol";
import {ScriptBase} from "./ScriptBase.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

// Predicts addresses for all standalone modules with salts taken from the environment.
// - AllowlistModule
// - NativeTokenLimitModule
// - PaymasterGuardModule
// - SingleSignerValidationModule
// - TimeRangeModule
// - WebAuthnValidationModule
contract DeployModulesScript is ScriptBase, Artifacts {
    // State vars for salts.

    uint256 public allowlistModuleSalt;
    uint256 public nativeTokenLimitModuleSalt;
    uint256 public paymasterGuardModuleSalt;
    uint256 public singleSignerValidationModuleSalt;
    uint256 public timeRangeModuleSalt;
    uint256 public webAuthnValidationModuleSalt;

    function setUp() public {
        // Load the salts from env vars.

        allowlistModuleSalt = vm.envOr("ALLOWLIST_MODULE_SALT", uint256(0));
        nativeTokenLimitModuleSalt = vm.envOr("NATIVE_TOKEN_LIMIT_MODULE_SALT", uint256(0));
        paymasterGuardModuleSalt = vm.envOr("PAYMASTER_GUARD_MODULE_SALT", uint256(0));
        singleSignerValidationModuleSalt = vm.envOr("SINGLE_SIGNER_VALIDATION_MODULE_SALT", uint256(0));
        timeRangeModuleSalt = vm.envOr("TIME_RANGE_MODULE_SALT", uint256(0));
        webAuthnValidationModuleSalt = vm.envOr("WEBAUTHN_VALIDATION_MODULE_SALT", uint256(0));
    }

    function run() public view onlyProfile("optimized-build") {
        console.log("******** Logging Expected Module Addresses With Env Salts *********");

        console.log(
            "ALLOWLIST_MODULE=",
            Create2.computeAddress(
                bytes32(allowlistModuleSalt), keccak256(_getAllowlistModuleInitcode()), CREATE2_FACTORY
            )
        );

        console.log(
            "NATIVE_TOKEN_LIMIT_MODULE=",
            Create2.computeAddress(
                bytes32(nativeTokenLimitModuleSalt),
                keccak256(_getNativeTokenLimitModuleInitcode()),
                CREATE2_FACTORY
            )
        );

        console.log(
            "PAYMASTER_GUARD_MODULE=",
            Create2.computeAddress(
                bytes32(paymasterGuardModuleSalt), keccak256(_getPaymasterGuardModuleInitcode()), CREATE2_FACTORY
            )
        );

        console.log(
            "SINGLE_SIGNER_VALIDATION_MODULE=",
            Create2.computeAddress(
                bytes32(singleSignerValidationModuleSalt),
                keccak256(_getSingleSignerValidationModuleInitcode()),
                CREATE2_FACTORY
            )
        );

        console.log(
            "TIME_RANGE_MODULE=",
            Create2.computeAddress(
                bytes32(timeRangeModuleSalt), keccak256(_getTimeRangeModuleInitcode()), CREATE2_FACTORY
            )
        );

        console.log(
            "WEBAUTHN_VALIDATION_MODULE=",
            Create2.computeAddress(
                bytes32(webAuthnValidationModuleSalt),
                keccak256(_getWebAuthnValidationModuleInitcode()),
                CREATE2_FACTORY
            )
        );
    }
}
