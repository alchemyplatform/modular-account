// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {ModularAccount} from "../src/account/ModularAccount.sol";
import {SemiModularAccountBytecode} from "../src/account/SemiModularAccountBytecode.sol";
import {ExecutionInstallDelegate} from "../src/helpers/ExecutionInstallDelegate.sol";

import {Artifacts} from "./Artifacts.sol";

// Logs all initcode hashes from deployment artifacts.
// Generates in order of dependencies:
// No dependencies:
// - AllowlistModule
// - ExecutionInstallDelegate
// - NativeTokenLimitModule
// - PaymasterGuardModule
// - SingleSignerValidationModule
// - TimeRangeModule
// - WebAuthnValidationModule
// Depends on EntryPoint and ExecutionInstallDelegate:
// - ModularAccount
// - SemiModularAccount7702
// - SemiModularAccountBytecode
// - SemiModularAccountStorageOnly
// Depends on EntryPoint, ModularAccount impl, SemiModularAccountBytecode impl, SingleSignerValidationModule,
// WebAuthnValidationModule, and owner address:
// - AccountFactory

contract GetInitcodeHashScript is Script, Artifacts {
    function run() public view {
        // Assert that the correct profile is being used.
        string memory profile = vm.envOr(string("FOUNDRY_PROFILE"), string(""));

        if (keccak256(bytes(profile)) != keccak256("optimized-build")) {
            revert("This script should be run with the `optimized-build` profile.");
        }

        console.log("******** Calculating Initcode Hashes *********");

        console.log("Artifact initcode hashes with no dependencies:");
        console.log("- AllowlistModule: %x", uint256(keccak256(_getAllowlistModuleInitcode())));
        console.log("- ExecutionInstallDelegate: %x", uint256(keccak256(_getExecutionInstallDelegateInitcode())));
        console.log("- NativeTokenLimitModule: %x", uint256(keccak256(_getNativeTokenLimitModuleInitcode())));
        console.log("- PaymasterGuardModule: %x", uint256(keccak256(_getPaymasterGuardModuleInitcode())));
        console.log(
            "- SingleSignerValidationModule: %x", uint256(keccak256(_getSingleSignerValidationModuleInitcode()))
        );
        console.log("- TimeRangeModule: %x", uint256(keccak256(_getTimeRangeModuleInitcode())));
        console.log("- WebAuthnValidationModule: %x", uint256(keccak256(_getWebAuthnValidationModuleInitcode())));

        console.log("Artifact initcode hashes with dependencies on EntryPoint and ExecutionInstallDelegate:");
        IEntryPoint entryPoint = IEntryPoint(payable(vm.envOr("ENTRYPOINT", address(0))));
        if (address(entryPoint) == address(0)) {
            console.log(
                "Env Variable 'ENTRYPOINT' not found or invalid, defaulting to v0.7 EntryPoint at "
                "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
            );
            entryPoint = IEntryPoint(0x0000000071727De22E5E9d8BAf0edAc6f37da032);
        } else {
            console.log("Using user-defined EntryPoint at: %x", address(entryPoint));
        }
        ExecutionInstallDelegate executionInstallDelegate =
            ExecutionInstallDelegate(vm.envOr("EXECUTION_INSTALL_DELEGATE", address(0)));

        if (address(executionInstallDelegate) == address(0)) {
            console.log(
                "Env Variable 'EXECUTION_INSTALL_DELEGATE' not found or invalid, skipping reporting "
                "initcode hashes for ModularAccount, SemiModularAccount7702, SemiModularAccountBytecode, "
                "and SemiModularAccountStorageOnly"
            );
        } else {
            console.log("Using user-defined ExecutionInstallDelegate at: %x", address(executionInstallDelegate));

            console.log(
                "- ModularAccount: %x",
                uint256(keccak256(_getModularAccountInitcode(entryPoint, executionInstallDelegate)))
            );
            console.log(
                "- SemiModularAccount7702: %x",
                uint256(keccak256(_getSemiModularAccount7702Initcode(entryPoint, executionInstallDelegate)))
            );
            console.log(
                "- SemiModularAccountBytecode: %x",
                uint256(keccak256(_getSemiModularAccountBytecodeInitcode(entryPoint, executionInstallDelegate)))
            );
            console.log(
                "- SemiModularAccountStorageOnly: %x",
                uint256(keccak256(_getSemiModularAccountStorageOnlyInitcode(entryPoint, executionInstallDelegate)))
            );
        }

        console.log(
            "Artifact initcode hashes with dependency on EntryPoint, ModularAccount impl, "
            "SemiModularAccountBytecode impl, SingleSignerValidationModule, "
            "WebAuthnValidationModule, and owner address:"
        );

        ModularAccount modularAccountImpl = ModularAccount(payable(vm.envOr("MODULAR_ACCOUNT_IMPL", address(0))));
        SemiModularAccountBytecode semiModularImpl =
            SemiModularAccountBytecode(payable(vm.envOr("SEMI_MODULAR_ACCOUNT_BYTECODE_IMPL", address(0))));
        address singleSignerValidationModule = vm.envOr("SINGLE_SIGNER_VALIDATION_MODULE", address(0));
        address webAuthnValidationModule = vm.envOr("WEBAUTHN_VALIDATION_MODULE", address(0));
        address factoryOwner = vm.envOr("FACTORY_OWNER", address(0));

        if (address(modularAccountImpl) == address(0)) {
            console.log(
                "Env Variable 'MODULAR_ACCOUNT_IMPL' not found or invalid, skipping reporting initcode hash for "
                "AccountFactory"
            );
            return;
        } else {
            console.log("Using user-defined ModularAccount at: %x", address(modularAccountImpl));
        }

        if (address(semiModularImpl) == address(0)) {
            console.log(
                "Env Variable 'SEMI_MODULAR_ACCOUNT_BYTECODE_IMPL' not found or invalid, skipping reporting "
                "initcode hash for AccountFactory"
            );
            return;
        } else {
            console.log("Using user-defined SemiModularAccountBytecode at: %x", address(semiModularImpl));
        }

        if (singleSignerValidationModule == address(0)) {
            console.log(
                "Env Variable 'SINGLE_SIGNER_VALIDATION_MODULE' not found or invalid, skipping reporting "
                "initcode hash for AccountFactory"
            );
            return;
        } else {
            console.log("Using user-defined SingleSignerValidationModule at: %x", singleSignerValidationModule);
        }

        if (webAuthnValidationModule == address(0)) {
            console.log(
                "Env Variable 'WEBAUTHN_VALIDATION_MODULE' not found or invalid, skipping reporting initcode "
                "hash for AccountFactory"
            );
            return;
        } else {
            console.log("Using user-defined WebAuthnValidationModule at: %x", webAuthnValidationModule);
        }

        if (factoryOwner == address(0)) {
            console.log(
                "Env Variable 'FACTORY_OWNER' not found or invalid, skipping reporting initcode hash for "
                "AccountFactory"
            );
            return;
        } else {
            console.log("Using user-defined factory owner at: %x", factoryOwner);
        }

        console.log(
            "- AccountFactory: %x",
            uint256(
                keccak256(
                    _getAccountFactoryInitcode(
                        entryPoint,
                        modularAccountImpl,
                        semiModularImpl,
                        singleSignerValidationModule,
                        webAuthnValidationModule,
                        factoryOwner
                    )
                )
            )
        );
    }
}
