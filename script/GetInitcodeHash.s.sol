// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {console} from "forge-std/console.sol";

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {ModularAccount} from "../src/account/ModularAccount.sol";
import {SemiModularAccountBytecode} from "../src/account/SemiModularAccountBytecode.sol";
import {ExecutionInstallDelegate} from "../src/helpers/ExecutionInstallDelegate.sol";

import {Artifacts} from "./Artifacts.sol";
import {ScriptBase} from "./ScriptBase.sol";

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

contract GetInitcodeHashScript is ScriptBase, Artifacts {
    function run() public view {
        string memory actualProfile = vm.envOr(string("FOUNDRY_PROFILE"), string(""));
        console.log(string.concat("Running script with the `", actualProfile, "` profile."));

        console.log("******** Calculating Initcode Hashes *********");

        if (keccak256(bytes(actualProfile)) == keccak256(bytes("optimized-build-standalone"))) {
            console.log("Artifact initcode hashes with no dependencies:");
            console.log("- AllowlistModule: %x", uint256(keccak256(_getAllowlistModuleInitcode())));
            console.log(
                "- ExecutionInstallDelegate: %x", uint256(keccak256(_getExecutionInstallDelegateInitcode()))
            );
            console.log("- NativeTokenLimitModule: %x", uint256(keccak256(_getNativeTokenLimitModuleInitcode())));
            console.log("- PaymasterGuardModule: %x", uint256(keccak256(_getPaymasterGuardModuleInitcode())));
            console.log(
                "- SingleSignerValidationModule: %x",
                uint256(keccak256(_getSingleSignerValidationModuleInitcode()))
            );
            console.log("- TimeRangeModule: %x", uint256(keccak256(_getTimeRangeModuleInitcode())));
            console.log(
                "- WebAuthnValidationModule: %x", uint256(keccak256(_getWebAuthnValidationModuleInitcode()))
            );

            _logFactoryInitcodeHash();
        }

        if (
            keccak256(bytes(actualProfile)) == keccak256(bytes("optimized-build"))
                || keccak256(bytes(actualProfile)) == keccak256(bytes("optimized-build-sma-storage"))
        ) {
            console.log("Artifact initcode hashes with dependencies on EntryPoint and ExecutionInstallDelegate:");
            IEntryPoint entryPoint = _getEntryPoint();

            ExecutionInstallDelegate executionInstallDelegate =
                ExecutionInstallDelegate(_getExecutionInstallDelegate());

            if (address(executionInstallDelegate) == address(0)) {
                console.log(
                    "Env Variable 'EXECUTION_INSTALL_DELEGATE' not found or invalid, skipping reporting "
                    "initcode hashes for ModularAccount, SemiModularAccount7702, SemiModularAccountBytecode, "
                    "and SemiModularAccountStorageOnly"
                );
            } else {
                console.log(
                    "Using user-defined ExecutionInstallDelegate at: %x", address(executionInstallDelegate)
                );

                if (keccak256(bytes(actualProfile)) == keccak256(bytes("optimized-build-sma-storage"))) {
                    console.log(
                        "- SemiModularAccountStorageOnly: %x",
                        uint256(
                            keccak256(
                                _getSemiModularAccountStorageOnlyInitcode(entryPoint, executionInstallDelegate)
                            )
                        )
                    );
                }

                if (keccak256(bytes(actualProfile)) == keccak256(bytes("optimized-build"))) {
                    console.log(
                        "- ModularAccount: %x",
                        uint256(keccak256(_getModularAccountInitcode(entryPoint, executionInstallDelegate)))
                    );
                    console.log(
                        "- SemiModularAccount7702: %x",
                        uint256(
                            keccak256(_getSemiModularAccount7702Initcode(entryPoint, executionInstallDelegate))
                        )
                    );
                    console.log(
                        "- SemiModularAccountBytecode: %x",
                        uint256(
                            keccak256(_getSemiModularAccountBytecodeInitcode(entryPoint, executionInstallDelegate))
                        )
                    );
                }
            }
        }
    }

    function _logFactoryInitcodeHash() internal view {
        IEntryPoint entryPoint = _getEntryPoint();

        console.log(
            "Artifact initcode hashes with dependency on EntryPoint, ModularAccount impl, "
            "SemiModularAccountBytecode impl, SingleSignerValidationModule, "
            "WebAuthnValidationModule, and owner address:"
        );

        ModularAccount modularAccountImpl = ModularAccount(payable(_getModularAccountImpl()));
        SemiModularAccountBytecode semiModularImpl =
            SemiModularAccountBytecode(payable(_getSemiModularAccountBytecodeImpl()));
        address singleSignerValidationModule = _getSingleSignerValidationModule();
        address webAuthnValidationModule = _getWebAuthnValidationModule();
        address factoryOwner = _getFactoryOwner();

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
