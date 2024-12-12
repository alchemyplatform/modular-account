// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {console} from "forge-std/console.sol";

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {ModularAccount} from "../src/account/ModularAccount.sol";
import {SemiModularAccountBytecode} from "../src/account/SemiModularAccountBytecode.sol";
import {ExecutionInstallDelegate} from "../src/helpers/ExecutionInstallDelegate.sol";
import {Artifacts} from "./Artifacts.sol";
import {ScriptBase} from "./ScriptBase.sol";

// Predicts addresses for all contracts with salts taken from the environment.
// - AllowlistModule
// - NativeTokenLimitModule
// - PaymasterGuardModule
// - SingleSignerValidationModule
// - TimeRangeModule
// - WebAuthnValidationModule
contract PredictAddressScript is ScriptBase, Artifacts {
    // State vars for salts.

    uint256 public allowlistModuleSalt;
    uint256 public nativeTokenLimitModuleSalt;
    uint256 public paymasterGuardModuleSalt;
    uint256 public singleSignerValidationModuleSalt;
    uint256 public timeRangeModuleSalt;
    uint256 public webAuthnValidationModuleSalt;
    uint256 public factorySalt;
    uint256 public executionInstallDelegateSalt;
    uint256 public modularAccountImplSalt;
    uint256 public semiModularAccountBytecodeImplSalt;
    uint256 public semiModularAccountStorageOnlyImplSalt;

    IEntryPoint public entryPoint;
    ExecutionInstallDelegate public executionInstallDelegate;
    address public modularAccountImpl;
    address public semiModularAccountBytecodeImpl;
    address public singleSignerValidationModule;
    address public webAuthnValidationModule;
    address public factoryOwner;

    function setUp() public {
        // Load the salts from env vars.

        allowlistModuleSalt = _getSaltOrZero("ALLOWLIST_MODULE");
        nativeTokenLimitModuleSalt = _getSaltOrZero("NATIVE_TOKEN_LIMIT_MODULE");
        paymasterGuardModuleSalt = _getSaltOrZero("PAYMASTER_GUARD_MODULE");
        singleSignerValidationModuleSalt = _getSaltOrZero("SINGLE_SIGNER_VALIDATION_MODULE");
        timeRangeModuleSalt = _getSaltOrZero("TIME_RANGE_MODULE");
        webAuthnValidationModuleSalt = _getSaltOrZero("WEBAUTHN_VALIDATION_MODULE");
        factorySalt = _getSaltOrZero("ACCOUNT_FACTORY");
        executionInstallDelegateSalt = _getSaltOrZero("EXECUTION_INSTALL_DELEGATE");
        modularAccountImplSalt = _getSaltOrZero("MODULAR_ACCOUNT_IMPL");
        semiModularAccountBytecodeImplSalt = _getSaltOrZero("SEMI_MODULAR_ACCOUNT_BYTECODE_IMPL");
        semiModularAccountStorageOnlyImplSalt = _getSaltOrZero("SEMI_MODULAR_ACCOUNT_STORAGE_ONLY_IMPL");

        // Load the env vars for the account implementations and the factory.
        entryPoint = _getEntryPoint();
        executionInstallDelegate = ExecutionInstallDelegate(_getExecutionInstallDelegate());

        modularAccountImpl = _getModularAccountImpl();
        semiModularAccountBytecodeImpl = _getSemiModularAccountBytecodeImpl();
        singleSignerValidationModule = _getSingleSignerValidationModule();
        webAuthnValidationModule = _getWebAuthnValidationModule();
        factoryOwner = _getFactoryOwner();
    }

    function run() public view onlyProfile("optimized-build") {
        console.log("#******** Logging Expected Addresses With Env Salts *********");

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

        // Needed for factory.
        address computedSingleSignerValidationModule = Create2.computeAddress(
            bytes32(singleSignerValidationModuleSalt),
            keccak256(_getSingleSignerValidationModuleInitcode()),
            CREATE2_FACTORY
        );
        console.log("SINGLE_SIGNER_VALIDATION_MODULE=", computedSingleSignerValidationModule);

        console.log(
            "TIME_RANGE_MODULE=",
            Create2.computeAddress(
                bytes32(timeRangeModuleSalt), keccak256(_getTimeRangeModuleInitcode()), CREATE2_FACTORY
            )
        );

        address computedWebauthValidationModule = Create2.computeAddress(
            bytes32(webAuthnValidationModuleSalt),
            keccak256(_getWebAuthnValidationModuleInitcode()),
            CREATE2_FACTORY
        );
        console.log("WEBAUTHN_VALIDATION_MODULE=", computedWebauthValidationModule);

        console.log("");
        console.log("#******** Logging Expected Account Impl Addresses With Env Salt And Env Addresses *********");

        // Needed for accounts.
        ExecutionInstallDelegate computedExecutionInstallDelegate = ExecutionInstallDelegate(
            Create2.computeAddress(
                bytes32(executionInstallDelegateSalt),
                keccak256(_getExecutionInstallDelegateInitcode()),
                CREATE2_FACTORY
            )
        );
        console.log("EXECUTION_INSTALL_DELEGATE=", address(computedExecutionInstallDelegate));

        if (computedExecutionInstallDelegate != executionInstallDelegate) {
            console.log(
                "#    Create2 computed ExecutionInstallDelegate: %s differs from env: %s, proceeding with"
                "computed value for account computations.",
                address(computedExecutionInstallDelegate),
                address(executionInstallDelegate)
            );
        }

        // Needed for factory.
        address computedModularAccountImpl = Create2.computeAddress(
            bytes32(modularAccountImplSalt),
            keccak256(_getModularAccountInitcode(entryPoint, computedExecutionInstallDelegate)),
            CREATE2_FACTORY
        );
        console.log("MODULAR_ACCOUNT_IMPL=", computedModularAccountImpl);

        // Needed for factory.
        address computedSemiModularAccountBytecodeImpl = Create2.computeAddress(
            bytes32(semiModularAccountBytecodeImplSalt),
            keccak256(_getSemiModularAccountBytecodeInitcode(entryPoint, computedExecutionInstallDelegate)),
            CREATE2_FACTORY
        );
        console.log("SEMI_MODULAR_ACCOUNT_BYTECODE_IMPL=", computedSemiModularAccountBytecodeImpl);

        console.log(
            "SEMI_MODULAR_ACCOUNT_STORAGE_ONLY_IMPL=",
            Create2.computeAddress(
                bytes32(semiModularAccountStorageOnlyImplSalt),
                keccak256(_getSemiModularAccountStorageOnlyInitcode(entryPoint, computedExecutionInstallDelegate)),
                CREATE2_FACTORY
            )
        );

        // Now, we check all factory dependencies and log if they differ from the environment variables.
        console.log("");

        if (computedModularAccountImpl != modularAccountImpl) {
            console.log(
                "#    Create2 computed ModularAccountImpl: %s differs from env: %s,"
                "  proceeding with computed value for Factory computation.",
                computedModularAccountImpl,
                modularAccountImpl
            );
        }

        if (computedSemiModularAccountBytecodeImpl != semiModularAccountBytecodeImpl) {
            console.log(
                "#    Create2 computed SemiModularAccountBytecodeImpl: %s differs from env: %s,"
                " proceeding with computed value for Factory computation.",
                computedSemiModularAccountBytecodeImpl,
                semiModularAccountBytecodeImpl
            );
        }

        if (computedSingleSignerValidationModule != singleSignerValidationModule) {
            console.log(
                "#    Create2 computed SingleSignerValidationModule: %s differs from env: %s,"
                " proceeding with computed value for Factory computation.",
                computedSingleSignerValidationModule,
                singleSignerValidationModule
            );
        }

        if (computedWebauthValidationModule != webAuthnValidationModule) {
            console.log(
                "#    Create2 computed WebAuthnValidationModule: %s differs from env: %s,"
                " proceeding with computed value for Factory computation.",
                computedWebauthValidationModule,
                webAuthnValidationModule
            );
        }

        if (factoryOwner == address(0)) {
            console.log("#    WARNING: ACCOUNT_FACTORY_OWNER is set to zero, this factory will have no owner!");
        }

        console.log("#******** Logging Expected Factory Address With Env Salt And Env Addresses *********");
        console.log(
            "ACCOUNT_FACTORY=",
            Create2.computeAddress(
                bytes32(factorySalt),
                keccak256(
                    _getAccountFactoryInitcode(
                        entryPoint,
                        ModularAccount(payable(computedModularAccountImpl)),
                        SemiModularAccountBytecode(payable(computedSemiModularAccountBytecodeImpl)),
                        computedSingleSignerValidationModule,
                        computedWebauthValidationModule,
                        factoryOwner
                    )
                ),
                CREATE2_FACTORY
            )
        );
    }
}
