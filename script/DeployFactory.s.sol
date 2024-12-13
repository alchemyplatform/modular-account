// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {console} from "forge-std/console.sol";

import {ModularAccount} from "../src/account/ModularAccount.sol";
import {SemiModularAccountBytecode} from "../src/account/SemiModularAccountBytecode.sol";
import {Artifacts} from "./Artifacts.sol";
import {ScriptBase} from "./ScriptBase.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

// Deploys the Account Factory. This requires the following env vars to be set:
// - ENTRY_POINT
// - MODULAR_ACCOUNT_IMPL
// - SEMI_MODULAR_ACCOUNT_BYTECODE_IMPL
// - SINGLE_SIGNER_VALIDATION_MODULE
// - WEBAUTHN_VALIDATION_MODULE
// - FACTORY_OWNER
contract DeployFactoryScript is ScriptBase, Artifacts {
    // State vars for expected addresses and salts.

    address public expectedFactoryAddr;
    uint256 public factorySalt;

    // State vars for factory dependencies

    IEntryPoint public entryPoint;
    ModularAccount public modularAccountImpl;
    SemiModularAccountBytecode public semiModularAccountBytecodeImpl;
    address public singleSignerValidationModule;
    address public webAuthnValidationModule;
    address public factoryOwner;

    function setUp() public {
        // Load the required addresses for the factory deployment from env vars.
        entryPoint = _getEntryPoint();
        modularAccountImpl = ModularAccount(payable(_getModularAccountImpl()));
        semiModularAccountBytecodeImpl = SemiModularAccountBytecode(payable(_getSemiModularAccountBytecodeImpl()));
        singleSignerValidationModule = _getSingleSignerValidationModule();
        webAuthnValidationModule = _getWebAuthnValidationModule();
        factoryOwner = _getFactoryOwner();

        // Load the expected address and salt from env vars.
        expectedFactoryAddr = vm.envOr("ACCOUNT_FACTORY", address(0));
        factorySalt = _getSaltOrZero("ACCOUNT_FACTORY");
    }

    function run() public onlyProfile("optimized-build-standalone") {
        console.log("******** Deploying Factory *********");

        vm.startBroadcast();

        _safeDeploy(
            "Account Factory",
            expectedFactoryAddr,
            factorySalt,
            _getAccountFactoryInitcode(
                entryPoint,
                modularAccountImpl,
                semiModularAccountBytecodeImpl,
                singleSignerValidationModule,
                webAuthnValidationModule,
                factoryOwner
            ),
            _wrappedDeployAccountFactory
        );

        vm.stopBroadcast();

        console.log("******** Factory Deployed *********");
    }

    // Wrapper function to be called within _safeDeploy using the context in this contract.
    function _wrappedDeployAccountFactory(bytes32 salt) internal returns (address) {
        _ensureNonzeroFactoryArgs();
        return _deployAccountFactory(
            salt,
            entryPoint,
            modularAccountImpl,
            semiModularAccountBytecodeImpl,
            singleSignerValidationModule,
            webAuthnValidationModule,
            factoryOwner
        );
    }

    function _ensureNonzeroFactoryArgs() internal view {
        bool shouldRevert;
        if (address(modularAccountImpl) == address(0)) {
            console.log("Env Variable 'MODULAR_ACCOUNT_IMPL' not found or invalid during factory deployment");
            shouldRevert = true;
        } else {
            console.log("Using user-defined ModularAccount at: %x", address(modularAccountImpl));
        }

        if (address(semiModularAccountBytecodeImpl) == address(0)) {
            console.log(
                "Env Variable 'SEMI_MODULAR_ACCOUNT_BYTECODE_IMPL' not found or invalid during factory deployment"
            );
            shouldRevert = true;
        } else {
            console.log(
                "Using user-defined SemiModularAccountBytecode at: %x", address(semiModularAccountBytecodeImpl)
            );
        }

        if (singleSignerValidationModule == address(0)) {
            console.log(
                "Env Variable 'SINGLE_SIGNER_VALIDATION_MODULE' not found or invalid during factory deployment"
            );
            shouldRevert = true;
        } else {
            console.log("Using user-defined SingleSignerValidationModule at: %x", singleSignerValidationModule);
        }

        if (webAuthnValidationModule == address(0)) {
            console.log("Env Variable 'WEBAUTHN_VALIDATION_MODULE' not found or invalid during factory deployment");
            shouldRevert = true;
        } else {
            console.log("Using user-defined WebAuthnValidationModule at: %x", webAuthnValidationModule);
        }

        if (factoryOwner == address(0)) {
            console.log("Env Variable 'ACCOUNT_FACTORY_OWNER' not found or invalid during factory deployment");
            shouldRevert = true;
        } else {
            console.log("Using user-defined factory owner at: %x", factoryOwner);
        }

        if (shouldRevert) {
            revert("Missing or invalid env variables during factory deployment");
        }
    }
}
