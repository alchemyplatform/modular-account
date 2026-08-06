// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {console} from "forge-std/console.sol";

import {ModularAccount} from "../src/account/ModularAccount.sol";
import {Artifacts} from "./Artifacts.sol";
import {ScriptBase} from "./ScriptBase.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

// Deploys the WebAuthn Account Factory. This requires the following env vars to be set:
// - ENTRY_POINT
// - MODULAR_ACCOUNT_IMPL
// - WEBAUTHN_VALIDATION_MODULE
// - FACTORY_OWNER
contract DeployWebAuthnFactoryScript is ScriptBase, Artifacts {
    // State vars for expected addresses and salts.

    address public expectedFactoryAddr;
    uint256 public factorySalt;

    // State vars for factory dependencies

    IEntryPoint public entryPoint;
    ModularAccount public modularAccountImpl;
    address public webAuthnValidationModule;
    address public factoryOwner;

    function setUp() public {
        // Load the required addresses for the factory deployment from env vars.
        entryPoint = _getEntryPoint();
        modularAccountImpl = ModularAccount(payable(_getModularAccountImpl()));
        webAuthnValidationModule = _getWebAuthnValidationModule();
        factoryOwner = _getFactoryOwner();

        // Load the expected address and salt from env vars.
        expectedFactoryAddr = vm.envOr("WEBAUTHN_ACCOUNT_FACTORY", address(0));
        factorySalt = _getSaltOrZero("WEBAUTHN_ACCOUNT_FACTORY");
    }

    function run() public onlyProfile("optimized-build-standalone") {
        console.log("******** Deploying Factory *********");

        vm.startBroadcast();

        _safeDeploy(
            "Account Factory",
            expectedFactoryAddr,
            factorySalt,
            _getWebAuthnFactoryInitcode(entryPoint, modularAccountImpl, webAuthnValidationModule, factoryOwner),
            _wrappedDeployAccountFactory
        );

        vm.stopBroadcast();

        console.log("******** WebAuthn Factory Deployed *********");
    }

    // Wrapper function to be called within _safeDeploy using the context in this contract.
    function _wrappedDeployAccountFactory(bytes32 salt) internal returns (address) {
        _ensureNonzeroFactoryArgs();
        return _deployWebAuthnFactory(salt, entryPoint, modularAccountImpl, webAuthnValidationModule, factoryOwner);
    }

    function _ensureNonzeroFactoryArgs() internal view {
        bool shouldRevert;
        if (address(modularAccountImpl) == address(0)) {
            console.log("Env Variable 'MODULAR_ACCOUNT_IMPL' not found or invalid during factory deployment");
            shouldRevert = true;
        } else {
            console.log("Using user-defined ModularAccount at: %x", address(modularAccountImpl));
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
