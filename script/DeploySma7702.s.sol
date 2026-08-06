// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {console} from "forge-std/console.sol";

import {ExecutionInstallDelegate} from "../src/helpers/ExecutionInstallDelegate.sol";
import {Artifacts} from "./Artifacts.sol";
import {ScriptBase} from "./ScriptBase.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

// Deploys only the SemiModularAccount7702 implementation. This requires the following env vars to be set:
// - EXECUTION_INSTALL_DELEGATE
// - SEMI_MODULAR_ACCOUNT_7702_IMPL
// - SEMI_MODULAR_ACCOUNT_7702_IMPL_SALT (optional, defaults to zero)
// - ENTRYPOINT (optional, defaults to the v0.7 EntryPoint)
contract DeploySma7702Script is ScriptBase, Artifacts {
    // State vars for expected addresses and salts.

    IEntryPoint public entryPoint;

    address public executionInstallDelegate;

    address public expectedSemiModularAccount7702Impl;
    uint256 public semiModularAccount7702ImplSalt;

    function setUp() public {
        // Load the required addresses for the deployment from env vars.
        entryPoint = _getEntryPoint();

        executionInstallDelegate = _getExecutionInstallDelegate();

        expectedSemiModularAccount7702Impl = _getSemiModularAccount7702Impl();
        semiModularAccount7702ImplSalt = _getSaltOrZero("SEMI_MODULAR_ACCOUNT_7702_IMPL");
    }

    // Uses the same profile as DeployAccounts so the deployed bytecode, and therefore the CREATE2 address,
    // matches the one produced by the full account deployment.
    function run() public onlyProfile("optimized-build") {
        console.log("******** Deploying SMA-7702 Implementation *********");

        _ensureNonzeroArgs();

        vm.startBroadcast();

        // At this point, the delegate and entrypoint are valid, so we can safely proceed with
        // using them as parameters and accessing them in wrapped functions.

        _safeDeploy(
            "Semi Modular Account 7702 Impl",
            expectedSemiModularAccount7702Impl,
            semiModularAccount7702ImplSalt,
            _getSemiModularAccount7702Initcode(entryPoint, ExecutionInstallDelegate(executionInstallDelegate)),
            _wrappedDeploySemiModularAccount7702
        );

        vm.stopBroadcast();

        console.log("******** SMA-7702 Implementation Deployed *********");
    }

    // These functions wrap the internal deployment functions to provide access to the needed state variables
    // without affecting the expected signature from _safeDeploy.

    function _wrappedDeploySemiModularAccount7702(bytes32 salt) internal returns (address) {
        return _deploySemiModularAccount7702(salt, entryPoint, ExecutionInstallDelegate(executionInstallDelegate));
    }

    function _ensureNonzeroArgs() internal view {
        bool shouldRevert;

        if (address(executionInstallDelegate) == address(0)) {
            console.log(
                "Env Variable 'EXECUTION_INSTALL_DELEGATE' not found or invalid during accounts deployment."
            );
            shouldRevert = true;
        } else {
            console.log("Using user-defined ExecutionInstallDelegate at: %x", executionInstallDelegate);
        }

        if (shouldRevert) {
            revert("Missing or invalid env variables during SMA-7702 deployment");
        }
    }
}
