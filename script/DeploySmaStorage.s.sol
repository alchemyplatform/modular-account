// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {console} from "forge-std/console.sol";

import {ExecutionInstallDelegate} from "../src/helpers/ExecutionInstallDelegate.sol";
import {Artifacts} from "./Artifacts.sol";
import {ScriptBase} from "./ScriptBase.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

// Deploys the three account implementations and an execution install delegate. This requires the following env
// vars to be set:
// - ENTRY_POINT (optional)
contract DeploySmaStorageScript is ScriptBase, Artifacts {
    // State vars for expected addresses and salts.

    IEntryPoint public entryPoint;

    address public executionInstallDelegate;

    address public expectedSemiModularAccountStorageOnlyImpl;
    uint256 public semiModularAccountStorageOnlyImplSalt;

    function setUp() public {
        // Load the required addresses for the deployment from env vars.
        entryPoint = _getEntryPoint();

        executionInstallDelegate = _getExecutionInstallDelegate();

        expectedSemiModularAccountStorageOnlyImpl = _getSemiModularAccountStorageOnlyImpl();
        semiModularAccountStorageOnlyImplSalt = _getSaltOrZero("SEMI_MODULAR_ACCOUNT_STORAGE_ONLY_IMPL");
    }

    function run() public onlyProfile("optimized-build-sma-storage") {
        console.log("******** Deploying SMA-Storage Implementation *********");

        _ensureNonzeroArgs();

        vm.startBroadcast();

        // At this point, the delegate and entrypoint are valid, so we can safely proceed with
        // using them as parameters and accessing them in wrapped functions.

        _safeDeploy(
            "Semi Modular Account Storage Only Impl",
            expectedSemiModularAccountStorageOnlyImpl,
            semiModularAccountStorageOnlyImplSalt,
            _getSemiModularAccountStorageOnlyInitcode(
                entryPoint, ExecutionInstallDelegate(executionInstallDelegate)
            ),
            _wrappedDeploySemiModularAccountStorageOnly
        );

        vm.stopBroadcast();

        console.log("******** SMA-Storage Implementation Deployed *********");
    }

    // These functions wrap the internal deployment functions to provide access to the needed state variables
    // without affecting the expected signature from _safeDeploy.

    function _wrappedDeploySemiModularAccountStorageOnly(bytes32 salt) internal returns (address) {
        return _deploySemiModularAccountStorageOnly(
            salt, entryPoint, ExecutionInstallDelegate(executionInstallDelegate)
        );
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
            revert("Missing or invalid env variables during factory deployment");
        }
    }
}
