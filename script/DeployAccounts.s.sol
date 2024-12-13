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
contract DeployAccountsScript is ScriptBase, Artifacts {
    // State vars for expected addresses and salts.

    IEntryPoint public entryPoint;

    address public executionInstallDelegate;

    address public expectedModularAccountImpl;
    uint256 public modularAccountImplSalt;

    address public expectedSemiModularAccountBytecodeImpl;
    uint256 public semiModularAccountBytecodeImplSalt;

    address public expectedSemiModularAccount7702Impl;
    uint256 public semiModularAccount7702ImplSalt;

    function setUp() public {
        // Load the required addresses for the deployment from env vars.
        entryPoint = _getEntryPoint();

        executionInstallDelegate = _getExecutionInstallDelegate();

        expectedModularAccountImpl = _getModularAccountImpl();
        modularAccountImplSalt = _getSaltOrZero("MODULAR_ACCOUNT_IMPL");

        expectedSemiModularAccountBytecodeImpl = _getSemiModularAccountBytecodeImpl();
        semiModularAccountBytecodeImplSalt = _getSaltOrZero("SEMI_MODULAR_ACCOUNT_BYTECODE_IMPL");

        expectedSemiModularAccount7702Impl = _getSemiModularAccount7702Impl();
        semiModularAccount7702ImplSalt = _getSaltOrZero("SEMI_MODULAR_ACCOUNT_7702_IMPL");
    }

    function run() public onlyProfile("optimized-build") {
        console.log("******** Deploying Account Implementations *********");

        _ensureNonzeroArgs();

        vm.startBroadcast();

        // At this point, the delegate and entrypoint are valid, so we can safely proceed with
        // using them as parameters and accessing them in wrapped functions.

        _safeDeploy(
            "Modular Account Impl",
            expectedModularAccountImpl,
            modularAccountImplSalt,
            _getModularAccountInitcode(entryPoint, ExecutionInstallDelegate(executionInstallDelegate)),
            _wrappedDeployModularAccount
        );

        _safeDeploy(
            "Semi Modular Account Bytecode Impl",
            expectedSemiModularAccountBytecodeImpl,
            semiModularAccountBytecodeImplSalt,
            _getSemiModularAccountBytecodeInitcode(entryPoint, ExecutionInstallDelegate(executionInstallDelegate)),
            _wrappedDeploySemiModularAccountBytecode
        );

        _safeDeploy(
            "Semi Modular Account 7702 Impl",
            expectedSemiModularAccount7702Impl,
            semiModularAccount7702ImplSalt,
            _getSemiModularAccount7702Initcode(entryPoint, ExecutionInstallDelegate(executionInstallDelegate)),
            _wrappedDeploySemiModularAccount7702
        );

        vm.stopBroadcast();

        console.log("******** Account Implementations Deployed *********");
    }

    // These functions wrap the internal deployment functions to provide access to the needed state variables
    // without affecting the expected signature from _safeDeploy.

    function _wrappedDeployModularAccount(bytes32 salt) internal returns (address) {
        return _deployModularAccount(salt, entryPoint, ExecutionInstallDelegate(executionInstallDelegate));
    }

    function _wrappedDeploySemiModularAccountBytecode(bytes32 salt) internal returns (address) {
        return
            _deploySemiModularAccountBytecode(salt, entryPoint, ExecutionInstallDelegate(executionInstallDelegate));
    }

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
            revert("Missing or invalid env variables during factory deployment");
        }
    }
}
