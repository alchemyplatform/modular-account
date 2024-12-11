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

    address public expectedExecutionInstallDelegate;
    uint256 public executionInstallDelegateSalt;

    address public expectedModularAccountImpl;
    uint256 public modularAccountImplSalt;

    address public expectedSemiModularAccountBytecodeImpl;
    uint256 public semiModularAccountBytecodeImplSalt;

    address public expectedSemiModularAccountStorageOnlyImpl;
    uint256 public semiModularAccountStorageOnlyImplSalt;

    function setUp() public {
        // Load the required addresses for the deployment from env vars.
        entryPoint = _getEntryPoint();

        expectedExecutionInstallDelegate = _getExecutionInstallDelegate();
        executionInstallDelegateSalt = _getSaltOrZero("EXECUTION_INSTALL_DELEGATE");

        expectedModularAccountImpl = _getModularAccountImpl();
        modularAccountImplSalt = _getSaltOrZero("MODULAR_ACCOUNT_IMPL");

        expectedSemiModularAccountBytecodeImpl = _getSemiModularAccountBytecodeImpl();
        semiModularAccountBytecodeImplSalt = _getSaltOrZero("SEMI_MODULAR_ACCOUNT_BYTECODE_IMPL");

        expectedSemiModularAccountStorageOnlyImpl = address(_getSemiModularAccountStorageOnlyImpl());
        semiModularAccountStorageOnlyImplSalt = _getSaltOrZero("SEMI_MODULAR_ACCOUNT_STORAGE_ONLY_IMPL");
    }

    function run() public onlyProfile("optimized-build") {
        console.log("******** Deploying Account Implementations and Execution Install Delegate *********");

        vm.startBroadcast();

        _safeDeploy(
            "Execution Install Delegate",
            expectedExecutionInstallDelegate,
            executionInstallDelegateSalt,
            _getExecutionInstallDelegateInitcode(),
            _deployExecutionInstallDelegate
        );

        // At this point, the delegate and entrypoint are valid, so we can safely proceed with
        // using them as parameters and accessing them in wrapped functions.

        _safeDeploy(
            "Modular Account Impl",
            expectedModularAccountImpl,
            modularAccountImplSalt,
            _getModularAccountInitcode(entryPoint, ExecutionInstallDelegate(expectedExecutionInstallDelegate)),
            _wrappedDeployModularAccount
        );

        _safeDeploy(
            "Semi Modular Account Bytecode Impl",
            expectedSemiModularAccountBytecodeImpl,
            semiModularAccountBytecodeImplSalt,
            _getSemiModularAccountBytecodeInitcode(
                entryPoint, ExecutionInstallDelegate(expectedExecutionInstallDelegate)
            ),
            _wrappedDeploySemiModularAccountBytecode
        );

        _safeDeploy(
            "Semi Modular Account Storage Only Impl",
            expectedSemiModularAccountStorageOnlyImpl,
            semiModularAccountStorageOnlyImplSalt,
            _getSemiModularAccountStorageOnlyInitcode(
                entryPoint, ExecutionInstallDelegate(expectedExecutionInstallDelegate)
            ),
            _wrappedDeploySemiModularAccountStorageOnly
        );

        vm.stopBroadcast();

        console.log("******** Account Implementations and Execution Install Delegate Deployed *********");
    }

    // These functions wrap the internal deployment functions to provide access to the needed state variables
    // without affecting the expected signature from _safeDeploy.

    function _wrappedDeployModularAccount(bytes32 salt) internal returns (address) {
        return _deployModularAccount(salt, entryPoint, ExecutionInstallDelegate(expectedExecutionInstallDelegate));
    }

    function _wrappedDeploySemiModularAccountBytecode(bytes32 salt) internal returns (address) {
        return _deploySemiModularAccountBytecode(
            salt, entryPoint, ExecutionInstallDelegate(expectedExecutionInstallDelegate)
        );
    }

    function _wrappedDeploySemiModularAccountStorageOnly(bytes32 salt) internal returns (address) {
        return _deploySemiModularAccountStorageOnly(
            salt, entryPoint, ExecutionInstallDelegate(expectedExecutionInstallDelegate)
        );
    }
}
