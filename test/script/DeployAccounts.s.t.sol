// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";

import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {DeployAccountsScript} from "../../script/DeployAccounts.s.sol";
import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {SemiModularAccountBytecode} from "../../src/account/SemiModularAccountBytecode.sol";
import {SemiModularAccountStorageOnly} from "../../src/account/SemiModularAccountStorageOnly.sol";
import {ExecutionInstallDelegate} from "../../src/helpers/ExecutionInstallDelegate.sol";

contract DeployAccountsTest is Test {
    DeployAccountsScript internal _deployAccountsScript;

    address public entryPoint;
    address public executionInstallDelegate;
    address public modularAccountImpl;
    address public semiModularAccountBytecodeImpl;
    address public semiModularAccountStorageOnlyImpl;

    function setUp() public {
        _deployAccountsScript = new DeployAccountsScript();

        bytes32 zeroSalt = bytes32(0);

        entryPoint = makeAddr("Entrypoint");

        executionInstallDelegate = Create2.computeAddress(
            zeroSalt, keccak256(type(ExecutionInstallDelegate).creationCode), CREATE2_FACTORY
        );

        modularAccountImpl = Create2.computeAddress(
            zeroSalt,
            keccak256(
                bytes.concat(type(ModularAccount).creationCode, abi.encode(entryPoint, executionInstallDelegate))
            ),
            CREATE2_FACTORY
        );

        semiModularAccountBytecodeImpl = Create2.computeAddress(
            zeroSalt,
            keccak256(
                bytes.concat(
                    type(SemiModularAccountBytecode).creationCode, abi.encode(entryPoint, executionInstallDelegate)
                )
            ),
            CREATE2_FACTORY
        );

        semiModularAccountStorageOnlyImpl = Create2.computeAddress(
            zeroSalt,
            keccak256(
                bytes.concat(
                    type(SemiModularAccountStorageOnly).creationCode,
                    abi.encode(entryPoint, executionInstallDelegate)
                )
            ),
            CREATE2_FACTORY
        );

        vm.setEnv("ENTRYPOINT", vm.toString(entryPoint));
        vm.setEnv("EXECUTION_INSTALL_DELEGATE", vm.toString(executionInstallDelegate));
        vm.setEnv("MODULAR_ACCOUNT_IMPL", vm.toString(modularAccountImpl));
        vm.setEnv("SEMI_MODULAR_ACCOUNT_BYTECODE_IMPL", vm.toString(semiModularAccountBytecodeImpl));
        vm.setEnv("SEMI_MODULAR_ACCOUNT_STORAGE_ONLY_IMPL", vm.toString(semiModularAccountStorageOnlyImpl));

        string memory zeroSaltString = vm.toString(zeroSalt);

        vm.setEnv("EXECUTION_INSTALL_DELEGATE_SALT", zeroSaltString);
        vm.setEnv("MODULAR_ACCOUNT_IMPL_SALT", zeroSaltString);
        vm.setEnv("SEMI_MODULAR_ACCOUNT_BYTECODE_IMPL_SALT", zeroSaltString);
        vm.setEnv("SEMI_MODULAR_ACCOUNT_STORAGE_ONLY_IMPL_SALT", zeroSaltString);

        // Spoof as though the profile is set to "optimized-build".
        vm.setEnv("FOUNDRY_PROFILE", "optimized-build");
    }

    function test_deployFactoryScript() public {
        _deployAccountsScript.setUp();

        _deployAccountsScript.run();

        assertEq(ModularAccount(payable(modularAccountImpl)).accountId(), "alchemy.modular-account.2.0.0");

        assertEq(
            SemiModularAccountBytecode(payable(semiModularAccountBytecodeImpl)).accountId(),
            "alchemy.sma-bytecode.1.0.0"
        );

        assertEq(
            SemiModularAccountStorageOnly(payable(semiModularAccountStorageOnlyImpl)).accountId(),
            "alchemy.sma-storage.1.0.0"
        );

        // Check that the delegate's in the right place by checking that `installExecution()` can only be called
        // via delegatecall.
        ExecutionManifest memory manifest;
        vm.expectRevert(ExecutionInstallDelegate.OnlyDelegateCall.selector);
        ExecutionInstallDelegate(executionInstallDelegate).installExecution(address(0), manifest, "");
    }
}
