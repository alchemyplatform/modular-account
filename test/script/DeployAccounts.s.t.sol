// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {DeployAccountsScript} from "../../script/DeployAccounts.s.sol";
import {ModularAccount} from "../../src/account/ModularAccount.sol";

import {SemiModularAccount7702} from "../../src/account/SemiModularAccount7702.sol";
import {SemiModularAccountBytecode} from "../../src/account/SemiModularAccountBytecode.sol";

contract DeployAccountsTest is Test {
    DeployAccountsScript internal _deployAccountsScript;

    address public entryPoint;
    address public executionInstallDelegate;
    address public modularAccountImpl;
    address public semiModularAccountBytecodeImpl;
    address public semiModularAccount7702Impl;

    function setUp() public {
        _deployAccountsScript = new DeployAccountsScript();

        bytes32 zeroSalt = bytes32(0);

        entryPoint = makeAddr("Entrypoint");

        executionInstallDelegate = makeAddr("ExecutionInstallDelegate");

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

        semiModularAccount7702Impl = Create2.computeAddress(
            zeroSalt,
            keccak256(
                bytes.concat(
                    type(SemiModularAccount7702).creationCode, abi.encode(entryPoint, executionInstallDelegate)
                )
            ),
            CREATE2_FACTORY
        );

        vm.setEnv("ENTRYPOINT", vm.toString(entryPoint));
        vm.setEnv("EXECUTION_INSTALL_DELEGATE", vm.toString(executionInstallDelegate));
        vm.setEnv("MODULAR_ACCOUNT_IMPL", vm.toString(modularAccountImpl));
        vm.setEnv("SEMI_MODULAR_ACCOUNT_BYTECODE_IMPL", vm.toString(semiModularAccountBytecodeImpl));
        vm.setEnv("SEMI_MODULAR_ACCOUNT_7702_IMPL", vm.toString(semiModularAccount7702Impl));

        string memory zeroSaltString = vm.toString(zeroSalt);

        vm.setEnv("MODULAR_ACCOUNT_IMPL_SALT", zeroSaltString);
        vm.setEnv("SEMI_MODULAR_ACCOUNT_BYTECODE_IMPL_SALT", zeroSaltString);
        vm.setEnv("SEMI_MODULAR_ACCOUNT_7702_IMPL_SALT", zeroSaltString);

        // Spoof as though the profile is set to "optimized-build".
        vm.setEnv("FOUNDRY_PROFILE", "optimized-build");
    }

    function test_deployAccountsScript() public {
        _deployAccountsScript.setUp();

        _deployAccountsScript.run();

        assertEq(ModularAccount(payable(modularAccountImpl)).accountId(), "alchemy.modular-account.2.0.0");

        assertEq(
            SemiModularAccountBytecode(payable(semiModularAccountBytecodeImpl)).accountId(),
            "alchemy.sma-bytecode.1.0.0"
        );

        assertEq(SemiModularAccount7702(payable(semiModularAccount7702Impl)).accountId(), "alchemy.sma-7702.1.0.0");
    }
}
