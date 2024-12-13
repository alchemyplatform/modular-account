// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {DeploySmaStorageScript} from "../../script/DeploySmaStorage.s.sol";
import {SemiModularAccountStorageOnly} from "../../src/account/SemiModularAccountStorageOnly.sol";

contract DeploySmaStorageTest is Test {
    DeploySmaStorageScript internal _deploySmaStorageScript;

    address public entryPoint;
    address public executionInstallDelegate;
    address public semiModularAccountStorageOnlyImpl;

    function setUp() public {
        _deploySmaStorageScript = new DeploySmaStorageScript();

        bytes32 zeroSalt = bytes32(0);

        entryPoint = makeAddr("Entrypoint");

        executionInstallDelegate = makeAddr("ExecutionInstallDelegate");

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
        vm.setEnv("SEMI_MODULAR_ACCOUNT_STORAGE_ONLY_IMPL", vm.toString(semiModularAccountStorageOnlyImpl));

        string memory zeroSaltString = vm.toString(zeroSalt);

        vm.setEnv("SEMI_MODULAR_ACCOUNT_STORAGE_ONLY_IMPL_SALT", zeroSaltString);

        // Spoof as though the profile is set to "optimized-build".
        vm.setEnv("FOUNDRY_PROFILE", "optimized-build-sma-storage");
    }

    function test_deploySmaStorageScript() public {
        _deploySmaStorageScript.setUp();

        _deploySmaStorageScript.run();

        assertEq(
            SemiModularAccountStorageOnly(payable(semiModularAccountStorageOnlyImpl)).accountId(),
            "alchemy.sma-storage.1.0.0"
        );
    }
}
