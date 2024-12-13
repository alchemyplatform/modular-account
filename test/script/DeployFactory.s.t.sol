// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {DeployFactoryScript} from "../../script/DeployFactory.s.sol";
import {AccountFactory} from "../../src/factory/AccountFactory.sol";

contract DeployFactoryTest is Test {
    DeployFactoryScript internal _deployFactoryScript;

    address public entryPoint;
    address public modularAccountImpl;
    address public semiModularAccountBytecodeImpl;
    address public singleSignerValidationModule;
    address public webAuthnValidationModule;
    address public factoryOwner;

    AccountFactory public factory;

    function setUp() public {
        _deployFactoryScript = new DeployFactoryScript();

        bytes32 zeroSalt = bytes32(0);

        entryPoint = makeAddr("Entrypoint");
        modularAccountImpl = makeAddr("Modular Account Impl");
        semiModularAccountBytecodeImpl = makeAddr("Semi Modular Account Bytecode Impl");
        singleSignerValidationModule = makeAddr("Single Signer Validation Module");
        webAuthnValidationModule = makeAddr("Webauthn Validation Module");
        factoryOwner = makeAddr("Factory Owner");

        vm.setEnv("ENTRYPOINT", vm.toString(entryPoint));
        vm.setEnv("MODULAR_ACCOUNT_IMPL", vm.toString(modularAccountImpl));
        vm.setEnv("SEMI_MODULAR_ACCOUNT_BYTECODE_IMPL", vm.toString(semiModularAccountBytecodeImpl));
        vm.setEnv("SINGLE_SIGNER_VALIDATION_MODULE", vm.toString(singleSignerValidationModule));
        vm.setEnv("WEBAUTHN_VALIDATION_MODULE", vm.toString(webAuthnValidationModule));
        vm.setEnv("ACCOUNT_FACTORY_OWNER", vm.toString(factoryOwner));

        factory = AccountFactory(
            Create2.computeAddress(
                zeroSalt,
                keccak256(
                    bytes.concat(
                        type(AccountFactory).creationCode,
                        abi.encode(
                            entryPoint,
                            modularAccountImpl,
                            semiModularAccountBytecodeImpl,
                            singleSignerValidationModule,
                            webAuthnValidationModule,
                            factoryOwner
                        )
                    )
                ),
                CREATE2_FACTORY
            )
        );

        vm.setEnv("ACCOUNT_FACTORY", vm.toString(address(factory)));

        string memory zeroSaltString = vm.toString(zeroSalt);

        vm.setEnv("ACCOUNT_FACTORY_SALT", zeroSaltString);

        // Spoof as though the profile is set to "optimized-build-standalone".
        vm.setEnv("FOUNDRY_PROFILE", "optimized-build-standalone");
    }

    function test_deployFactoryScript() public {
        assertEq(address(factory).code.length, 0);

        _deployFactoryScript.setUp();

        _deployFactoryScript.run();

        assertGt(address(factory).code.length, 0);

        // Test an arbitrary function, ensuring the factory doesn't revert.
        factory.createSemiModularAccount(address(this), 1);
    }
}
