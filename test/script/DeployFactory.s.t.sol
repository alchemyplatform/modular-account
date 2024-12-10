// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";

import {DeployFactoryScript} from "../../script/DeployFactory.s.sol";
import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {SemiModularAccountBytecode} from "../../src/account/SemiModularAccountBytecode.sol";
import {AccountFactory} from "../../src/factory/AccountFactory.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

contract DeployFactoryTest is Test {
    DeployFactoryScript internal _deployFactoryScript;

    IEntryPoint public entryPoint;
    ModularAccount public modularAccountImpl;
    SemiModularAccountBytecode public semiModularAccountBytecodeImpl;
    address public singleSignerValidationModule;
    address public webAuthnValidationModule;
    address public factoryOwner;

    AccountFactory public factory;

    function setUp() public {
        _deployFactoryScript = new DeployFactoryScript();

        bytes32 zeroSalt = bytes32(0);

        entryPoint = IEntryPoint(address(6));
        modularAccountImpl = ModularAccount(payable(address(1)));
        semiModularAccountBytecodeImpl = SemiModularAccountBytecode(payable(address(2)));
        singleSignerValidationModule = address(3);
        webAuthnValidationModule = address(4);
        factoryOwner = address(5);

        vm.setEnv("ENTRYPOINT", vm.toString(address(entryPoint)));
        vm.setEnv("MODULAR_ACCOUNT_IMPL", vm.toString(address(modularAccountImpl)));
        vm.setEnv("SEMI_MODULAR_ACCOUNT_BYTECODE_IMPL", vm.toString(address(semiModularAccountBytecodeImpl)));
        vm.setEnv("SINGLE_SIGNER_VALIDATION_MODULE", vm.toString(singleSignerValidationModule));
        vm.setEnv("WEBAUTHN_VALIDATION_MODULE", vm.toString(address(webAuthnValidationModule)));
        vm.setEnv("FACTORY_OWNER", vm.toString(address(factoryOwner)));

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

        vm.setEnv("FACTORY", vm.toString(address(factory)));

        string memory zeroSaltString = vm.toString(zeroSalt);

        vm.setEnv("FACTORY_SALT", zeroSaltString);

        // Spoof as though the profile is set to "optimized-build".
        vm.setEnv("FOUNDRY_PROFILE", "optimized-build");
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
