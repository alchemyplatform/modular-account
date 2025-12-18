// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {DeployWebAuthnFactoryScript} from "../../script/DeployWebAuthnFactory.s.sol";
import {WebAuthnFactory} from "../../src/factory/WebAuthnFactory.sol";

import {OptimizedTest} from "../utils/OptimizedTest.sol";

contract DeployWebAuthnFactoryTest is OptimizedTest {
    DeployWebAuthnFactoryScript internal _deployFactoryScript;

    address public entryPoint;
    address public modularAccountImpl;
    address public webAuthnValidationModule;
    address public factoryOwner;

    WebAuthnFactory public factory;

    function setUp() public {
        _deployFactoryScript = new DeployWebAuthnFactoryScript();

        bytes32 zeroSalt = bytes32(0);

        entryPoint = address(_deployEntryPoint090());
        modularAccountImpl = makeAddr("Modular Account Impl");
        vm.etch(modularAccountImpl, "0x01");
        webAuthnValidationModule = makeAddr("Webauthn Validation Module");
        vm.etch(webAuthnValidationModule, "0x01");
        factoryOwner = makeAddr("Factory Owner");

        vm.setEnv("ENTRYPOINT", vm.toString(entryPoint));
        vm.setEnv("MODULAR_ACCOUNT_IMPL", vm.toString(modularAccountImpl));
        vm.setEnv("WEBAUTHN_VALIDATION_MODULE", vm.toString(webAuthnValidationModule));
        vm.setEnv("ACCOUNT_FACTORY_OWNER", vm.toString(factoryOwner));

        factory = WebAuthnFactory(
            Create2.computeAddress(
                zeroSalt,
                keccak256(
                    bytes.concat(
                        type(WebAuthnFactory).creationCode,
                        abi.encode(entryPoint, modularAccountImpl, webAuthnValidationModule, factoryOwner)
                    )
                ),
                CREATE2_FACTORY
            )
        );

        vm.setEnv("WEBAUTHN_ACCOUNT_FACTORY", vm.toString(address(factory)));

        string memory zeroSaltString = vm.toString(zeroSalt);

        vm.setEnv("WEBAUTHN_ACCOUNT_FACTORY_SALT", zeroSaltString);

        // Spoof as though the profile is set to "optimized-build-standalone".
        vm.setEnv("FOUNDRY_PROFILE", "optimized-build-standalone");
    }

    function test_deployWebAuthnFactoryScript() public {
        assertEq(address(factory).code.length, 0);

        _deployFactoryScript.setUp();

        _deployFactoryScript.run();

        assertGt(address(factory).code.length, 0);

        // Test an arbitrary function, ensuring the factory doesn't revert.
        factory.createWebAuthnAccount(0, 0, 0, 0);
    }
}
