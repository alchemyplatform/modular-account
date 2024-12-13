// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

abstract contract ScriptBase is Script {
    modifier onlyProfile(string memory expectedProfile) {
        // Assert that the correct profile is being used.
        string memory actualProfile = vm.envOr(string("FOUNDRY_PROFILE"), string(""));

        if (keccak256(bytes(actualProfile)) != keccak256(bytes(expectedProfile))) {
            revert(string.concat("This script should be run with the `", expectedProfile, "` profile."));
        }
        _;
    }

    function _getEntryPoint() internal view returns (IEntryPoint) {
        IEntryPoint entryPoint = IEntryPoint(payable(vm.envOr("ENTRYPOINT", address(0))));
        if (address(entryPoint) == address(0)) {
            console.log(
                "Env Variable 'ENTRYPOINT' not found or invalid, defaulting to v0.7 EntryPoint at "
                "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
            );
            entryPoint = IEntryPoint(0x0000000071727De22E5E9d8BAf0edAc6f37da032);
        } else {
            console.log("Using user-defined EntryPoint at: %x", address(entryPoint));
        }

        return entryPoint;
    }

    function _getModularAccountImpl() internal view returns (address) {
        return vm.envOr("MODULAR_ACCOUNT_IMPL", address(0));
    }

    function _getSemiModularAccountBytecodeImpl() internal view returns (address) {
        return vm.envOr("SEMI_MODULAR_ACCOUNT_BYTECODE_IMPL", address(0));
    }

    function _getSemiModularAccountStorageOnlyImpl() internal view returns (address) {
        return vm.envOr("SEMI_MODULAR_ACCOUNT_STORAGE_ONLY_IMPL", address(0));
    }

    function _getSemiModularAccount7702Impl() internal view returns (address) {
        return vm.envOr("SEMI_MODULAR_ACCOUNT_7702_IMPL", address(0));
    }

    function _getExecutionInstallDelegate() internal view returns (address) {
        return vm.envOr("EXECUTION_INSTALL_DELEGATE", address(0));
    }

    function _getSingleSignerValidationModule() internal view returns (address) {
        return vm.envOr("SINGLE_SIGNER_VALIDATION_MODULE", address(0));
    }

    function _getWebAuthnValidationModule() internal view returns (address) {
        return vm.envOr("WEBAUTHN_VALIDATION_MODULE", address(0));
    }

    function _getFactoryOwner() internal view returns (address) {
        return vm.envOr("ACCOUNT_FACTORY_OWNER", address(0));
    }

    function _getSaltOrZero(string memory name) internal view returns (uint256) {
        return vm.envOr(string(bytes.concat(bytes(name), "_SALT")), uint256(0));
    }

    function _safeDeploy(
        string memory contractName,
        address expectedAddress,
        uint256 salt,
        bytes memory creationCode,
        function (bytes32) internal returns (address) deployFunction
    ) internal {
        console.log(string.concat("Deploying ", contractName, " with salt: ", vm.toString(salt)));

        address predicted = Create2.computeAddress(bytes32(salt), keccak256(creationCode), CREATE2_FACTORY);

        if (predicted != expectedAddress) {
            console.log("Expected address mismatch with predicted!");
            console.log("Expected: ", expectedAddress);
            console.log("Create2 predicted: ", predicted);
            revert();
        }

        if (predicted.code.length == 0) {
            console.log("No code found at expected address, deploying...");
            // Invoke type-safe deploy function
            address deployed = deployFunction(bytes32(salt));

            if (deployed == address(0)) {
                console.log("Deployment failed");
                revert();
            }

            if (address(deployed) != expectedAddress) {
                console.log("Deployed address mismatch with expected!");
                console.log("Expected: ", expectedAddress);
                console.log("Deployed: ", address(deployed));
                revert();
            }

            console.log(string.concat("Deployed ", contractName, " at: "), address(deployed));
        } else {
            console.log("Code found at expected address: ", predicted);
            console.log("Skipping deployment");
        }
    }
}
