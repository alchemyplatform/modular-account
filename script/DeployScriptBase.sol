// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {ScriptBase} from "forge-std/Base.sol";
import {console} from "forge-std/console.sol";

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

contract DeployScriptBase is ScriptBase {
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
