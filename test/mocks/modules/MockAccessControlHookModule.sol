// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

import {BaseModule} from "../../../src/modules/BaseModule.sol";

// A pre validaiton hook module that uses per-hook data.
// This example enforces that the target of an `execute` call must only be the previously specified address.
// This is just a mock - it does not enforce this over `executeBatch` and other methods of making calls, and should
// not be used in production..
contract MockAccessControlHookModule is IValidationHookModule, BaseModule {
    mapping(uint32 entityId => mapping(address account => address allowedTarget)) public allowedTargets;

    function onInstall(bytes calldata data) external override {
        (uint32 entityId, address allowedTarget) = abi.decode(data, (uint32, address));
        allowedTargets[entityId][msg.sender] = allowedTarget;
    }

    function onUninstall(bytes calldata data) external override {
        uint32 entityId = abi.decode(data, (uint32));
        delete allowedTargets[entityId][msg.sender];
    }

    function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata userOp, bytes32)
        external
        view
        override
        returns (uint256)
    {
        if (bytes4(userOp.callData[:4]) == IModularAccount.execute.selector) {
            address target = abi.decode(userOp.callData[4:36], (address));

            // Simulate a merkle proof - require that the target address is also provided in the signature
            address proof = address(bytes20(userOp.signature));
            require(proof == target, "Proof doesn't match target");
            require(target == allowedTargets[entityId][msg.sender], "Target not allowed");
            return 0;
        }

        revert("Unsupported method");
    }

    function preRuntimeValidationHook(
        uint32 entityId,
        address,
        uint256,
        bytes calldata data,
        bytes calldata authorization
    ) external view override {
        if (bytes4(data[:4]) == IModularAccount.execute.selector) {
            address target = abi.decode(data[4:36], (address));

            // Simulate a merkle proof - require that the target address is also provided in the authorization
            // data
            address proof = address(bytes20(authorization));
            require(proof == target, "Proof doesn't match target");
            require(target == allowedTargets[entityId][msg.sender], "Target not allowed");

            return;
        }

        revert("Unsupported method");
    }

    function preSignatureValidationHook(uint32, address, bytes32 hash, bytes calldata signature)
        external
        pure
        override
    {
        // Simulates some signature checking by requiring a preimage of the hash.

        require(keccak256(signature) == hash, "Preimage not provided");

        return;
    }

    function moduleId() external pure returns (string memory) {
        return "erc6900.mock-access-control-hook-module.1.0.0";
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(BaseModule, IERC165)
        returns (bool)
    {
        return interfaceId == type(IValidationHookModule).interfaceId || super.supportsInterface(interfaceId);
    }
}
