// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

import {ModuleBase} from "../../../src/modules/ModuleBase.sol";

contract MockCountModule is ModuleBase, IExecutionHookModule, IValidationHookModule {
    uint256 public preExecutionHookRunCount = 0;
    uint256 public postExecutionHookRunCount = 0;
    uint256 public runtimeValidationHookRunCount = 0;
    uint256 public userOpValidationHookRunCount = 0;
    uint256 public signatureValidationHookRunCount = 0;

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {
        preExecutionHookRunCount = 0;
        postExecutionHookRunCount = 0;
        runtimeValidationHookRunCount = 0;
        userOpValidationHookRunCount = 0;
        signatureValidationHookRunCount = 0;
    }

    function preRuntimeValidationHook(uint32, address, uint256, bytes calldata, bytes calldata) external {
        runtimeValidationHookRunCount++;
    }

    function preExecutionHook(uint32, address, uint256, bytes calldata) external override returns (bytes memory) {
        preExecutionHookRunCount++;
        return abi.encode(keccak256(hex"04546b"));
    }

    function postExecutionHook(uint32, bytes calldata preExecHookData) external override {
        require(
            abi.decode(preExecHookData, (bytes32)) == keccak256(hex"04546b"),
            "mockCountModule post execution hook failed"
        );
        postExecutionHookRunCount++;
    }

    function moduleId() external pure override returns (string memory) {
        return "erc6900.direct-call-module.1.0.0";
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ModuleBase, IERC165)
        returns (bool)
    {
        return interfaceId == type(IExecutionHookModule).interfaceId
            || interfaceId == type(IValidationHookModule).interfaceId || super.supportsInterface(interfaceId);
    }

    function preUserOpValidationHook(uint32, PackedUserOperation calldata, bytes32)
        external
        override
        returns (uint256)
    {
        userOpValidationHookRunCount++;
        return 0;
    }

    function preSignatureValidationHook(uint32, address, bytes32, bytes calldata) external view override {}
}
