// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {
    ExecutionManifest,
    IExecutionModule,
    ManifestExecutionFunction
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";

import {BaseModule} from "../../../src/modules/BaseModule.sol";
import {ResultCreatorModule} from "./ReturnDataModuleMocks.sol";

contract PermittedCallerModule is IExecutionModule, BaseModule {
    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function executionManifest() external pure override returns (ExecutionManifest memory) {
        ExecutionManifest memory manifest;

        manifest.executionFunctions = new ManifestExecutionFunction[](2);
        manifest.executionFunctions[0].executionSelector = this.usePermittedCallAllowed.selector;
        manifest.executionFunctions[1].executionSelector = this.usePermittedCallNotAllowed.selector;

        for (uint256 i = 0; i < manifest.executionFunctions.length; i++) {
            manifest.executionFunctions[i].skipRuntimeValidation = true;
        }

        return manifest;
    }

    function moduleId() external pure returns (string memory) {
        return "erc6900.permitted-caller-module.1.0.0";
    }

    // The manifest requested access to use the module-defined method "foo"
    function usePermittedCallAllowed() external view returns (bytes memory) {
        return abi.encode(ResultCreatorModule(msg.sender).foo());
    }

    // The manifest has not requested access to use the module-defined method "bar", so this should revert.
    function usePermittedCallNotAllowed() external view returns (bytes memory) {
        return abi.encode(ResultCreatorModule(msg.sender).bar());
    }
}
