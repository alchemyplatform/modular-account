// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {
    ExecutionManifest,
    ManifestExecutionFunction
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {
    ExecutionManifest, IExecutionModule
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";

import {BaseModule} from "../../../src/modules/BaseModule.sol";

contract MockExecutionInstallationModule is BaseModule, IExecutionModule {
    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function executionInstallationExecute() external pure returns (bool) {
        return true;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Module interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IModule
    // solhint-disable-next-line no-empty-blocks
    function onInstall(bytes calldata) external pure override {}

    /// @inheritdoc IModule
    // solhint-disable-next-line no-empty-blocks
    function onUninstall(bytes calldata) external pure override {}

    /// @inheritdoc IExecutionModule
    function executionManifest() external pure override returns (ExecutionManifest memory) {
        ExecutionManifest memory manifest;

        manifest.executionFunctions = new ManifestExecutionFunction[](1);
        manifest.executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: this.executionInstallationExecute.selector,
            skipRuntimeValidation: true,
            allowGlobalValidation: false
        });

        return manifest;
    }

    /// @inheritdoc IModule
    function moduleId() external pure returns (string memory) {
        return "erc6900.mock-execution-module.1.0.0";
    }
}
