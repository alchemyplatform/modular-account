// This file is part of Modular Account.
//
// Copyright 2024 Alchemy Insights, Inc.
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General
// Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.26;

import {
    ExecutionManifest,
    IExecutionModule,
    ManifestExecutionFunction
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";

import {ModuleBase} from "../../../src/modules/ModuleBase.sol";
import {ResultCreatorModule} from "./ReturnDataModuleMocks.sol";

contract PermittedCallerModule is IExecutionModule, ModuleBase {
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
