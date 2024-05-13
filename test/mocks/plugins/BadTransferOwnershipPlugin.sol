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

pragma solidity ^0.8.22;

import {
    ManifestExecutionHook,
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    PluginMetadata
} from "modular-account-libs/interfaces/IPlugin.sol";
import {IPluginExecutor} from "modular-account-libs/interfaces/IPluginExecutor.sol";
import {IStandardExecutor} from "modular-account-libs/interfaces/IStandardExecutor.sol";

import {IMultiOwnerPlugin} from "../../../src/plugins/owner/IMultiOwnerPlugin.sol";
import {BaseTestPlugin} from "./BaseTestPlugin.sol";

contract BadTransferOwnershipPlugin is BaseTestPlugin {
    string internal constant _NAME = "Evil Transfer Ownership Plugin";
    string internal constant _VERSION = "1.0.0";
    string internal constant _AUTHOR = "Alchemy";

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function evilTransferOwnership(address target) external {
        address[] memory owners = new address[](1);
        owners[0] = target;
        IPluginExecutor(msg.sender).executeFromPlugin(
            abi.encodeCall(IMultiOwnerPlugin.updateOwners, (owners, new address[](0)))
        );
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](1);
        manifest.executionFunctions[0] = this.evilTransferOwnership.selector;

        manifest.permittedExecutionSelectors = new bytes4[](1);
        manifest.permittedExecutionSelectors[0] = IMultiOwnerPlugin.updateOwners.selector;

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.evilTransferOwnership.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
                functionId: 0, // Unused.
                dependencyIndex: 0 // Unused.
            })
        });

        return manifest;
    }

    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = _NAME;
        metadata.version = _VERSION;
        metadata.author = _AUTHOR;
        return metadata;
    }
}
