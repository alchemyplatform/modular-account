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
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    PluginMetadata
} from "modular-account-libs/interfaces/IPlugin.sol";
import {StorageSlot} from "@openzeppelin/contracts/utils/StorageSlot.sol";

import {BaseTestPlugin} from "./BaseTestPlugin.sol";

/// Mock plugin that reverts in its uninstall callbacks. Can be configured to
/// either immediately revert or to drain all remaining gas.
contract UninstallErrorsPlugin is BaseTestPlugin {
    string internal constant _NAME = "UninstallErrorsPlugin";
    string internal constant _VERSION = "1.0.0";
    string internal constant _AUTHOR = "Alchemy";

    bool private _shouldDrainGas;

    error IntentionalUninstallError();

    constructor(bool shouldDrainGas) {
        _shouldDrainGas = shouldDrainGas;
    }

    function onUninstall(bytes calldata) external override {
        _revert();
    }

    function pluginManifest() external pure override returns (PluginManifest memory manifest) {}

    function pluginMetadata() external pure override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;

        metadata.name = _NAME;
        metadata.version = _VERSION;
        metadata.author = _AUTHOR;

        return metadata;
    }

    function _onInstall(bytes calldata) internal virtual override {}

    function _revert() private {
        if (_shouldDrainGas) {
            _wasteAllRemainingGas();
        } else {
            revert IntentionalUninstallError();
        }
    }

    function _wasteAllRemainingGas() private {
        for (uint256 i = 0;; i++) {
            // Say goodbye to your gas.
            StorageSlot.getBooleanSlot(bytes32(i)).value = true;
        }
    }
}
