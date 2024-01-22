// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {StorageSlot} from "@openzeppelin/contracts/utils/StorageSlot.sol";

import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    PluginMetadata
} from "../../../src/interfaces/IPlugin.sol";
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
