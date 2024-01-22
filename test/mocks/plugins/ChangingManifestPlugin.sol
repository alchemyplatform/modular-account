// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    PluginMetadata
} from "../../../src/interfaces/IPlugin.sol";
import {BasePlugin} from "../../../src/plugins/BasePlugin.sol";

contract CanChangeManifestPluginFactory {
    function newPlugin() external returns (CanChangeManifestPlugin) {
        return
            CanChangeManifestPlugin(address(new ERC1967Proxy(address(new CanChangeManifestPlugin()), bytes(""))));
    }
}

contract CanChangeManifestPlugin is BasePlugin, UUPSUpgradeable {
    string internal constant _NAME = "CanChangeManifestPlugin";
    string internal constant _VERSION = "1.0.0";
    string internal constant _AUTHOR = "Alchemy";

    function someExecutionFunction() external {}

    function changeManifest() external {
        _upgradeTo(address(new DidChangeManifestPlugin()));
    }

    function onInstall(bytes calldata) external override {}

    function pluginManifest() external pure override returns (PluginManifest memory manifest) {
        manifest.executionFunctions = new bytes4[](1);
        manifest.executionFunctions[0] = this.someExecutionFunction.selector;

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.someExecutionFunction.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
                functionId: 0, // Unused.
                dependencyIndex: 0 // Unused.
            })
        });
    }

    /// @inheritdoc BasePlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = _NAME;
        metadata.version = _VERSION;
        metadata.author = _AUTHOR;
        return metadata;
    }

    function _authorizeUpgrade(address) internal virtual override {}
}

contract DidChangeManifestPlugin is BasePlugin {
    string internal constant _NAME = "DidChangeManifestPlugin";
    string internal constant _VERSION = "1.0.0";
    string internal constant _AUTHOR = "Alchemy";

    function someExecutionFunction() external {}

    function onUninstall(bytes calldata) external override {}

    function pluginManifest() external pure override returns (PluginManifest memory manifest) {}

    /// @inheritdoc BasePlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = _NAME;
        metadata.version = _VERSION;
        metadata.author = _AUTHOR;
        return metadata;
    }
}
