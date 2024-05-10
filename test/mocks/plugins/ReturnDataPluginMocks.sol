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
    ManifestExternalCallPermission,
    PluginManifest
} from "modular-account-libs/interfaces/IPlugin.sol";
import {IPlugin} from "modular-account-libs/interfaces/IPlugin.sol";
import {IPluginExecutor} from "modular-account-libs/interfaces/IPluginExecutor.sol";
import {FunctionReference} from "modular-account-libs/interfaces/IPluginManager.sol";
import {IStandardExecutor} from "modular-account-libs/interfaces/IStandardExecutor.sol";

import {BaseTestPlugin} from "./BaseTestPlugin.sol";

contract RegularResultContract {
    function foo() external pure returns (bytes32) {
        return keccak256("bar");
    }

    function bar() external pure returns (bytes32) {
        return keccak256("foo");
    }
}

contract ResultCreatorPlugin is BaseTestPlugin {
    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function foo() external pure returns (bytes32) {
        return keccak256("bar");
    }

    function bar() external pure returns (bytes32) {
        return keccak256("foo");
    }

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](2);
        manifest.executionFunctions[0] = this.foo.selector;
        manifest.executionFunctions[1] = this.bar.selector;

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        return manifest;
    }
}

contract ResultConsumerPlugin is BaseTestPlugin {
    ResultCreatorPlugin public immutable resultCreator;
    RegularResultContract public immutable regularResultContract;

    constructor(ResultCreatorPlugin _resultCreator, RegularResultContract _regularResultContract) {
        resultCreator = _resultCreator;
        regularResultContract = _regularResultContract;
    }

    // Check the return data through the executeFromPlugin fallback case
    function checkResultEFPFallback(bytes32 expected) external returns (bool) {
        // This result should be allowed based on the manifest permission request
        IPluginExecutor(msg.sender).executeFromPlugin(abi.encodeCall(ResultCreatorPlugin.foo, ()));

        bytes32 actual = ResultCreatorPlugin(msg.sender).foo();

        return actual == expected;
    }

    // Check the rturn data through the executeFromPlugin std exec case
    function checkResultEFPExternal(address target, bytes32 expected) external returns (bool) {
        // This result should be allowed based on the manifest permission request
        bytes memory returnData = IPluginExecutor(msg.sender).executeFromPluginExternal(
            target, 0, abi.encodeCall(RegularResultContract.foo, ())
        );

        bytes32 actual = abi.decode(returnData, (bytes32));

        return actual == expected;
    }

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function pluginManifest() external pure override returns (PluginManifest memory) {
        // We want to return the address of the immutable RegularResultContract in the permitted external calls
        // area of the manifest.
        // However, reading from immutable values is not permitted in pure functions. So we use this hack to get
        // around that.
        // In regular, non-mock plugins, external call targets in the plugin manifest should be constants, not just
        // immutbales.
        // But to make testing easier, we do this.

        function() internal pure returns (PluginManifest memory) pureManifestGetter;

        function() internal view returns (PluginManifest memory) viewManifestGetter = _innerPluginManifest;

        assembly ("memory-safe") {
            pureManifestGetter := viewManifestGetter
        }

        return pureManifestGetter();
    }

    function _innerPluginManifest() internal view returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](2);
        manifest.executionFunctions[0] = this.checkResultEFPFallback.selector;
        manifest.executionFunctions[1] = this.checkResultEFPExternal.selector;

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](2);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.checkResultEFPFallback.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
                functionId: 0,
                dependencyIndex: 0
            })
        });
        manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.checkResultEFPExternal.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        manifest.permittedExecutionSelectors = new bytes4[](1);
        manifest.permittedExecutionSelectors[0] = ResultCreatorPlugin.foo.selector;

        manifest.permittedExternalCalls = new ManifestExternalCallPermission[](1);

        bytes4[] memory allowedSelectors = new bytes4[](1);
        allowedSelectors[0] = RegularResultContract.foo.selector;
        manifest.permittedExternalCalls[0] = ManifestExternalCallPermission({
            externalAddress: address(regularResultContract),
            permitAnySelector: false,
            selectors: allowedSelectors
        });

        return manifest;
    }
}
