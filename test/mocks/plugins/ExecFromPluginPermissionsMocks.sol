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
    ManifestExecutionHook,
    PluginManifest
} from "modular-account-libs/interfaces/IPlugin.sol";
import {IPlugin} from "modular-account-libs/interfaces/IPlugin.sol";
import {IPluginExecutor} from "modular-account-libs/interfaces/IPluginExecutor.sol";
import {FunctionReference} from "modular-account-libs/interfaces/IPluginManager.sol";
import {IStandardExecutor} from "modular-account-libs/interfaces/IStandardExecutor.sol";

import {Counter} from "../Counter.sol";
import {BaseTestPlugin} from "./BaseTestPlugin.sol";
import {ResultCreatorPlugin} from "./ReturnDataPluginMocks.sol";

// Hardcode the counter addresses from ExecuteFromPluginPermissionsTest to be able to have a pure plugin manifest
// easily
address constant counter1 = 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f;
address constant counter2 = 0x2e234DAe75C793f67A35089C9d99245E1C58470b;
address constant counter3 = 0xF62849F9A0B5Bf2913b396098F7c7019b51A820a;

contract EFPCallerPlugin is BaseTestPlugin {
    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](12);
        manifest.executionFunctions[0] = this.useEFPPermissionAllowed.selector;
        manifest.executionFunctions[1] = this.useEFPPermissionNotAllowed.selector;
        manifest.executionFunctions[2] = this.passthroughExecuteFromPlugin.selector;
        manifest.executionFunctions[3] = this.setNumberCounter1.selector;
        manifest.executionFunctions[4] = this.getNumberCounter1.selector;
        manifest.executionFunctions[5] = this.incrementCounter1.selector;
        manifest.executionFunctions[6] = this.setNumberCounter2.selector;
        manifest.executionFunctions[7] = this.getNumberCounter2.selector;
        manifest.executionFunctions[8] = this.incrementCounter2.selector;
        manifest.executionFunctions[9] = this.setNumberCounter3.selector;
        manifest.executionFunctions[10] = this.getNumberCounter3.selector;
        manifest.executionFunctions[11] = this.incrementCounter3.selector;

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](12);

        ManifestFunction memory alwaysAllowValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
            functionId: 0,
            dependencyIndex: 0
        });

        for (uint256 i = 0; i < manifest.executionFunctions.length; i++) {
            manifest.runtimeValidationFunctions[i] = ManifestAssociatedFunction({
                executionSelector: manifest.executionFunctions[i],
                associatedFunction: alwaysAllowValidationFunction
            });
        }

        // Request permission for "foo" and the non-existent selector "baz", but not "bar", from
        // ResultCreatorPlugin
        manifest.permittedExecutionSelectors = new bytes4[](2);
        manifest.permittedExecutionSelectors[0] = ResultCreatorPlugin.foo.selector;
        manifest.permittedExecutionSelectors[1] = bytes4(keccak256("baz()"));

        // Request permission for:
        // - `setNumber` and `number` on counter 1
        // - All selectors on counter 2
        // - None on counter 3
        manifest.permittedExternalCalls = new ManifestExternalCallPermission[](2);

        bytes4[] memory selectorsCounter1 = new bytes4[](2);
        selectorsCounter1[0] = Counter.setNumber.selector;
        selectorsCounter1[1] = bytes4(keccak256("number()")); // Public vars don't automatically get exported
            // selectors

        manifest.permittedExternalCalls[0] = ManifestExternalCallPermission({
            externalAddress: counter1,
            permitAnySelector: false,
            selectors: selectorsCounter1
        });

        manifest.permittedExternalCalls[1] = ManifestExternalCallPermission({
            externalAddress: counter2,
            permitAnySelector: true,
            selectors: new bytes4[](0)
        });

        return manifest;
    }

    // The manifest requested access to use the plugin-defined method "foo"
    function useEFPPermissionAllowed() external returns (bytes memory) {
        return IPluginExecutor(msg.sender).executeFromPlugin(abi.encodeCall(ResultCreatorPlugin.foo, ()));
    }

    // The manifest has not requested access to use the plugin-defined method "bar", so this should revert.
    function useEFPPermissionNotAllowed() external returns (bytes memory) {
        return IPluginExecutor(msg.sender).executeFromPlugin(abi.encodeCall(ResultCreatorPlugin.bar, ()));
    }

    function passthroughExecuteFromPlugin(bytes calldata data) external returns (bytes memory) {
        return IPluginExecutor(msg.sender).executeFromPlugin(data);
    }

    // Should be allowed
    function setNumberCounter1(uint256 number) external {
        IPluginExecutor(msg.sender).executeFromPluginExternal(
            counter1, 0, abi.encodeWithSelector(Counter.setNumber.selector, number)
        );
    }

    // Should be allowed
    function getNumberCounter1() external returns (uint256) {
        bytes memory returnData = IPluginExecutor(msg.sender).executeFromPluginExternal(
            counter1, 0, abi.encodePacked(bytes4(keccak256("number()")))
        );

        return abi.decode(returnData, (uint256));
    }

    // Should not be allowed
    function incrementCounter1() external {
        IPluginExecutor(msg.sender).executeFromPluginExternal(
            counter1, 0, abi.encodeWithSelector(Counter.increment.selector)
        );
    }

    // Should be allowed
    function setNumberCounter2(uint256 number) external {
        IPluginExecutor(msg.sender).executeFromPluginExternal(
            counter2, 0, abi.encodeWithSelector(Counter.setNumber.selector, number)
        );
    }

    // Should be allowed
    function getNumberCounter2() external returns (uint256) {
        bytes memory returnData = IPluginExecutor(msg.sender).executeFromPluginExternal(
            counter2, 0, abi.encodePacked(bytes4(keccak256("number()")))
        );

        return abi.decode(returnData, (uint256));
    }

    // Should be allowed
    function incrementCounter2() external {
        IPluginExecutor(msg.sender).executeFromPluginExternal(
            counter2, 0, abi.encodeWithSelector(Counter.increment.selector)
        );
    }

    // Should not be allowed
    function setNumberCounter3(uint256 number) external {
        IPluginExecutor(msg.sender).executeFromPluginExternal(
            counter3, 0, abi.encodeWithSelector(Counter.setNumber.selector, number)
        );
    }

    // Should not be allowed
    function getNumberCounter3() external returns (uint256) {
        bytes memory returnData = IPluginExecutor(msg.sender).executeFromPluginExternal(
            counter3, 0, abi.encodePacked(bytes4(keccak256("number()")))
        );

        return abi.decode(returnData, (uint256));
    }

    // Should not be allowed
    function incrementCounter3() external {
        IPluginExecutor(msg.sender).executeFromPluginExternal(
            counter3, 0, abi.encodeWithSelector(Counter.increment.selector)
        );
    }
}

contract EFPCallerPluginAnyExternal is BaseTestPlugin {
    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](2);
        manifest.executionFunctions[0] = this.passthroughExecute.selector;
        manifest.executionFunctions[1] = this.passthroughExecuteWith1Eth.selector;

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](2);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.passthroughExecute.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
                functionId: 0,
                dependencyIndex: 0
            })
        });
        manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.passthroughExecuteWith1Eth.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        manifest.permitAnyExternalAddress = true;

        return manifest;
    }

    function passthroughExecute(address target, uint256 value, bytes calldata data)
        external
        payable
        returns (bytes memory)
    {
        return IPluginExecutor(msg.sender).executeFromPluginExternal(target, value, data);
    }

    function passthroughExecuteWith1Eth(address target, uint256 value, bytes calldata data)
        external
        payable
        returns (bytes memory)
    {
        return IPluginExecutor(msg.sender).executeFromPluginExternal{value: 1 ether}(target, value, data);
    }
}

contract EFPCallerPluginAnyExternalCanSpendNativeToken is BaseTestPlugin {
    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](1);
        manifest.executionFunctions[0] = this.passthroughExecuteWithNativeTokenSpendPermission.selector;

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.passthroughExecuteWithNativeTokenSpendPermission.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        manifest.canSpendNativeToken = true;
        manifest.permitAnyExternalAddress = true;

        return manifest;
    }

    function passthroughExecuteWithNativeTokenSpendPermission(address target, uint256 value, bytes calldata data)
        external
        payable
        returns (bytes memory)
    {
        return IPluginExecutor(msg.sender).executeFromPluginExternal(target, value, data);
    }
}

// Create pre and post execution hooks for calling ResultCreatorPlugin.foo, and add a function that calls it via
// `executeFromPlugin`
contract EFPExecutionHookPlugin is BaseTestPlugin {
    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function preExecutionHook(uint8 functionId, address, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes memory)
    {
        return abi.encode(functionId);
    }

    function postExecutionHook(uint8, bytes calldata) external pure override {
        return;
    }

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](1);
        manifest.executionFunctions[0] = this.performEFPCallWithExecHooks.selector;

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.performEFPCallWithExecHooks.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        manifest.executionHooks = new ManifestExecutionHook[](2);
        // Pre and post hook
        manifest.executionHooks[0] = ManifestExecutionHook({
            executionSelector: ResultCreatorPlugin.foo.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 1,
                dependencyIndex: 0
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 2,
                dependencyIndex: 0
            })
        });
        // Post only hook
        manifest.executionHooks[1] = ManifestExecutionHook({
            executionSelector: ResultCreatorPlugin.foo.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.NONE,
                functionId: 0,
                dependencyIndex: 0
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 2,
                dependencyIndex: 0
            })
        });

        manifest.permittedExecutionSelectors = new bytes4[](1);
        manifest.permittedExecutionSelectors[0] = ResultCreatorPlugin.foo.selector;

        return manifest;
    }

    function performEFPCallWithExecHooks() external returns (bytes memory) {
        return IPluginExecutor(msg.sender).executeFromPlugin(abi.encodeCall(ResultCreatorPlugin.foo, ()));
    }
}
