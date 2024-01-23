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

import {Test} from "forge-std/Test.sol";

import {BaseAccount} from "@eth-infinitism/account-abstraction/core/BaseAccount.sol";
import {IAggregator} from "@eth-infinitism/account-abstraction/interfaces/IAggregator.sol";
import {IPaymaster} from "@eth-infinitism/account-abstraction/interfaces/IPaymaster.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {KnownSelectors} from "../../src/helpers/KnownSelectors.sol";
import {IAccountInitializable} from "../../src/interfaces/IAccountInitializable.sol";
import {IAccountLoupe} from "../../src/interfaces/IAccountLoupe.sol";
import {IPlugin} from "../../src/interfaces/IPlugin.sol";
import {IPluginExecutor} from "../../src/interfaces/IPluginExecutor.sol";
import {IPluginManager} from "../../src/interfaces/IPluginManager.sol";
import {IStandardExecutor} from "../../src/interfaces/IStandardExecutor.sol";

contract KnownSelectorsTest is Test {
    function test_isNativeFunction() public {
        // account-abstraction BaseAccount methods
        assertTrue(KnownSelectors.isNativeFunction(BaseAccount.getNonce.selector));
        assertTrue(KnownSelectors.isNativeFunction(BaseAccount.entryPoint.selector));
        assertTrue(KnownSelectors.isNativeFunction(BaseAccount.validateUserOp.selector));

        // IPluginManager methods
        assertTrue(KnownSelectors.isNativeFunction(IPluginManager.installPlugin.selector));
        assertTrue(KnownSelectors.isNativeFunction(IPluginManager.uninstallPlugin.selector));

        // IERC165 methods
        assertTrue(KnownSelectors.isNativeFunction(IERC165.supportsInterface.selector));

        // UUPSUpgradeable methods
        assertTrue(KnownSelectors.isNativeFunction(UUPSUpgradeable.proxiableUUID.selector));
        assertTrue(KnownSelectors.isNativeFunction(UUPSUpgradeable.upgradeToAndCall.selector));

        // IStandardExecutor methods
        assertTrue(KnownSelectors.isNativeFunction(IStandardExecutor.execute.selector));
        assertTrue(KnownSelectors.isNativeFunction(IStandardExecutor.executeBatch.selector));

        // IPluginExecutor methods
        assertTrue(KnownSelectors.isNativeFunction(IPluginExecutor.executeFromPlugin.selector));
        assertTrue(KnownSelectors.isNativeFunction(IPluginExecutor.executeFromPluginExternal.selector));

        // IAccountInitializable methods
        assertTrue(KnownSelectors.isNativeFunction(IAccountInitializable.initialize.selector));

        // IAccountLoupe methods
        assertTrue(KnownSelectors.isNativeFunction(IAccountLoupe.getExecutionFunctionConfig.selector));
        assertTrue(KnownSelectors.isNativeFunction(IAccountLoupe.getExecutionHooks.selector));
        assertTrue(KnownSelectors.isNativeFunction(IAccountLoupe.getPreValidationHooks.selector));
        assertTrue(KnownSelectors.isNativeFunction(IAccountLoupe.getInstalledPlugins.selector));

        assertFalse(KnownSelectors.isNativeFunction(IPaymaster.validatePaymasterUserOp.selector));
    }

    function test_isErc4337Function() public {
        assertTrue(KnownSelectors.isErc4337Function(IAggregator.validateSignatures.selector));
        assertTrue(KnownSelectors.isErc4337Function(IAggregator.validateUserOpSignature.selector));
        assertTrue(KnownSelectors.isErc4337Function(IAggregator.aggregateSignatures.selector));
        assertTrue(KnownSelectors.isErc4337Function(IPaymaster.validatePaymasterUserOp.selector));
        assertTrue(KnownSelectors.isErc4337Function(IPaymaster.postOp.selector));

        assertFalse(KnownSelectors.isErc4337Function(BaseAccount.validateUserOp.selector));
    }

    function test_isIPluginFunction() public {
        assertTrue(KnownSelectors.isIPluginFunction(IPlugin.onInstall.selector));
        assertTrue(KnownSelectors.isIPluginFunction(IPlugin.onUninstall.selector));
        assertTrue(KnownSelectors.isIPluginFunction(IPlugin.preUserOpValidationHook.selector));
        assertTrue(KnownSelectors.isIPluginFunction(IPlugin.userOpValidationFunction.selector));
        assertTrue(KnownSelectors.isIPluginFunction(IPlugin.preRuntimeValidationHook.selector));
        assertTrue(KnownSelectors.isIPluginFunction(IPlugin.runtimeValidationFunction.selector));
        assertTrue(KnownSelectors.isIPluginFunction(IPlugin.preExecutionHook.selector));
        assertTrue(KnownSelectors.isIPluginFunction(IPlugin.postExecutionHook.selector));
        assertTrue(KnownSelectors.isIPluginFunction(IPlugin.pluginManifest.selector));
        assertTrue(KnownSelectors.isIPluginFunction(IPlugin.pluginMetadata.selector));

        assertFalse(KnownSelectors.isIPluginFunction(IPaymaster.postOp.selector));
    }
}
