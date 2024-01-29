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

import {UUPSUpgradeable} from "../../ext/UUPSUpgradeable.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/interfaces/IERC1155Receiver.sol";
import {IERC777Recipient} from "@openzeppelin/contracts/interfaces/IERC777Recipient.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IAccount} from "../../src/interfaces/erc4337/IAccount.sol";
import {IAggregator} from "../../src/interfaces/erc4337/IAggregator.sol";
import {IPaymaster} from "../../src/interfaces/erc4337/IPaymaster.sol";
import {IAccountLoupe} from "../../src/interfaces/IAccountLoupe.sol";
import {IAccountView} from "../../src/interfaces/IAccountView.sol";
import {IPluginManager} from "../../src/interfaces/IPluginManager.sol";
import {IAccountInitializable} from "../interfaces/IAccountInitializable.sol";
import {IPlugin} from "../interfaces/IPlugin.sol";
import {IPluginExecutor} from "../interfaces/IPluginExecutor.sol";
import {IStandardExecutor} from "../interfaces/IStandardExecutor.sol";

/// @title Known Selectors
/// @author Alchemy
/// @notice Library to help to check if a selector is a know function selector of the modular account or ERC-4337
/// contract.
library KnownSelectors {
    function isNativeFunction(bytes4 selector) internal pure returns (bool) {
        return
        // check against IAccount methods
        selector == IAccount.validateUserOp.selector
        // check against IAccountView methods
        || selector == IAccountView.entryPoint.selector || selector == IAccountView.getNonce.selector
        // check against IPluginManager methods
        || selector == IPluginManager.installPlugin.selector || selector == IPluginManager.uninstallPlugin.selector
        // check against IERC165 methods
        || selector == IERC165.supportsInterface.selector
        // check against UUPSUpgradeable methods
        || selector == UUPSUpgradeable.proxiableUUID.selector
            || selector == UUPSUpgradeable.upgradeToAndCall.selector
        // check against IStandardExecutor methods
        || selector == IStandardExecutor.execute.selector || selector == IStandardExecutor.executeBatch.selector
        // check against IPluginExecutor methods
        || selector == IPluginExecutor.executeFromPlugin.selector
            || selector == IPluginExecutor.executeFromPluginExternal.selector
        // check against IAccountInitializable methods
        || selector == IAccountInitializable.initialize.selector
        // check against IAccountLoupe methods
        || selector == IAccountLoupe.getExecutionFunctionConfig.selector
            || selector == IAccountLoupe.getExecutionHooks.selector
            || selector == IAccountLoupe.getPreValidationHooks.selector
            || selector == IAccountLoupe.getInstalledPlugins.selector
        // check against token receiver methods
        || selector == IERC777Recipient.tokensReceived.selector
            || selector == IERC721Receiver.onERC721Received.selector
            || selector == IERC1155Receiver.onERC1155Received.selector
            || selector == IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    function isErc4337Function(bytes4 selector) internal pure returns (bool) {
        return selector == IAggregator.validateSignatures.selector
            || selector == IAggregator.validateUserOpSignature.selector
            || selector == IAggregator.aggregateSignatures.selector
            || selector == IPaymaster.validatePaymasterUserOp.selector || selector == IPaymaster.postOp.selector;
    }

    function isIPluginFunction(bytes4 selector) internal pure returns (bool) {
        return selector == IPlugin.onInstall.selector || selector == IPlugin.onUninstall.selector
            || selector == IPlugin.preUserOpValidationHook.selector
            || selector == IPlugin.userOpValidationFunction.selector
            || selector == IPlugin.preRuntimeValidationHook.selector
            || selector == IPlugin.runtimeValidationFunction.selector || selector == IPlugin.preExecutionHook.selector
            || selector == IPlugin.postExecutionHook.selector || selector == IPlugin.pluginManifest.selector
            || selector == IPlugin.pluginMetadata.selector;
    }
}
