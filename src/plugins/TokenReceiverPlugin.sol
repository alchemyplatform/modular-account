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

import {IERC1155Receiver} from "@openzeppelin/contracts/interfaces/IERC1155Receiver.sol";
import {IERC777Recipient} from "@openzeppelin/contracts/interfaces/IERC777Recipient.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    PluginMetadata
} from "../interfaces/IPlugin.sol";
import {BasePlugin} from "./BasePlugin.sol";

/// @title Token Receiver Plugin
/// @author Alchemy
/// @notice This plugin allows modular accounts to receive various types of tokens by implementing
/// required token receiver interfaces.
contract TokenReceiverPlugin is BasePlugin, IERC721Receiver, IERC777Recipient, IERC1155Receiver {
    string internal constant _NAME = "Token Receiver Plugin";
    string internal constant _VERSION = "1.0.0";
    string internal constant _AUTHOR = "Alchemy";

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata)
        external
        pure
        override
    // solhint-disable-next-line no-empty-blocks
    {}

    function onERC721Received(address, address, uint256, bytes calldata) external pure override returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    // solhint-disable-next-line no-empty-blocks
    function onInstall(bytes calldata) external pure override {}

    /// @inheritdoc BasePlugin
    // solhint-disable-next-line no-empty-blocks
    function onUninstall(bytes calldata) external pure override {}

    /// @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](4);
        manifest.executionFunctions[0] = this.tokensReceived.selector;
        manifest.executionFunctions[1] = this.onERC721Received.selector;
        manifest.executionFunctions[2] = this.onERC1155Received.selector;
        manifest.executionFunctions[3] = this.onERC1155BatchReceived.selector;

        // Only runtime validationFunction is needed since callbacks come from token contracts only
        ManifestFunction memory alwaysAllowFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
            functionId: 0, // Unused.
            dependencyIndex: 0 // Unused.
        });
        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](4);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.tokensReceived.selector,
            associatedFunction: alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.onERC721Received.selector,
            associatedFunction: alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: this.onERC1155Received.selector,
            associatedFunction: alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[3] = ManifestAssociatedFunction({
            executionSelector: this.onERC1155BatchReceived.selector,
            associatedFunction: alwaysAllowFunction
        });

        manifest.interfaceIds = new bytes4[](3);
        manifest.interfaceIds[0] = type(IERC721Receiver).interfaceId;
        manifest.interfaceIds[1] = type(IERC777Recipient).interfaceId;
        manifest.interfaceIds[2] = type(IERC1155Receiver).interfaceId;

        return manifest;
    }

    /// @inheritdoc BasePlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = _NAME;
        metadata.version = _VERSION;
        metadata.author = _AUTHOR;
        return metadata;
    }
}
