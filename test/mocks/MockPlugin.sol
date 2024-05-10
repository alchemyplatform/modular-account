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

import {PluginManifest, PluginMetadata, IPlugin} from "modular-account-libs/interfaces/IPlugin.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

contract MockPlugin is ERC165 {
    // It's super inefficient to hold the entire abi-encoded manifest in storage, but this is fine since it's
    // just a mock. Note that the reason we do this is to allow copying the entire contents of the manifest
    // into storage in a single line, since solidity fails to compile with memory -> storage copying of nested
    // dynamic types when compiling without `via-ir` in the lite profile.
    // See the error code below:
    // Error: Unimplemented feature (/solidity/libsolidity/codegen/ArrayUtils.cpp:228):Copying of type
    // struct ManifestAssociatedFunction memory[] memory to storage not yet supported.
    bytes internal _manifest;

    string internal constant _NAME = "Mock Plugin Modifiable";
    string internal constant _VERSION = "1.0.0";
    string internal constant _AUTHOR = "Alchemy";

    event ReceivedCall(bytes msgData, uint256 msgValue);

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    constructor(PluginManifest memory _pluginManifest) {
        _manifest = abi.encode(_pluginManifest);
    }

    // solhint-disable-next-line no-empty-blocks
    function foo() public {}

    function _getManifest() internal view returns (PluginManifest memory) {
        PluginManifest memory m = abi.decode(_manifest, (PluginManifest));
        return m;
    }

    function _castToPure(function() internal view returns (PluginManifest memory) fnIn)
        internal
        pure
        returns (function() internal pure returns (PluginManifest memory) fnOut)
    {
        assembly {
            fnOut := fnIn
        }
    }

    function pluginManifest() external pure returns (PluginManifest memory) {
        return _castToPure(_getManifest)();
    }

    function pluginMetadata() external pure returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = _NAME;
        metadata.version = _VERSION;
        metadata.author = _AUTHOR;
        return metadata;
    }

    /// @dev Returns true if this contract implements the interface defined by
    /// `interfaceId`. See the corresponding
    /// https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
    /// to learn more about how these ids are created.
    ///
    /// This function call must use less than 30 000 gas.
    ///
    /// Supporting the IPlugin interface is a requirement for plugin installation. This is also used
    /// by the modular account to prevent standard execution functions `execute` and `executeBatch` from
    /// making calls to plugins.
    /// @param interfaceId The interface ID to check for support.
    /// @return True if the contract supports `interfaceId`.
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return (interfaceId != 0xffffffff);
    }

    /// @dev Hardcode the pre execution hook to return the functionId, which will be passed to the post execution
    /// hook.
    function preExecutionHook(uint8 functionId, address, uint256, bytes calldata)
        external
        returns (bytes memory)
    {
        emit ReceivedCall(msg.data, 0);
        return abi.encode(functionId);
    }

    receive() external payable {}

    // solhint-disable-next-line no-complex-fallback
    fallback() external payable {
        emit ReceivedCall(msg.data, msg.value);
        if (
            msg.sig == IPlugin.userOpValidationFunction.selector
                || msg.sig == IPlugin.runtimeValidationFunction.selector
                || msg.sig == IPlugin.preUserOpValidationHook.selector
        ) {
            // return 0 for userOpVal/runtimeVal/preUserOpValidationHook
            assembly {
                return(0x00, 0x20)
            }
        }
    }
}
