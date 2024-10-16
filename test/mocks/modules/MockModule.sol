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

pragma solidity ^0.8.26;

import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";

contract MockModule is ERC165 {
    // It's super inefficient to hold the entire abi-encoded manifest in storage, but this is fine since it's
    // just a mock. Note that the reason we do this is to allow copying the entire contents of the manifest
    // into storage in a single line, since solidity fails to compile with memory -> storage copying of nested
    // dynamic types when compiling without `via-ir` in the lite profile.
    // See the error code below:
    // Error: Unimplemented feature (/solidity/libsolidity/codegen/ArrayUtils.cpp:228):Copying of type
    // struct ManifestAssociatedFunction memory[] memory to storage not yet supported.
    bytes internal _manifest;

    event ReceivedCall(bytes msgData, uint256 msgValue);

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Module interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    constructor(ExecutionManifest memory _executionManifest) {
        _manifest = abi.encode(_executionManifest);
    }

    function _getManifest() internal view returns (ExecutionManifest memory) {
        ExecutionManifest memory m = abi.decode(_manifest, (ExecutionManifest));
        return m;
    }

    function _castToPure(function() internal view returns (ExecutionManifest memory) fnIn)
        internal
        pure
        returns (function() internal pure returns (ExecutionManifest memory) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    function executionManifest() external pure returns (ExecutionManifest memory) {
        return _castToPure(_getManifest)();
    }

    function moduleId() external pure returns (string memory) {
        return "erc6900.mock-module.1.0.0";
    }

    /// @dev Returns true if this contract implements the interface defined by
    /// `interfaceId`. See the corresponding
    /// https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
    /// to learn more about how these ids are created.
    ///
    /// This function call must use less than 30 000 gas.
    ///
    /// Supporting the IModule interface is a requirement for module installation. This is also used
    /// by the modular account to prevent standard execution functions `execute` and `executeBatch` from
    /// making calls to modules.
    /// @param interfaceId The interface ID to check for support.
    /// @return True if the contract supports `interfaceId`.

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IModule).interfaceId || super.supportsInterface(interfaceId);
    }

    receive() external payable {}

    // solhint-disable-next-line no-complex-fallback
    fallback() external payable {
        emit ReceivedCall(msg.data, msg.value);
        if (
            msg.sig == IValidationModule.validateUserOp.selector
                || msg.sig == IValidationHookModule.preUserOpValidationHook.selector
                || msg.sig == IValidationModule.validateRuntime.selector
        ) {
            // return 0 for userOp/runtimeVal case, return bytes("") for preExecutionHook case
            assembly ("memory-safe") {
                mstore(0, 0)
                return(0x00, 0x20)
            }
        }

        if (msg.sig == IExecutionHookModule.preExecutionHook.selector) {
            // return bytes("") for preExecutionHook case
            assembly ("memory-safe") {
                mstore(0, 0x20)
                mstore(0x20, 0)
                return(0x00, 0x40)
            }
        }
    }
}
