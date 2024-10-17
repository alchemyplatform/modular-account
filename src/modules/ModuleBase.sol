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

import {IAccountExecute} from "@eth-infinitism/account-abstraction/interfaces/IAccountExecute.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {ERC165, IERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";

/// @title Module Base
/// @author Alchemy
/// @dev Implements ERC-165 to support IModule's interface, which is a requirement for module installation.
abstract contract ModuleBase is ERC165, IModule {
    error NotImplemented();
    error UnexpectedDataPassed();

    modifier assertNoData(bytes calldata data) {
        if (data.length > 0) {
            revert UnexpectedDataPassed();
        }
        _;
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
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IModule).interfaceId || super.supportsInterface(interfaceId);
    }

    /// @dev help method that returns extracted selector and calldata. If selector is executeUserOp, return the
    /// selector and calldata of the inner call.
    function _getSelectorAndCalldata(bytes calldata data) internal pure returns (bytes4, bytes memory) {
        bytes4 selector = bytes4(data[:4]);
        if (selector == IAccountExecute.executeUserOp.selector) {
            (PackedUserOperation memory uo,) = abi.decode(data[4:], (PackedUserOperation, bytes32));
            bytes memory finalCalldata = uo.callData;
            // Bytes arr representation: [bytes32(len), bytes4(executeUserOp.selector), bytes4(actualSelector),
            // bytes(actualCallData)]
            assembly ("memory-safe") {
                // Copy actualSelector into a new var
                selector := shl(224, mload(add(finalCalldata, 8)))

                let len := mload(finalCalldata)

                // Move the finalCalldata pointer by 8
                finalCalldata := add(finalCalldata, 8)

                // Shorten bytes arry by 8 by: store length - 8 into the new pointer location
                mstore(finalCalldata, sub(len, 8))
            }
            return (selector, finalCalldata);
        }
        return (selector, data[4:]);
    }
}
