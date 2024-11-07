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

import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {IERC165, ModuleBase} from "../ModuleBase.sol";

/// @title Paymaster Guard Module
/// @author Alchemy
/// @notice This module supports permission checks where an validation is allowed only if a certain paymaster is
/// used.
/// - If this hook is installed, and no paymaster is setup, all requests will revert.
/// - None of the functions are installed on the account. Account states are to be retrieved from this global
///   singleton directly.
/// - Uninstallation will NOT disable all installed hooks for an account. It only uninstalls hooks for the
///   entity ID that is passed in. Account must remove access for each entity ID if want to disable all hooks.
contract PaymasterGuardModule is ModuleBase, IValidationHookModule {
    mapping(uint32 entityId => mapping(address account => address paymaster)) public paymasters;

    error BadPaymasterSpecified();
    error InvalidPaymaster();

    /// @inheritdoc IModule
    /// @param data should be encoded with the entityId of the validation and the paymaster address that guards the
    /// validation
    function onInstall(bytes calldata data) external override {
        (uint32 entityId, address paymaster) = abi.decode(data, (uint32, address));
        if (paymaster == address(0)) {
            revert InvalidPaymaster();
        }
        paymasters[entityId][msg.sender] = paymaster;
    }

    /// @inheritdoc IModule
    /// @param data should be encoded with the entityId of the validation
    function onUninstall(bytes calldata data) external override {
        (uint32 entityId) = abi.decode(data, (uint32));
        delete paymasters[entityId][msg.sender];
    }

    /// @inheritdoc IValidationHookModule
    function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata userOp, bytes32)
        external
        view
        override
        assertNoData(userOp.signature)
        returns (uint256)
    {
        address payingPaymaster = address(bytes20(userOp.paymasterAndData[:20]));
        if (payingPaymaster == paymasters[entityId][msg.sender]) {
            return 0;
        } else {
            revert BadPaymasterSpecified();
        }
    }

    /// @inheritdoc IValidationHookModule
    function preRuntimeValidationHook(uint32, address, uint256, bytes calldata, bytes calldata)
        external
        view
        override
    // solhint-disable-next-line no-empty-blocks
    {}

    // solhint-disable-next-line no-empty-blocks
    function preSignatureValidationHook(uint32, address, bytes32, bytes calldata) external pure override {}

    /// @inheritdoc IModule
    function moduleId() external pure returns (string memory) {
        return "alchemy.paymaster-guard-module.1.0.0";
    }

    /// @inheritdoc ModuleBase
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ModuleBase, IERC165)
        returns (bool)
    {
        return interfaceId == type(IValidationHookModule).interfaceId || super.supportsInterface(interfaceId);
    }
}
