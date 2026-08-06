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

import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

import {ModuleBase} from "../../../src/modules/ModuleBase.sol";

/// @dev A pre-validation hook module that records whether its `onUninstall` ran, and can be told to revert there.
///
/// A non-reverting instance is what makes "was never called" provable. The account swallows a reverting
/// `onUninstall`, which also rolls back that module's own state, so a zero counter on a *reverting* module is
/// ambiguous between "never called" and "called and reverted". A zero counter on a *non-reverting* module is not:
/// had it been called, the increment would have persisted.
contract MockUninstallHookModule is ModuleBase, IValidationHookModule {
    error UninstallCallbackFailed();

    uint256 public onUninstallCount;
    bool public shouldRevertOnUninstall;

    function setShouldRevertOnUninstall(bool shouldRevert) external {
        shouldRevertOnUninstall = shouldRevert;
    }

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {
        if (shouldRevertOnUninstall) {
            revert UninstallCallbackFailed();
        }
        onUninstallCount++;
    }

    function preRuntimeValidationHook(uint32, address, uint256, bytes calldata, bytes calldata)
        external
        pure
        override
    {}

    function preUserOpValidationHook(uint32, PackedUserOperation calldata, bytes32)
        external
        pure
        override
        returns (uint256)
    {
        return 0;
    }

    function preSignatureValidationHook(uint32, address, bytes32, bytes calldata) external pure override {}

    function moduleId() external pure override returns (string memory) {
        return "erc6900.mock-uninstall-hook-module.1.0.0";
    }

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
