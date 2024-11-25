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

import {
    IModularAccount, ValidationConfig
} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {ExecutionInstallDelegate} from "../helpers/ExecutionInstallDelegate.sol";
import {ModularAccountBase} from "./ModularAccountBase.sol";

/// @title Modular Account
/// @author Alchemy
/// @notice This contract allows initializing with a validation config (of a validation module) to be installed on
/// the account.
contract ModularAccount is ModularAccountBase {
    constructor(IEntryPoint entryPoint, ExecutionInstallDelegate executionInstallDelegate)
        ModularAccountBase(entryPoint, executionInstallDelegate)
    {}

    /// @notice Initializes the account with a validation function.
    /// @dev This function is only callable once.
    function initializeWithValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) external virtual initializer {
        _installValidation(validationConfig, selectors, installData, hooks);
    }

    /// @inheritdoc IModularAccount
    function accountId() external pure override returns (string memory) {
        return "alchemy.modular-account.2.0.0";
    }

    /// @dev Overrides ModularAccountView.
    function _isNativeFunction(uint32 selector) internal pure override returns (bool) {
        return super._isNativeFunction(selector) || selector == uint32(this.initializeWithValidation.selector);
    }
}
