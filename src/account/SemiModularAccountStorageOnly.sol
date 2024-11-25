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

import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {ExecutionInstallDelegate} from "../helpers/ExecutionInstallDelegate.sol";
import {SemiModularAccountBase} from "./SemiModularAccountBase.sol";

/// @title Semi-Modular Account Storage Only
/// @author Alchemy
/// @notice An implementation of a semi-modular account which includes an initializer to set the fallback signer in
/// storage upon initialization.
/// @dev Inherits SemiModularAccountBase. Note that the initializer has no access control and should be called via
/// `upgradeToAndCall()`. Use the `SemiModularAccountBytecode` instead for new accounts, this implementation should
/// only be used for account upgrades.
contract SemiModularAccountStorageOnly is SemiModularAccountBase {
    constructor(IEntryPoint entryPoint, ExecutionInstallDelegate executionInstallDelegate)
        SemiModularAccountBase(entryPoint, executionInstallDelegate)
    {}

    function initialize(address initialSigner) external initializer {
        SemiModularAccountStorage storage smaStorage = _getSemiModularAccountStorage();

        smaStorage.fallbackSigner = initialSigner;
        smaStorage.fallbackSignerDisabled = false;

        emit FallbackSignerUpdated(initialSigner, false);
    }

    /// @inheritdoc IModularAccount
    function accountId() external pure override returns (string memory) {
        return "alchemy.sma-storage.1.0.0";
    }

    /// @dev Overrides SemiModularAccountBase.
    function _isNativeFunction(uint32 selector) internal pure override returns (bool) {
        return super._isNativeFunction(selector) || selector == uint32(this.initialize.selector);
    }
}
