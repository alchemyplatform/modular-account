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

import {HookConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

import {toSetValue} from "../account/AccountStorage.sol";
import {ExecutionLib} from "./ExecutionLib.sol";
import {LinkedListSet, LinkedListSetLib} from "./LinkedListSetLib.sol";

/// @title Module Install Commons Library
/// @author Alchemy
/// @notice This is an internal library which holds module installation-related functions relevant to both the
/// ExecutionInstallDelegate and the ModuleManagerInternals contracts.
library ModuleInstallCommonsLib {
    using LinkedListSetLib for LinkedListSet;

    error InterfaceNotSupported(address module);
    error ModuleInstallCallbackFailed(address module, bytes revertReason);
    error ExecutionHookAlreadySet(HookConfig hookConfig);

    // Internal Functions

    // We don't need to bring the exec hook removal function here since it's only ever used in the
    // ExecutionInstallLib

    /// @dev adds an execution hook to a specific set of hooks.
    function addExecHooks(LinkedListSet storage hooks, HookConfig hookConfig) internal {
        if (!hooks.tryAdd(toSetValue(hookConfig))) {
            revert ExecutionHookAlreadySet(hookConfig);
        }
    }

    /// @dev setup the module storage for the account, reverts are bubbled up into a custom
    /// ModuleInstallCallbackFailed
    function onInstall(address module, bytes calldata data, bytes4 interfaceId) internal {
        if (data.length > 0) {
            if (!ERC165Checker.supportsERC165InterfaceUnchecked(module, interfaceId)) {
                revert InterfaceNotSupported(module);
            }
            // solhint-disable-next-line no-empty-blocks
            try IModule(module).onInstall(data) {}
            catch {
                bytes memory revertReason = ExecutionLib.collectReturnData();
                revert ModuleInstallCallbackFailed(module, revertReason);
            }
        }
    }

    /// @dev clear the module storage for the account, reverts are IGNORED. Status is included in emitted event.
    function onUninstall(address module, bytes calldata data) internal returns (bool onUninstallSuccess) {
        onUninstallSuccess = true;
        if (data.length > 0) {
            // Clear the module storage for the account.
            // solhint-disable-next-line no-empty-blocks
            try IModule(module).onUninstall(data) {}
            catch {
                onUninstallSuccess = false;
            }
        }
    }
}
