// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.26;

import {HookConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

import {toSetValue} from "../account/AccountStorage.sol";
import {ExecutionLib} from "./ExecutionLib.sol";
import {LinkedListSet, LinkedListSetLib} from "./LinkedListSetLib.sol";

/// @title ModuleInstallCommons
/// @author Alchemy
///
/// @notice This is an internal library which holds module installation-related functions relevant to both the
/// ExecutionInstallDelegate and the ModuleManagerInternals contracts.
library ModuleInstallCommons {
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
