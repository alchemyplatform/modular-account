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
    HookConfig,
    IModularAccount,
    ModuleEntity
} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {
    ExecutionDataView,
    IModularAccountView,
    ValidationDataView
} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";
import {IAccountExecute} from "@eth-infinitism/account-abstraction/interfaces/IAccountExecute.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/interfaces/IERC1155Receiver.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IModularAccountBase} from "../interfaces/IModularAccountBase.sol";
import {MemManagementLib} from "../libraries/MemManagementLib.sol";
import {ValidationLocatorLib} from "../libraries/ValidationLocatorLib.sol";
import {AccountBase} from "./AccountBase.sol";
import {ExecutionStorage, ValidationStorage, getAccountStorage} from "./AccountStorage.sol";

/// @title Modular Account View
/// @author Alchemy
/// @notice This abstract contract implements the two view functions to get validation and execution data for an
/// account.
abstract contract ModularAccountView is IModularAccountView {
    /// @inheritdoc IModularAccountView
    function getExecutionData(bytes4 selector) external view override returns (ExecutionDataView memory data) {
        ExecutionStorage storage executionStorage = getAccountStorage().executionStorage[selector];

        if (_isNativeFunction(uint32(selector))) {
            bool isGlobalValidationAllowed = _isGlobalValidationAllowedNativeFunction(uint32(selector));
            data.module = address(this);
            data.skipRuntimeValidation = !isGlobalValidationAllowed;
            data.allowGlobalValidation = isGlobalValidationAllowed;
            if (!_isWrappedNativeFunction(uint32(selector))) {
                // The native function does not run execution hooks associated with its selector, so
                // we can return early.
                return data;
            }
        } else {
            data.module = executionStorage.module;
            data.skipRuntimeValidation = executionStorage.skipRuntimeValidation;
            data.allowGlobalValidation = executionStorage.allowGlobalValidation;
        }

        HookConfig[] memory hooks = MemManagementLib.loadExecHooks(executionStorage);
        MemManagementLib.reverseArr(hooks);
        data.executionHooks = hooks;
    }

    /// @inheritdoc IModularAccountView
    function getValidationData(ModuleEntity validationFunction)
        external
        view
        override
        returns (ValidationDataView memory data)
    {
        ValidationStorage storage validationStorage =
            getAccountStorage().validationStorage[ValidationLocatorLib.moduleEntityToLookupKey(validationFunction)];
        data.isGlobal = validationStorage.isGlobal;
        data.isSignatureValidation = validationStorage.isSignatureValidation;
        data.isUserOpValidation = validationStorage.isUserOpValidation;
        data.validationHooks = MemManagementLib.loadValidationHooks(validationStorage);
        MemManagementLib.reverseArr(data.validationHooks);

        HookConfig[] memory hooks = MemManagementLib.loadExecHooks(validationStorage);
        MemManagementLib.reverseArr(hooks);
        data.executionHooks = hooks;

        bytes4[] memory selectors = MemManagementLib.loadSelectors(validationStorage);
        MemManagementLib.reverseArr(selectors);
        data.selectors = selectors;
    }

    function _isNativeFunction(uint32 selector) internal pure virtual returns (bool) {
        return (
            _isGlobalValidationAllowedNativeFunction(selector)
                || selector == uint32(AccountBase.entryPoint.selector)
                || selector == uint32(AccountBase.validateUserOp.selector)
                || selector == uint32(IERC1155Receiver.onERC1155BatchReceived.selector)
                || selector == uint32(IERC1155Receiver.onERC1155Received.selector)
                || selector == uint32(IERC1271.isValidSignature.selector)
                || selector == uint32(IERC165.supportsInterface.selector)
                || selector == uint32(IERC721Receiver.onERC721Received.selector)
                || selector == uint32(IModularAccount.accountId.selector)
                || selector == uint32(IModularAccountView.getExecutionData.selector)
                || selector == uint32(IModularAccountView.getValidationData.selector)
                || selector == uint32(UUPSUpgradeable.proxiableUUID.selector)
        );
    }

    /// @dev Check whether a function is a native function that allows global validation.
    function _isGlobalValidationAllowedNativeFunction(uint32 selector) internal pure virtual returns (bool) {
        return (
            _isWrappedNativeFunction(selector) || selector == uint32(IAccountExecute.executeUserOp.selector)
                || selector == uint32(IModularAccount.executeWithRuntimeValidation.selector)
        );
    }

    /// @dev Check whether a function is a native function that has the `wrapNativeFunction` modifier applied,
    /// which means it runs execution hooks associated with its selector.
    function _isWrappedNativeFunction(uint32 selector) internal pure virtual returns (bool) {
        return (
            selector == uint32(IModularAccount.execute.selector)
                || selector == uint32(IModularAccount.executeBatch.selector)
                || selector == uint32(IModularAccount.installExecution.selector)
                || selector == uint32(IModularAccount.installValidation.selector)
                || selector == uint32(IModularAccount.uninstallExecution.selector)
                || selector == uint32(IModularAccount.uninstallValidation.selector)
                || selector == uint32(IModularAccountBase.performCreate.selector)
                || selector == uint32(UUPSUpgradeable.upgradeToAndCall.selector)
        );
    }
}
