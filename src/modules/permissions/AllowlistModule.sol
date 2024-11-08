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

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {Call, IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {ModuleBase} from "../../modules/ModuleBase.sol";

/// @title Allowlist with ERC-20 Spend Limit Module
/// @author Alchemy
/// @notice This module allows for the setting and enforcement of allowlists with ERC-20 spend limit for an entity.
/// - Uninstallation will NOT disable all installed hooks for an account. It only uninstalls hooks for the
///   entity ID that is passed in. Account must remove access for each entity ID if want to disable all hooks.
/// - None of the functions are installed on the account. Account states are to be retrieved from this global
///   singleton directly.
/// - To enable allowlisting, the account must have this module installed as a validation hook.
///     - These allowlists can specify which addresses and or selectors can be called by the entity. It supports:
///         - Specific addresses + specific selectors
///         - Specific addresses + wildcard selectors
///         - Wildcard addresses + specific selectors
///     - These restrictions only apply to the `IModularAccount.execute` and `IModularAccount.executeBatch`
///       functions.
///     - The order of permission checks:
///         - If wildcard address (any selector allowed), pass
///         - If wildcard selector (any address allowed), pass
///         - If specific address + specific selector, pass
///         - Revert all other cases
/// - To enable ERC-20 spend limits, the account must also have this module installed as a validation associated
///   execution hook. The following features and restrictions apply:
///     - Only token contracts with a set limit will be checked, other allowed addresses will be allowed. To
///       protect the account's balance of non-tracked tokens, users are recommended to also install the allowlist
///       validation hook, to limit which addresses the validation may perform calls to.
///     - Spending requests are only supported through the following native execution functions:
///       IModularAccount.execute, IModularAccount.executeWithRuntimeValidation, IAccountExecute.executeUserOp,
///       IModularAccount.executeBatch. All other spending request will revert.
///     - This module is opinionated on what selectors can be called for token contracts: only `transfer` and
///       `approve` are allowed. This guards against edge cases, where token contracts like DAI have other
///       functions that result in ERC-20 transfers or allowance changes.
contract AllowlistModule is IExecutionHookModule, IValidationHookModule, ModuleBase {
    struct AllowlistInput {
        address target;
        // if target is address(0), hasSelectorAllowlist is ignored.
        bool hasSelectorAllowlist;
        // if true, indicates tartget is an ERC-20 token, and there is a spend limit on the token
        bool hasERC20SpendLimit;
        uint256 erc20SpendLimit;
        bytes4[] selectors;
    }

    struct AddressAllowlistEntry {
        bool allowed;
        bool hasSelectorAllowlist;
        // if true, indicates tartget is a token, and there is a spend limit on the token
        bool hasERC20SpendLimit;
    }

    mapping(uint32 entityId => mapping(address target => mapping(address account => AddressAllowlistEntry))) public
        addressAllowlist;

    /// @notice this is only for targets that are tokens, if hasERC20SpendLimit in AddressAllowlistEntry is false,
    /// this value is ignored.
    mapping(uint32 entityId => mapping(address target => mapping(address account => uint256))) public
        erc20SpendLimits;

    /// @notice if target is address(0), any address is allowed with the selector
    mapping(
        uint32 entityId => mapping(bytes4 selector => mapping(address target => mapping(address account => bool)))
    ) public selectorAllowlist;

    event AddressAllowlistUpdated(
        uint32 indexed entityId, address indexed account, address indexed target, AddressAllowlistEntry entry
    );
    event SelectorAllowlistUpdated(
        uint32 indexed entityId, address indexed account, bytes24 indexed targetAndSelector, bool allowed
    );

    error AddressNotAllowed();
    error SelectorNotAllowed();
    error NoSelectorSpecified();
    error ExceededTokenLimit();
    error SpendingRequestNotAllowed(bytes4);
    error ERC20NotAllowed(address);
    error InvalidCalldataLength();

    /// @inheritdoc IModule
    /// @dev The `data` parameter is expected to be encoded as `(uint32 entityId, AllowlistInput[] inputs)`.
    function onInstall(bytes calldata data) external override {
        (uint32 entityId, AllowlistInput[] memory inputs) = abi.decode(data, (uint32, AllowlistInput[]));

        updateAllowlist(entityId, inputs);
    }

    /// @inheritdoc IModule
    /// @dev The `data` parameter is expected to be encoded as `(uint32 entityId, AllowlistInput[] inputs)`.
    function onUninstall(bytes calldata data) external override {
        (uint32 entityId, AllowlistInput[] memory inputs) = abi.decode(data, (uint32, AllowlistInput[]));

        deleteAllowlist(entityId, inputs);
    }

    /// @inheritdoc IExecutionHookModule
    function preExecutionHook(uint32 entityId, address, uint256, bytes calldata data)
        external
        override
        returns (bytes memory)
    {
        (bytes4 selector, bytes memory callData) = _getSelectorAndCalldata(data);

        if (selector == IModularAccount.execute.selector) {
            // when calling execute or ERC-20 functions directly
            (address token,, bytes memory innerCalldata) = abi.decode(callData, (address, uint256, bytes));
            _decrementLimitIfApplies(entityId, token, innerCalldata);
        } else if (selector == IModularAccount.executeBatch.selector) {
            Call[] memory calls = abi.decode(callData, (Call[]));
            for (uint256 i = 0; i < calls.length; i++) {
                _decrementLimitIfApplies(entityId, calls[i].target, calls[i].data);
            }
        } else {
            revert SpendingRequestNotAllowed(selector);
        }
        return "";
    }

    /// @inheritdoc IValidationHookModule
    function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata userOp, bytes32)
        external
        view
        override
        assertNoData(userOp.signature)
        returns (uint256)
    {
        checkAllowlistCalldata(entityId, userOp.callData);
        return 0;
    }

    /// @inheritdoc IValidationHookModule
    function preRuntimeValidationHook(uint32 entityId, address, uint256, bytes calldata data, bytes calldata)
        external
        view
        override
    {
        checkAllowlistCalldata(entityId, data);
        return;
    }

    // solhint-disable-next-line no-empty-blocks
    function preSignatureValidationHook(uint32, address, bytes32, bytes calldata) external pure override {}

    /// @inheritdoc IExecutionHookModule
    function postExecutionHook(uint32, bytes calldata) external pure override {
        revert NotImplemented();
    }

    /// @inheritdoc IModule
    function moduleId() external pure returns (string memory) {
        return "alchemy.allowlist-module.1.0.0";
    }

    /// @notice Update the token limit of a validation
    /// @param entityId The validation entityId to update
    /// @param token The token address whose limit will be updated
    /// @param newLimit The new limit of the token for the validation
    function updateLimits(uint32 entityId, address token, bool hasERC20SpendLimit, uint256 newLimit) public {
        if (token == address(0)) {
            revert ERC20NotAllowed(address(0));
        }

        addressAllowlist[entityId][token][msg.sender].hasERC20SpendLimit = hasERC20SpendLimit;
        erc20SpendLimits[entityId][token][msg.sender] = newLimit;
    }

    /// @notice update the allowlists for a given entity ID. If the entry for an address or selector exist, it will
    /// be overwritten.
    /// @param entityId The entity ID to initialize the allowlist for.
    /// @param inputs The allowlist inputs data to update.
    function updateAllowlist(uint32 entityId, AllowlistInput[] memory inputs) public {
        for (uint256 i = 0; i < inputs.length; i++) {
            AllowlistInput memory input = inputs[i];
            if (input.target == address(0)) {
                // wildcard case for selectors, any address can be called for the selector
                for (uint256 j = 0; j < input.selectors.length; j++) {
                    setSelectorAllowlist(entityId, address(0), input.selectors[j], true);
                }
            } else {
                setAddressAllowlist(
                    entityId, input.target, true, input.hasSelectorAllowlist, input.hasERC20SpendLimit
                );
                updateLimits(entityId, input.target, input.hasERC20SpendLimit, input.erc20SpendLimit);

                if (input.hasSelectorAllowlist) {
                    for (uint256 j = 0; j < input.selectors.length; j++) {
                        setSelectorAllowlist(entityId, input.target, input.selectors[j], true);
                    }
                }
            }
        }
    }

    /// @notice delete the allowlists for a given entity ID.
    /// @param entityId The entity ID to initialize the allowlist for.
    /// @param inputs The allowlist inputs data to update.
    /// Note flag will be set to false despite passed different values.
    function deleteAllowlist(uint32 entityId, AllowlistInput[] memory inputs) public {
        for (uint256 i = 0; i < inputs.length; i++) {
            AllowlistInput memory input = inputs[i];
            if (input.target == address(0)) {
                // wildcard case for selectors, any address can be called for the selector
                for (uint256 j = 0; j < input.selectors.length; j++) {
                    setSelectorAllowlist(entityId, input.target, input.selectors[j], false);
                }
            } else {
                setAddressAllowlist(entityId, input.target, false, false, false);
                updateLimits(entityId, input.target, false, 0);

                if (input.hasSelectorAllowlist) {
                    for (uint256 j = 0; j < input.selectors.length; j++) {
                        setSelectorAllowlist(entityId, input.target, input.selectors[j], false);
                    }
                }
            }
        }
    }

    /// @notice Set the allowlist status for a target address, in the allowlist of the caller account and the
    /// provided entity ID.
    /// @param entityId The entity ID to set the allowlist status for.
    /// @param target The target address.
    /// @param allowed The new allowlist status, indicating whether or not the target address can be called.
    /// @param hasSelectorAllowlist Whether or not the target address has a selector allowlist. If true, the
    /// @param hasERC20SpendLimit Whether or not the target address has a ERC20 spend limit.
    /// allowlist checking will validate that the selector is on the selector allowlist.
    function setAddressAllowlist(
        uint32 entityId,
        address target,
        bool allowed,
        bool hasSelectorAllowlist,
        bool hasERC20SpendLimit
    ) public {
        AddressAllowlistEntry memory entry =
            AddressAllowlistEntry(allowed, hasSelectorAllowlist, hasERC20SpendLimit);
        addressAllowlist[entityId][target][msg.sender] = entry;
        emit AddressAllowlistUpdated(entityId, msg.sender, target, entry);
    }

    /// @notice Set the allowlist status for a selector, in the allowlist of the caller account and the provided
    /// entity ID.
    /// Note that if the target address does not have a selector allowlist, this update will not be
    /// reflected on the usage of the allowlist hook.
    /// @param entityId The entity ID to set the allowlist status for.
    /// @param target The target address.
    /// @param selector The selector to set the allowlist status for.
    /// @param allowed The new allowlist status, indicating whether or not the selector can be called.
    function setSelectorAllowlist(uint32 entityId, address target, bytes4 selector, bool allowed) public {
        selectorAllowlist[entityId][selector][target][msg.sender] = allowed;
        bytes24 targetAndSelector = bytes24(bytes24(bytes20(target)) | (bytes24(selector) >> 160));
        emit SelectorAllowlistUpdated(entityId, msg.sender, targetAndSelector, allowed);
    }

    /// @notice Check the allowlist status for a call payload. If the call is not allowed, this function will
    /// revert.
    /// @param entityId The entity ID to check the allowlist status for.
    /// @param callData The call payload to check the allowlist status for. This should be a call to either
    /// `IModularAccount.execute`, or `IModularAccount.executeBatch`.
    function checkAllowlistCalldata(uint32 entityId, bytes calldata callData) public view {
        if (bytes4(callData[:4]) == IModularAccount.execute.selector) {
            (address target,, bytes memory data) = abi.decode(callData[4:], (address, uint256, bytes));
            _checkCallPermission(entityId, msg.sender, target, data);
        } else if (bytes4(callData[:4]) == IModularAccount.executeBatch.selector) {
            Call[] memory calls = abi.decode(callData[4:], (Call[]));

            for (uint256 i = 0; i < calls.length; i++) {
                _checkCallPermission(entityId, msg.sender, calls[i].target, calls[i].data);
            }
        }
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ModuleBase, IERC165)
        returns (bool)
    {
        return interfaceId == type(IValidationHookModule).interfaceId
            || interfaceId == type(IExecutionHookModule).interfaceId || super.supportsInterface(interfaceId);
    }

    function _decrementLimitIfApplies(uint32 entityId, address token, bytes memory innerCalldata) internal {
        if (!addressAllowlist[entityId][token][msg.sender].hasERC20SpendLimit) return;

        uint256 spendLimit = erc20SpendLimits[entityId][token][msg.sender];

        if (innerCalldata.length < 68) {
            revert InvalidCalldataLength();
        }

        bytes4 selector;
        uint256 spend;
        assembly ("memory-safe") {
            selector := mload(add(innerCalldata, 0x20)) // 0x00:0x20 is arr len, 0x20:0x24 is selector
            spend := mload(add(innerCalldata, 0x44)) // 0x24:0x44 is recipient, 0x44:0x64 is spend
        }
        if (_isAllowedERC20Function(selector)) {
            uint256 limit = spendLimit;
            if (spend > limit) {
                revert ExceededTokenLimit();
            }
            unchecked {
                erc20SpendLimits[entityId][token][msg.sender] = limit - spend;
            }
        } else {
            revert SelectorNotAllowed();
        }
    }

    function _checkCallPermission(uint32 entityId, address account, address target, bytes memory data)
        internal
        view
    {
        bytes4 selector = bytes4(data);

        AddressAllowlistEntry storage entry = addressAllowlist[entityId][target][account];
        (bool allowed, bool hasSelectorAllowlist) = (entry.allowed, entry.hasSelectorAllowlist);

        if (!allowed) {
            if (selectorAllowlist[entityId][selector][address(0)][account]) {
                // selector wildcard case, any address is allowed
                return;
            }

            revert AddressNotAllowed();
        }

        if (hasSelectorAllowlist) {
            if (data.length < 4) {
                revert NoSelectorSpecified();
            }

            if (!selectorAllowlist[entityId][selector][target][account]) {
                revert SelectorNotAllowed();
            }
        }
    }

    function _isAllowedERC20Function(bytes4 selector) internal pure returns (bool) {
        return selector == IERC20.transfer.selector || selector == IERC20.approve.selector;
    }
}
