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
import {UserOperationLib} from "@eth-infinitism/account-abstraction/core/UserOperationLib.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {ModularAccountBase} from "../../account/ModularAccountBase.sol";
import {IERC165, ModuleBase} from "../ModuleBase.sol";

/// @title Native Token Limit Module
/// @author Alchemy
/// @notice This module supports a total native token spend limit across User Operation gas and native transfers.
/// - None of the functions are installed on the account. Account states are to be retrieved from this global
///   singleton directly.
/// - This module only tracks native transfers for the 3 functions `execute`, `executeBatch`, `performCreate`.
/// - By default, using a paymaster in a UO would cause the limit to not decrease. If an account uses a special
///   paymaster that converts non-native tokens in the account to pay for gas, this paymaster should be added to
///   the `specialPaymasters` list to enable the correct accounting of spend limits. When these paymasters are used
///   to pay for a UO, spend limits would be decremented.
contract NativeTokenLimitModule is ModuleBase, IExecutionHookModule, IValidationHookModule {
    using UserOperationLib for PackedUserOperation;

    mapping(uint256 entityId => mapping(address account => uint256 limit)) public limits;
    // paymasters given permissions to pull funds from accounts should be added here
    mapping(address paymaster => mapping(address account => bool allowed)) public specialPaymasters;

    error ExceededNativeTokenLimit();
    error InvalidPaymaster();

    /// @notice Update the native token limit for a specific entity
    /// @param entityId The entity id
    /// @param newLimit The new limit
    function updateLimits(uint32 entityId, uint256 newLimit) external {
        limits[entityId][msg.sender] = newLimit;
    }

    /// @notice Update special paymasters that should still decrease the limit of an account
    /// @param paymaster The paymaster address
    /// @param allowed Whether the paymaster is allowed to pull funds from the account
    function updateSpecialPaymaster(address paymaster, bool allowed) external {
        specialPaymasters[paymaster][msg.sender] = allowed;
    }

    /// @inheritdoc IValidationHookModule
    function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata userOp, bytes32)
        external
        assertNoData(userOp.signature)
        returns (uint256)
    {
        // Decrease limit only if no paymaster is used, or if its a special paymaster
        if (userOp.paymasterAndData.length > 0) {
            address paymaster = address(bytes20(userOp.paymasterAndData[:20]));
            if (paymaster == address(0)) {
                revert InvalidPaymaster();
            } else if (specialPaymasters[paymaster][msg.sender]) {
                // Special paymaster specified, decrease limit
                _decreaseLimit(entityId, userOp, true);
            }
        } else {
            // No paymaster specified, decrease limit
            _decreaseLimit(entityId, userOp, false);
        }

        return 0;
    }

    /// @inheritdoc IExecutionHookModule
    function preExecutionHook(uint32 entityId, address, uint256, bytes calldata data)
        external
        override
        returns (bytes memory)
    {
        (bytes4 selector, bytes memory callData) = _getSelectorAndCalldata(data);

        uint256 value;
        // Get value being sent
        if (selector == IModularAccount.execute.selector) {
            (, value) = abi.decode(callData, (address, uint256));
        } else if (selector == IModularAccount.executeBatch.selector) {
            Call[] memory calls = abi.decode(callData, (Call[]));
            for (uint256 i = 0; i < calls.length; i++) {
                value += calls[i].value;
            }
        } else if (selector == ModularAccountBase.performCreate.selector) {
            value = abi.decode(callData, (uint256));
        }

        uint256 limit = limits[entityId][msg.sender];
        if (value > limit) {
            revert ExceededNativeTokenLimit();
        }
        limits[entityId][msg.sender] = limit - value;

        return "";
    }

    /// @inheritdoc IModule
    function onInstall(bytes calldata data) external override {
        (uint32 entityId, uint256 spendLimit) = abi.decode(data, (uint32, uint256));
        limits[entityId][msg.sender] = spendLimit;
    }

    /// @inheritdoc IModule
    function onUninstall(bytes calldata data) external override {
        uint32 entityId = abi.decode(data, (uint32));
        delete limits[entityId][msg.sender];
    }

    /// @inheritdoc IExecutionHookModule
    function postExecutionHook(uint32, bytes calldata) external pure override {
        revert NotImplemented();
    }

    // No implementation, no revert
    // Runtime spends no account gas, and we check native token spend limits in exec hooks
    function preRuntimeValidationHook(uint32, address, uint256, bytes calldata, bytes calldata)
        external
        pure
        override
    {} // solhint-disable-line no-empty-blocks

    // solhint-disable-next-line no-empty-blocks
    function preSignatureValidationHook(uint32, address, bytes32, bytes calldata) external pure override {}

    /// @inheritdoc IModule
    function moduleId() external pure returns (string memory) {
        return "alchemy.native-token-limit-module.1.0.0";
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc ModuleBase
    function supportsInterface(bytes4 interfaceId) public view override(ModuleBase, IERC165) returns (bool) {
        return interfaceId == type(IExecutionHookModule).interfaceId
            || interfaceId == type(IValidationHookModule).interfaceId || super.supportsInterface(interfaceId);
    }

    function _decreaseLimit(uint32 entityId, PackedUserOperation calldata userOp, bool hasPaymaster) internal {
        uint256 vgl = UserOperationLib.unpackVerificationGasLimit(userOp);
        uint256 cgl = UserOperationLib.unpackCallGasLimit(userOp);
        uint256 pvgl;
        uint256 ppogl;
        if (hasPaymaster) {
            // Can skip the EP length check here since it would have reverted there if it was invalid
            (, pvgl, ppogl) = UserOperationLib.unpackPaymasterStaticFields(userOp.paymasterAndData);
        }
        uint256 totalGas = userOp.preVerificationGas + vgl + cgl + pvgl + ppogl;
        uint256 usage = totalGas * UserOperationLib.unpackMaxFeePerGas(userOp);

        uint256 limit = limits[entityId][msg.sender];
        if (usage > limit) {
            revert ExceededNativeTokenLimit();
        }
        limits[entityId][msg.sender] = limit - usage;
    }
}
