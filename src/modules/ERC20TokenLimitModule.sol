// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {UserOperationLib} from "@eth-infinitism/account-abstraction/core/UserOperationLib.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {Call, IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";

import {BaseModule, IERC165} from "./BaseModule.sol";

/// @title ERC20 Token Limit Module
/// @author Alchemy & ERC-6900 Authors
/// @notice This module supports ERC20 token spend limits. A few key features/restrictions features:
///     - This module only provide hooks associated with validations.
///     - For any validation function with this hook installed, all ERC20s without limits specified here will be
/// reverted.
///     - Only spending request through the following native execution functions are supported:
/// IModularAccount.execute, IModularAccount.executeWithAuthorization, IAccountExecute.executeUserOp,
/// IModularAccount.executeBatch. All other spending request will be reverted.
///     - this module is opinionated on what selectors (transfer and approve only) can be called for token
/// contracts to guard against weird edge cases like DAI. You wouldn't be able to use uni v2 pairs directly as the
/// pair contract is also the LP token contract.
contract ERC20TokenLimitModule is BaseModule, IExecutionHookModule {
    using UserOperationLib for PackedUserOperation;

    struct ERC20SpendLimit {
        address token;
        uint256 limit;
    }

    mapping(uint32 entityId => mapping(address token => mapping(address account => uint256 limit))) public limits;

    error ExceededTokenLimit();
    error SelectorNotAllowed();
    error SpendingRequestNotAllowed(bytes4);
    error ERC20NotAllowed(address);
    error InvalidCalldataLength();

    /// @notice Update the token limit of a validation
    /// @param entityId The validation entityId to update
    /// @param token The token address whose limit will be updated
    /// @param newLimit The new limit of the token for the validation
    function updateLimits(uint32 entityId, address token, uint256 newLimit) external {
        if (token == address(0)) {
            revert ERC20NotAllowed(address(0));
        }
        limits[entityId][token][msg.sender] = newLimit;
    }

    /// @inheritdoc IExecutionHookModule
    function preExecutionHook(uint32 entityId, address, uint256, bytes calldata data)
        external
        override
        returns (bytes memory)
    {
        (bytes4 selector, bytes memory callData) = _getSelectorAndCalldata(data);

        if (selector == IModularAccount.execute.selector) {
            // when calling execute or ERC20 functions directly
            (address token,, bytes memory innerCalldata) = abi.decode(callData, (address, uint256, bytes));
            _decrementLimit(entityId, token, innerCalldata);
        } else if (selector == IModularAccount.executeBatch.selector) {
            Call[] memory calls = abi.decode(callData, (Call[]));
            for (uint256 i = 0; i < calls.length; i++) {
                _decrementLimit(entityId, calls[i].target, calls[i].data);
            }
        } else {
            revert SpendingRequestNotAllowed(selector);
        }
        return "";
    }

    /// @inheritdoc IModule
    /// @param data should be encoded with the entityId of the validation and a list of ERC20 spend limits
    function onInstall(bytes calldata data) external override {
        (uint32 entityId, ERC20SpendLimit[] memory spendLimits) = abi.decode(data, (uint32, ERC20SpendLimit[]));

        for (uint8 i = 0; i < spendLimits.length; i++) {
            address token = spendLimits[i].token;
            if (token == address(0)) {
                revert ERC20NotAllowed(address(0));
            }
            limits[entityId][token][msg.sender] = spendLimits[i].limit;
        }
    }

    /// @inheritdoc IModule
    /// @notice uninstall this module can only clear limit for one token of one entity. To clear all limits, users
    /// are recommended to use updateLimit for each token and entityId.
    /// @param data should be encoded with the entityId of the validation and the token address to be uninstalled
    function onUninstall(bytes calldata data) external override {
        (address token, uint32 entityId) = abi.decode(data, (address, uint32));
        delete limits[entityId][token][msg.sender];
    }

    /// @inheritdoc IExecutionHookModule
    function postExecutionHook(uint32, bytes calldata) external pure override {
        revert NotImplemented();
    }

    /// @inheritdoc IModule
    function moduleId() external pure returns (string memory) {
        return "alchemy.erc20-token-limit-module.0.0.1";
    }

    /// @inheritdoc BaseModule
    function supportsInterface(bytes4 interfaceId) public view override(BaseModule, IERC165) returns (bool) {
        return interfaceId == type(IExecutionHookModule).interfaceId || super.supportsInterface(interfaceId);
    }

    function _decrementLimit(uint32 entityId, address token, bytes memory innerCalldata) internal {
        if (innerCalldata.length < 68) {
            revert InvalidCalldataLength();
        }

        bytes4 selector;
        uint256 spend;
        assembly ("memory-safe") {
            selector := mload(add(innerCalldata, 32)) // 0:32 is arr len, 32:36 is selector
            spend := mload(add(innerCalldata, 68)) // 36:68 is recipient, 68:100 is spend
        }
        if (_isAllowedERC20Function(selector)) {
            uint256 limit = limits[entityId][token][msg.sender];
            if (spend > limit) {
                revert ExceededTokenLimit();
            }
            unchecked {
                limits[entityId][token][msg.sender] = limit - spend;
            }
        } else {
            revert SelectorNotAllowed();
        }
    }

    function _isAllowedERC20Function(bytes4 selector) internal pure returns (bool) {
        return selector == IERC20.transfer.selector || selector == IERC20.approve.selector;
    }
}
