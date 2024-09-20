// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {UserOperationLib} from "@eth-infinitism/account-abstraction/core/UserOperationLib.sol";
import {IAccountExecute} from "@eth-infinitism/account-abstraction/interfaces/IAccountExecute.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {
    AssociatedLinkedListSet,
    AssociatedLinkedListSetLib,
    SetValue
} from "@erc6900/modular-account-libs/libraries/AssociatedLinkedListSetLib.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

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
/// pair contract is also the LP token contract

contract ERC20TokenLimitModule is BaseModule, IExecutionHookModule {
    using UserOperationLib for PackedUserOperation;
    using EnumerableSet for EnumerableSet.AddressSet;
    using AssociatedLinkedListSetLib for AssociatedLinkedListSet;

    struct ERC20SpendLimit {
        address token;
        uint256 limit;
    }

    string internal constant _NAME = "ERC20 Token Limit Module";
    string internal constant _VERSION = "1.0.0";
    string internal constant _AUTHOR = "Alchemy & ERC-6900 Authors";

    mapping(uint32 entityId => mapping(address token => mapping(address account => uint256 limit))) public limits;
    AssociatedLinkedListSet internal _tokenList;

    error ExceededTokenLimit();
    error ExceededNumberOfEntities();
    error SelectorNotAllowed();
    error SpendingRequestNotAllowed(bytes4);
    error ERC20NotAllowed(address);

    function updateLimits(uint32 entityId, address token, uint256 newLimit) external {
        _tokenList.tryAdd(msg.sender, SetValue.wrap(bytes30(bytes20(token))));
        limits[entityId][token][msg.sender] = newLimit;
    }

    /// @inheritdoc IExecutionHookModule
    function preExecutionHook(uint32 entityId, address, uint256, bytes calldata data)
        external
        override
        returns (bytes memory)
    {
        (bytes4 selector, bytes memory callData) = _getSelectorAndCalldata(data);

        if (
            selector == IModularAccount.execute.selector
                || selector == IModularAccount.executeWithAuthorization.selector
                || selector == IAccountExecute.executeUserOp.selector
        ) {
            // when calling execute or ERC20 functions directly
            (address token,, bytes memory innerCalldata) = abi.decode(callData, (address, uint256, bytes));
            if (_tokenList.contains(msg.sender, SetValue.wrap(bytes30(bytes20(token))))) {
                _decrementLimit(entityId, token, innerCalldata);
            } else {
                revert ERC20NotAllowed(token);
            }
        } else if (selector == IModularAccount.executeBatch.selector) {
            Call[] memory calls = abi.decode(callData, (Call[]));
            for (uint256 i = 0; i < calls.length; i++) {
                if (_tokenList.contains(msg.sender, SetValue.wrap(bytes30(bytes20(calls[i].target))))) {
                    _decrementLimit(entityId, calls[i].target, calls[i].data);
                } else {
                    revert ERC20NotAllowed(calls[i].target);
                }
            }
        } else {
            revert SpendingRequestNotAllowed(selector);
        }
        return "";
    }

    /// @inheritdoc IModule
    function onInstall(bytes calldata data) external override {
        (uint32 entityId, ERC20SpendLimit[] memory spendLimits) = abi.decode(data, (uint32, ERC20SpendLimit[]));

        for (uint8 i = 0; i < spendLimits.length; i++) {
            _tokenList.tryAdd(msg.sender, SetValue.wrap(bytes30(bytes20(spendLimits[i].token))));
            limits[entityId][spendLimits[i].token][msg.sender] = spendLimits[i].limit;
        }
    }

    /// @inheritdoc IModule
    function onUninstall(bytes calldata data) external override {
        (address token, uint32 entityId) = abi.decode(data, (address, uint32));
        delete limits[entityId][token][msg.sender];
    }

    function getTokensForAccount(address account) external view returns (address[] memory tokens) {
        SetValue[] memory set = _tokenList.getAll(account);
        tokens = new address[](set.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            tokens[i] = address(bytes20(bytes32(SetValue.unwrap(set[i]))));
        }
        return tokens;
    }

    /// @inheritdoc IExecutionHookModule
    function postExecutionHook(uint32, bytes calldata) external pure override {
        revert NotImplemented();
    }

    /// @inheritdoc IModule
    function moduleId() external pure returns (string memory) {
        return "erc6900.erc20-token-limit-module.1.0.0";
    }

    /// @inheritdoc BaseModule
    function supportsInterface(bytes4 interfaceId) public view override(BaseModule, IERC165) returns (bool) {
        return interfaceId == type(IExecutionHookModule).interfaceId || super.supportsInterface(interfaceId);
    }

    function _decrementLimit(uint32 entityId, address token, bytes memory innerCalldata) internal {
        bytes4 selector;
        uint256 spend;
        assembly {
            selector := mload(add(innerCalldata, 32)) // 0:32 is arr len, 32:36 is selector
            spend := mload(add(innerCalldata, 68)) // 36:68 is recipient, 68:100 is spend
        }
        if (selector == IERC20.transfer.selector || selector == IERC20.approve.selector) {
            uint256 limit = limits[entityId][token][msg.sender];
            if (spend > limit) {
                revert ExceededTokenLimit();
            }
            // solhint-disable-next-line reentrancy
            limits[entityId][token][msg.sender] = limit - spend;
        } else {
            revert SelectorNotAllowed();
        }
    }

    function _isAllowedERC20Function(bytes4 selector) internal pure returns (bool) {
        return selector == IERC20.transfer.selector || selector == IERC20.approve.selector;
    }
}
