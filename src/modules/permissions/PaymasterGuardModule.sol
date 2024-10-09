// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";

import {BaseModule, IERC165} from "../BaseModule.sol";

/// @title Paymaster Guard Module
/// @author Alchemy & ERC-6900 Authors
/// @notice This module supports permission checks where an validation is allowed only if a certain paymaster is
/// used.
/// - If this hook is installed, and no paymaster is setup, all requests will revert
contract PaymasterGuardModule is BaseModule, IValidationHookModule {
    mapping(uint32 entityId => mapping(address account => address paymaster)) public paymasters;

    error BadPaymasterSpecified();

    /// @inheritdoc IModule
    /// @param data should be encoded with the entityId of the validation and the paymaster address that guards the
    /// validation
    function onInstall(bytes calldata data) external override {
        (uint32 entityId, address paymaster) = abi.decode(data, (uint32, address));
        paymasters[entityId][msg.sender] = paymaster;
    }

    /// @inheritdoc IModule
    /// @param data should be encoded with the entityId of the validation
    function onUninstall(bytes calldata data) external override {
        (uint32 entityId) = abi.decode(data, (uint32));
        delete paymasters[entityId][msg.sender];
    }

    /// @inheritdoc IValidationHookModule
    function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata userOp, bytes32)
        external
        view
        override
        noValidationData(userOp.signature)
        returns (uint256)
    {
        address payingPaymaster = address(bytes20(userOp.paymasterAndData[:20]));
        if (payingPaymaster == paymasters[entityId][msg.sender]) {
            return 0;
        } else {
            revert BadPaymasterSpecified();
        }
    }

    /// @inheritdoc IValidationHookModule
    function preRuntimeValidationHook(uint32, address, uint256, bytes calldata, bytes calldata)
        external
        view
        override
    // solhint-disable-next-line no-empty-blocks
    {}

    // solhint-disable-next-line no-empty-blocks
    function preSignatureValidationHook(uint32, address, bytes32, bytes calldata) external pure override {}

    /// @inheritdoc IModule
    function moduleId() external pure returns (string memory) {
        return "alchemy.paymaster-guard-module.0.0.1";
    }

    /// @inheritdoc BaseModule
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(BaseModule, IERC165)
        returns (bool)
    {
        return interfaceId == type(IValidationHookModule).interfaceId || super.supportsInterface(interfaceId);
    }
}
