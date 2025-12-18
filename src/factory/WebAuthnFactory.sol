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

pragma solidity ^0.8.28;

import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {LibClone} from "solady/utils/LibClone.sol";

import {ModularAccount} from "../account/ModularAccount.sol";

/// @title WebAuthn Account Factory
/// @author Alchemy
/// @notice Factory contract to deploy WebAuthn modular accounts.
contract WebAuthnFactory is Ownable2Step {
    ModularAccount public immutable ACCOUNT_IMPL;
    IEntryPoint public immutable ENTRY_POINT;
    address public immutable WEBAUTHN_VALIDATION_MODULE;

    event WebAuthnModularAccountDeployed(
        address indexed account, uint256 indexed ownerX, uint256 indexed ownerY, uint256 salt
    );

    error InvalidAction();
    error TransferFailed();
    error NoCodeAccountImpl();
    error NoCodeWebAuthnModule();

    constructor(
        IEntryPoint _entryPoint,
        ModularAccount _accountImpl,
        address _webAuthnValidationModule,
        address owner
    ) Ownable(owner) {
        ENTRY_POINT = _entryPoint;
        ACCOUNT_IMPL = _accountImpl;
        WEBAUTHN_VALIDATION_MODULE = _webAuthnValidationModule;
        if (address(_accountImpl).code.length == 0) {
            revert NoCodeAccountImpl();
        }
        if (address(_webAuthnValidationModule).code.length == 0) {
            revert NoCodeWebAuthnModule();
        }
    }

    /// @notice Create an account with the WebAuthn module installed, and return its address.
    /// @dev Returns the address even if the account is already deployed.
    /// Note that during user operation execution, this method is called only if the account is not deployed.
    /// This method returns an existing account address so that entryPoint.getSenderAddress() would work even after
    /// account creation.
    /// @param ownerX The x coordinate of the owner's public key.
    /// @param ownerY The y coordinate of the owner's public key.
    /// @param salt The salt to use for the account creation.
    /// @param entityId The entity ID to use for the account creation.
    /// @return The address of the created account.
    function createWebAuthnAccount(uint256 ownerX, uint256 ownerY, uint256 salt, uint32 entityId)
        external
        returns (ModularAccount)
    {
        bytes32 combinedSalt = getSaltWebAuthn(ownerX, ownerY, salt, entityId);

        // LibClone short-circuits if it's already deployed.
        (bool alreadyDeployed, address instance) =
            LibClone.createDeterministicERC1967(address(ACCOUNT_IMPL), combinedSalt);

        // short circuit if exists
        if (!alreadyDeployed) {
            bytes memory moduleInstallData = abi.encode(entityId, ownerX, ownerY);
            // point proxy to actual implementation and init plugins
            ModularAccount(payable(instance))
                .initializeWithValidation(
                    ValidationConfigLib.pack(WEBAUTHN_VALIDATION_MODULE, entityId, true, true, true),
                    new bytes4[](0),
                    moduleInstallData,
                    new bytes[](0)
                );
            emit WebAuthnModularAccountDeployed(instance, ownerX, ownerY, salt);
        }

        return ModularAccount(payable(instance));
    }

    /// @notice Add stake to the entry point contract.
    /// @param unstakeDelay The delay in seconds before the stake can be withdrawn.
    function addStake(uint32 unstakeDelay) external payable onlyOwner {
        ENTRY_POINT.addStake{value: msg.value}(unstakeDelay);
    }

    /// @notice Unlock the stake in the entry point contract.
    function unlockStake() external onlyOwner {
        ENTRY_POINT.unlockStake();
    }

    /// @notice Withdraw the stake from the entry point contract.
    /// @param withdrawAddress The address to withdraw the stake to.
    function withdrawStake(address payable withdrawAddress) external onlyOwner {
        ENTRY_POINT.withdrawStake(withdrawAddress);
    }

    /// @notice Withdraw funds from this contract.
    /// @dev Can be used to withdraw native currency or ERC-20 tokens.
    /// @param to The address to withdraw the funds to.
    /// @param token The address of the token to withdraw, or the zero address for native currency.
    /// @param amount The amount to withdraw.
    function withdraw(address payable to, address token, uint256 amount) external onlyOwner {
        if (token == address(0)) {
            (bool success,) = to.call{value: address(this).balance}("");
            if (!success) {
                revert TransferFailed();
            }
        } else {
            SafeERC20.safeTransfer(IERC20(token), to, amount);
        }
    }

    /// @notice Calculate the counterfactual address of a webauthn account as it would be returned by
    /// createWebAuthnAccount.
    /// @param ownerX The x coordinate of the owner's public key.
    /// @param ownerY The y coordinate of the owner's public key.
    /// @param salt The salt to use for the account creation.
    /// @param entityId The entity ID to use for the account creation.
    /// @return The address of the account.
    function getAddressWebAuthn(uint256 ownerX, uint256 ownerY, uint256 salt, uint32 entityId)
        external
        view
        returns (address)
    {
        return LibClone.predictDeterministicAddressERC1967(
            address(ACCOUNT_IMPL), getSaltWebAuthn(ownerX, ownerY, salt, entityId), address(this)
        );
    }

    /// @notice Disable renouncing ownership.
    function renounceOwnership() public view override onlyOwner {
        revert InvalidAction();
    }

    /// @notice Get the full salt used for account creation using WebAuthn.
    /// @param ownerX The x coordinate of the owner's public key.
    /// @param ownerY The y coordinate of the owner's public key.
    /// @param salt The salt to use for the account creation.
    /// @param entityId The entity ID to use for the account creation.
    /// @return The full salt.
    function getSaltWebAuthn(uint256 ownerX, uint256 ownerY, uint256 salt, uint32 entityId)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(ownerX, ownerY, salt, entityId));
    }
}
