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

pragma solidity ^0.8.22;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {FactoryHelpers} from "../helpers/FactoryHelpers.sol";
import {IEntryPoint} from "../interfaces/erc4337/IEntryPoint.sol";
import {IAccountInitializable} from "../interfaces/IAccountInitializable.sol";

/// @title Multi Owner Plugin Modular Account Factory
/// @author Alchemy
/// @notice Factory for upgradeable modular accounts with MultiOwnerPlugin installed.
/// @dev There is a reliance on the assumption that the plugin manifest will remain static, following ERC-6900. If
/// this assumption is broken then account deployments would be bricked.
contract MultiOwnerModularAccountFactory is Ownable2Step {
    IEntryPoint public immutable ENTRYPOINT;
    address public immutable MULTI_OWNER_PLUGIN;
    address public immutable IMPL;
    bytes32 internal immutable _MULTI_OWNER_PLUGIN_MANIFEST_HASH;
    uint256 internal constant _MAX_OWNERS_ON_CREATION = 100;

    error InvalidAction();
    error InvalidOwner();
    error OwnersArrayEmpty();
    error OwnersLimitExceeded();
    error TransferFailed();

    /// @notice Constructor for the factory
    constructor(
        address owner,
        address multiOwnerPlugin,
        address implementation,
        bytes32 multiOwnerPluginManifestHash,
        IEntryPoint entryPoint
    ) {
        _transferOwnership(owner);
        MULTI_OWNER_PLUGIN = multiOwnerPlugin;
        IMPL = implementation;
        _MULTI_OWNER_PLUGIN_MANIFEST_HASH = multiOwnerPluginManifestHash;
        ENTRYPOINT = entryPoint;
    }

    /// @notice Allow contract to receive native currency
    receive() external payable {}

    /// @notice Create a modular smart contract account
    /// @dev Account address depends on salt, impl addr, plugins and plugin init data
    /// @dev The owner array must be in strictly ascending order and not include the 0 address.
    /// @param salt salt for create2
    /// @param owners address array of the owners
    function createAccount(uint256 salt, address[] calldata owners) external returns (address addr) {
        if (!FactoryHelpers.isValidOwnerArray(owners)) {
            revert InvalidOwner();
        }

        bytes[] memory pluginInitBytes = new bytes[](1);
        pluginInitBytes[0] = abi.encode(owners);

        bytes32 combinedSalt = FactoryHelpers.getCombinedSalt(salt, pluginInitBytes[0]);
        addr = Create2.computeAddress(
            combinedSalt, keccak256(abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(IMPL, "")))
        );

        // short circuit if exists
        if (addr.code.length == 0) {
            // not necessary to check return addr of this arg since next call fails if so
            new ERC1967Proxy{salt: combinedSalt}(IMPL, "");

            address[] memory plugins = new address[](1);
            plugins[0] = MULTI_OWNER_PLUGIN;

            bytes32[] memory manifestHashes = new bytes32[](1);
            manifestHashes[0] = _MULTI_OWNER_PLUGIN_MANIFEST_HASH;

            IAccountInitializable(addr).initialize(plugins, abi.encode(manifestHashes, pluginInitBytes));
        }
    }

    /// @notice Add stake to an entry point
    /// @dev only callable by owner
    /// @param unstakeDelay unstake delay for the stake
    /// @param amount amount of native currency to stake
    function addStake(uint32 unstakeDelay, uint256 amount) external payable onlyOwner {
        ENTRYPOINT.addStake{value: amount}(unstakeDelay);
    }

    /// @notice Start unlocking stake for an entry point
    /// @dev only callable by owner
    function unlockStake() external onlyOwner {
        ENTRYPOINT.unlockStake();
    }

    /// @notice Withdraw stake from an entry point
    /// @dev only callable by owner
    /// @param to address to send native currency to
    function withdrawStake(address payable to) external onlyOwner {
        ENTRYPOINT.withdrawStake(to);
    }

    /// @notice Withdraw funds from this contract
    /// @dev can withdraw stuck erc20s or native currency
    /// @param to address to send erc20s or native currency to
    /// @param token address of the token to withdraw, 0 address for native currency
    /// @param amount amount of the token to withdraw in case of rebasing tokens
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

    /// @notice Getter for counterfactual address based on input params
    /// @dev The owner array must be in strictly ascending order and not include the 0 address.
    /// @param salt salt for additional entropy for create2
    /// @param owners array of addresses of the owner
    /// @return address of counterfactual account
    function getAddress(uint256 salt, address[] calldata owners) external view returns (address) {
        // Array can't be empty.
        if (owners.length == 0) {
            revert OwnersArrayEmpty();
        }

        // This protects against counterfactuals being generated against an exceptionally large number of owners
        // that may exceed the block gas limit when actually creating the account.
        if (owners.length > _MAX_OWNERS_ON_CREATION) {
            revert OwnersLimitExceeded();
        }

        if (!FactoryHelpers.isValidOwnerArray(owners)) {
            revert InvalidOwner();
        }

        return Create2.computeAddress(
            FactoryHelpers.getCombinedSalt(salt, abi.encode(owners)),
            keccak256(abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(IMPL, "")))
        );
    }

    /// @notice Overriding to disable renounce ownership in Ownable
    function renounceOwnership() public view override onlyOwner {
        revert InvalidAction();
    }
}
