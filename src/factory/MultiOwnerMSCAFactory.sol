// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {IAccountInitializable} from "../interfaces/IAccountInitializable.sol";
import {IEntryPoint} from "../interfaces/erc4337/IEntryPoint.sol";
import {FactoryHelpers} from "../helpers/FactoryHelpers.sol";

/// @title Multi Owner Plugin MSCA (Modular Smart Contract Account) Factory
/// @author Alchemy
/// @notice Factory for upgradeable modular accounts with MultiOwnerPlugin installed.
/// @dev There is a reliance on the assumption that the plugin manifest will remain static, following ERC-6900. If
/// this assumption is broken then account deployments would be bricked.
contract MultiOwnerMSCAFactory is Ownable2Step {
    address public immutable MULTI_OWNER_PLUGIN;
    address public immutable IMPL;
    bytes32 internal immutable _MULTI_OWNER_PLUGIN_MANIFEST_HASH;
    IEntryPoint public immutable ENTRYPOINT;

    error OwnersArrayEmpty();
    error InvalidOwner();
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
    /// @dev The owner array must be sorted in ascending order. It cannot have 0 or duplicated addresses.
    /// @param salt salt for additional entropy for create2
    /// @param owners address array of the owners
    function createAccount(uint256 salt, address[] calldata owners) external returns (address addr) {
        if (!FactoryHelpers.validateOwnerArray(owners)) {
            revert InvalidOwner();
        }

        bytes[] memory pluginInitBytes = new bytes[](1);
        pluginInitBytes[0] = abi.encode(owners);

        bytes32 combinedSalt = FactoryHelpers.getSalt(salt, pluginInitBytes[0]);
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
    /// @dev can withdraw stuck erc20s
    /// @param to address to send native currency to
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
    /// @dev The owner array must be sorted in ascending order. It cannot have 0 or duplicated addresses.
    /// @param owners array of addresses of the owner
    function getAddress(uint256 salt, address[] calldata owners) external view returns (address) {
        // array can't be empty
        if (owners.length == 0) {
            revert OwnersArrayEmpty();
        }

        if (!FactoryHelpers.validateOwnerArray(owners)) {
            revert InvalidOwner();
        }

        return Create2.computeAddress(
            FactoryHelpers.getSalt(salt, abi.encode(owners)),
            keccak256(abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(IMPL, "")))
        );
    }
}
