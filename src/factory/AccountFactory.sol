// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {LibClone} from "solady/utils/LibClone.sol";

import {ModularAccount} from "../account/ModularAccount.sol";
import {SemiModularAccountBytecode} from "../account/SemiModularAccountBytecode.sol";

/// @title Account Factory
/// @author Alchemy
/// @notice Factory contract to deploy modular accounts. Allows creation of both modular and semi-modular accounts
/// (the bytecode variant).
contract AccountFactory is Ownable {
    ModularAccount public immutable ACCOUNT_IMPL;
    SemiModularAccountBytecode public immutable SEMI_MODULAR_ACCOUNT_IMPL;
    IEntryPoint public immutable ENTRY_POINT;
    address public immutable SINGLE_SIGNER_VALIDATION_MODULE;
    address public immutable WEBAUTHN_VALIDATION_MODULE;

    event ModularAccountDeployed(address indexed account, address indexed owner, uint256 salt);
    event SemiModularAccountDeployed(address indexed account, address indexed owner, uint256 salt);
    event WebAuthnModularAccountDeployed(
        address indexed account, uint256 indexed ownerX, uint256 indexed ownerY, uint256 salt
    );

    error TransferFailed();

    constructor(
        IEntryPoint _entryPoint,
        ModularAccount _accountImpl,
        SemiModularAccountBytecode _semiModularImpl,
        address _singleSignerValidationModule,
        address _webAuthnValidationModule,
        address owner
    ) Ownable(owner) {
        ENTRY_POINT = _entryPoint;
        ACCOUNT_IMPL = _accountImpl;
        SEMI_MODULAR_ACCOUNT_IMPL = _semiModularImpl;
        SINGLE_SIGNER_VALIDATION_MODULE = _singleSignerValidationModule;
        WEBAUTHN_VALIDATION_MODULE = _webAuthnValidationModule;
    }

    /// @notice Create an account with the single singer validation module installed, and return its address.
    /// @dev Returns the address even if the account is already deployed.
    /// Note that during user operation execution, this method is called only if the account is not deployed.
    /// This method returns an existing account address so that entryPoint.getSenderAddress() would work even after
    /// account creation.
    /// @param owner The owner of the account.
    /// @param salt The salt to use for the account creation.
    /// @param entityId The entity ID to use for the account creation.
    /// @return The address of the created account.
    function createAccount(address owner, uint256 salt, uint32 entityId) external returns (ModularAccount) {
        bytes32 combinedSalt = getSalt(owner, salt, entityId);

        // LibClone short-circuits if it's already deployed.
        (bool alreadyDeployed, address instance) =
            LibClone.createDeterministicERC1967(address(ACCOUNT_IMPL), combinedSalt);

        // short circuit if exists
        if (!alreadyDeployed) {
            bytes memory moduleInstallData = abi.encode(entityId, owner);
            // point proxy to actual implementation and init plugins
            ModularAccount(payable(instance)).initializeWithValidation(
                ValidationConfigLib.pack(SINGLE_SIGNER_VALIDATION_MODULE, entityId, true, true, true),
                new bytes4[](0),
                moduleInstallData,
                new bytes[](0)
            );
            emit ModularAccountDeployed(instance, owner, salt);
        }

        return ModularAccount(payable(instance));
    }

    /// @notice Create a semi-modular account and return its address.
    /// @dev This only ever deploys semi-modular accounts with added bytecode since this is much less
    /// expensive than the storage-only variant, which should only be used for upgrades.
    /// @param owner The owner of the account.
    /// @param salt The salt to use for the account creation.
    /// @return The address of the created account.
    function createSemiModularAccount(address owner, uint256 salt) external returns (SemiModularAccountBytecode) {
        // both module address and entityId for fallback validations are hardcoded at the maximum value.
        bytes32 fullSalt = getSalt(owner, salt, type(uint32).max);

        bytes memory immutables = _getImmutableArgs(owner);

        // LibClone short-circuits if it's already deployed.
        (bool alreadyDeployed, address instance) =
            LibClone.createDeterministicERC1967(address(SEMI_MODULAR_ACCOUNT_IMPL), immutables, fullSalt);

        if (!alreadyDeployed) {
            emit SemiModularAccountDeployed(instance, owner, salt);
        }

        return SemiModularAccountBytecode(payable(instance));
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
            ModularAccount(payable(instance)).initializeWithValidation(
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

    /// @notice Calculate the counterfactual address of this account as it would be returned by createAccount.
    /// @param owner The owner of the account.
    /// @param salt The salt to use for the account creation.
    /// @param entityId The entity ID to use for the account creation.
    /// @return The address of the account.
    function getAddress(address owner, uint256 salt, uint32 entityId) external view returns (address) {
        return LibClone.predictDeterministicAddressERC1967(
            address(ACCOUNT_IMPL), getSalt(owner, salt, entityId), address(this)
        );
    }

    /// @notice Calculate the counterfactual address of a semi-modular account as it would be returned by
    /// createSemiModularAccount.
    /// @param owner The owner of the account.
    /// @param salt The salt to use for the account creation.
    /// @return The address of the account.
    function getAddressSemiModular(address owner, uint256 salt) public view returns (address) {
        bytes32 fullSalt = getSalt(owner, salt, type(uint32).max);
        bytes memory immutables = _getImmutableArgs(owner);
        return _getAddressSemiModular(immutables, fullSalt);
    }

    /// @notice Calculate the counterfactual address of a webauthn account as it would be returned by
    /// createWebAuthnAccount.
    /// @param ownerX The x coordinate of the owner's public key.
    /// @param ownerY The y coordinate of the owner's public key.
    /// @param salt The salt to use for the account creation.
    /// @param entityId The entity ID to use for the account creation.
    /// @return The address of the account.
    function getAddressWebAuthn(uint256 ownerX, uint256 ownerY, uint256 salt, uint32 entityId)
        public
        view
        returns (address)
    {
        return LibClone.predictDeterministicAddressERC1967(
            address(ACCOUNT_IMPL), getSaltWebAuthn(ownerX, ownerY, salt, entityId), address(this)
        );
    }

    /// @notice Get the full salt used for account creation.
    /// @dev To get the full salt used in createSemiModularAccount, use type(uint32).max for entityId.
    /// @param owner The owner of the account.
    /// @param salt The salt to use for the account creation.
    /// @param entityId The entity ID to use for the account creation.
    /// @return The full salt.
    function getSalt(address owner, uint256 salt, uint32 entityId) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(owner, salt, entityId));
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

    function _getAddressSemiModular(bytes memory immutables, bytes32 salt) internal view returns (address) {
        return LibClone.predictDeterministicAddressERC1967(
            address(SEMI_MODULAR_ACCOUNT_IMPL), immutables, salt, address(this)
        );
    }

    function _getImmutableArgs(address owner) private pure returns (bytes memory) {
        return abi.encodePacked(owner);
    }
}
