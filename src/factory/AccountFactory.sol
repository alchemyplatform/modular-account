// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {ModularAccount} from "../account/ModularAccount.sol";
import {SemiModularAccount} from "../account/SemiModularAccount.sol";
import {ValidationConfigLib} from "../libraries/ValidationConfigLib.sol";

import {LibClone} from "solady/utils/LibClone.sol";

contract AccountFactory is Ownable {
    ModularAccount public immutable ACCOUNT_IMPL;
    SemiModularAccount public immutable SEMI_MODULAR_ACCOUNT_IMPL;
    IEntryPoint public immutable ENTRY_POINT;
    address public immutable SINGLE_SIGNER_VALIDATION_MODULE;

    event ModularAccountDeployed(address indexed account, address indexed owner, uint256 salt);
    event SemiModularAccountDeployed(address indexed account, address indexed owner, uint256 salt);

    constructor(
        IEntryPoint _entryPoint,
        ModularAccount _accountImpl,
        SemiModularAccount _semiModularImpl,
        address _ecdsaValidationModule,
        address owner
    ) Ownable(owner) {
        ENTRY_POINT = _entryPoint;
        ACCOUNT_IMPL = _accountImpl;
        SEMI_MODULAR_ACCOUNT_IMPL = _semiModularImpl;
        SINGLE_SIGNER_VALIDATION_MODULE = _ecdsaValidationModule;
    }

    /**
     * Create an account, and return its address.
     * Returns the address even if the account is already deployed.
     * Note that during user operation execution, this method is called only if the account is not deployed.
     * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after
     * account creation
     */
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

    function createSemiModularAccount(address owner, uint256 salt) external returns (SemiModularAccount) {
        // both module address and entityId for fallback validations are hardcoded at the maximum value.
        bytes32 fullSalt = getSalt(owner, salt, type(uint32).max);

        bytes memory immutables = _getImmutableArgs(owner);

        // LibClone short-circuits if it's already deployed.
        (bool alreadyDeployed, address instance) =
            LibClone.createDeterministicERC1967(address(SEMI_MODULAR_ACCOUNT_IMPL), immutables, fullSalt);

        if (!alreadyDeployed) {
            emit SemiModularAccountDeployed(instance, owner, salt);
        }

        return SemiModularAccount(payable(instance));
    }

    function addStake(uint32 unstakeDelay) external payable onlyOwner {
        ENTRY_POINT.addStake{value: msg.value}(unstakeDelay);
    }

    function unlockStake() external onlyOwner {
        ENTRY_POINT.unlockStake();
    }

    function withdrawStake(address payable withdrawAddress) external onlyOwner {
        ENTRY_POINT.withdrawStake(withdrawAddress);
    }

    /**
     * Calculate the counterfactual address of this account as it would be returned by createAccount()
     */
    function getAddress(address owner, uint256 salt, uint32 entityId) external view returns (address) {
        return LibClone.predictDeterministicAddressERC1967(
            address(ACCOUNT_IMPL), getSalt(owner, salt, entityId), address(this)
        );
    }

    function getAddressSemiModular(address owner, uint256 salt) public view returns (address) {
        bytes32 fullSalt = getSalt(owner, salt, type(uint32).max);
        bytes memory immutables = _getImmutableArgs(owner);
        return _getAddressSemiModular(immutables, fullSalt);
    }

    function getSalt(address owner, uint256 salt, uint32 entityId) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(owner, salt, entityId));
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
