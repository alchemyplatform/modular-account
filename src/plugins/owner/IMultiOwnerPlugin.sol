// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {UserOperation} from "../../interfaces/erc4337/UserOperation.sol";

interface IMultiOwnerPlugin {
    enum FunctionId {
        RUNTIME_VALIDATION_OWNER_OR_SELF, // require owner or self access
        USER_OP_VALIDATION_OWNER // require owner access

    }

    /// @notice This event is emitted when owners of the account are updated.
    /// @param account The account whose ownership changed.
    /// @param addedOwners The address array of added owners.
    /// @param removedOwners The address array of removed owners.
    event OwnerUpdated(address indexed account, address[] addedOwners, address[] removedOwners);

    error InvalidOwner(address owner);
    error EmptyOwnersNotAllowed();
    error NotAuthorized();
    error OwnerDoesNotExist(address owner);

    /// @notice Update owners of the account. Owners can update owners.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @param ownersToAdd The address array of owners to be added.
    /// @param ownersToRemove The address array of owners to be removed.
    function updateOwners(address[] memory ownersToAdd, address[] memory ownersToRemove) external;

    /// @notice Gets the EIP712 domain
    /// @dev This implementation is different from typical 712 via its use of msg.sender instead. As such, it
    /// should only be called from the SCAs that has installed this. See ERC-5267.
    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        );

    /// @notice Check if an address is an owner of `account`.
    /// @param account The account to check.
    /// @param ownerToCheck The owner to check if it is an owner of the provided account.
    /// @return True if the address is an owner of the account.
    function isOwnerOf(address account, address ownerToCheck) external view returns (bool);

    /// @notice Get the owners of `account`.
    /// @param account The account to get the owners of.
    /// @return The addresses of the owners of the account.
    function ownersOf(address account) external view returns (address[] memory);

    /// @notice Returns the pre-image of the message hash
    /// @dev Assumes that the SCA's implementation of `domainSeparator` is this plugin's
    /// @param account SCA to build the message encoding for
    /// @param message Message that should be encoded.
    /// @return Encoded message.
    function encodeMessageData(address account, bytes memory message) external view returns (bytes memory);

    /// @notice Returns hash of a message that can be signed by owners.
    /// @param account SCA to build the message hash for
    /// @param message Message that should be hashed.
    /// @return Message hash.
    function getMessageHash(address account, bytes memory message) external view returns (bytes32);
}
