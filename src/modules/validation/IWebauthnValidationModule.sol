// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";

interface IWebauthnValidationModule is IValidationModule {
    /// @notice This event is emitted when Signer of the account's validation changes.
    /// @param account The account whose validation Signer changed.
    /// @param entityId The entityId for the account and the signer.
    /// @param newX X coordinate of the new signer.
    /// @param newY Y coordinate of the new signer.
    /// @param oldX X coordinate of the old signer.
    /// @param oldY Y coordinate of the old signer.
    event SignerTransferred(
        address indexed account,
        uint32 indexed entityId,
        uint256 indexed newX,
        uint256 indexed newY,
        uint256 oldX,
        uint256 oldY
    ) anonymous;

    error NotAuthorized();

    /// @notice Updates the signer for an entityId.
    /// @dev Used for key rotation or deleting a key
    /// @param entityId The entityId to update the signer for.
    /// @param x The x coordinate of the new signer.
    /// @param y The y coordinate of the new signer.
    function transferSigner(uint32 entityId, uint256 x, uint256 y) external;
}
