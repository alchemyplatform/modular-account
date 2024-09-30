// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";

interface IAddressValidationModule is IValidationModule {
    /// @notice This event is emitted when Signer of the account's validation changes.
    /// @param account The account whose validation Signer changed.
    /// @param entityId The entityId for the account and the signer.
    /// @param newOwner The address of the new owner.
    /// @param previousOwner The address of the previous owner.
    event SignerTransferred(
        address indexed account, uint32 indexed entityId, address indexed newOwner, address previousOwner
    ) anonymous;

    error NotAuthorized();

    /// @notice Transfer Signer of the account's validation to `newSigner`.
    /// @param entityId The entityId for the account and the signer.
    /// @param newOwner The address of the new signer.
    function transferSigner(uint32 entityId, address newOwner) external;
}
