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

pragma solidity ^0.8.26;

import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {ReplaySafeWrapper} from "@erc6900/reference-implementation/modules/ReplaySafeWrapper.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {WebAuthn} from "webauthn-sol/src/WebAuthn.sol";

import {ModuleBase} from "../ModuleBase.sol";

/// @title WebAuthn Validation Module
/// @author Alchemy
/// @dev Implementation referenced from WebAuthn + Coinbase Smart Wallet developed by Base.
/// @notice This validation module enables WebAuthn (secp256r1 curve) signature validation.
/// NOTE:
/// - Uninstallation will NOT disable all installed entity IDs of an account. It only uninstalls the entity ID that
///   is passed in. Account must remove access for each entity ID if want to disable all.
/// - None of the functions are installed on the account. Account states are to be retrieved from this global
///   singleton directly.
/// - This validation supports ERC-1271. The signature is valid if it is signed by the owner's private key.
/// - This validation supports composition that other validation can relay on entities in this validation to
///   validate partially or fully.
contract WebAuthnValidationModule is IValidationModule, ReplaySafeWrapper, ModuleBase {
    using MessageHashUtils for bytes32;
    using WebAuthn for WebAuthn.WebAuthnAuth;

    struct PubKey {
        uint256 x;
        uint256 y;
    }

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant _1271_INVALID = 0xffffffff;

    mapping(uint32 entityId => mapping(address account => PubKey)) public signers;

    /// @notice This event is emitted when signer of the account's validation changes.
    /// @param account The account whose validation signer changed.
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
    function transferSigner(uint32 entityId, uint256 x, uint256 y) external {
        _transferSigner(entityId, x, y);
    }

    /// @inheritdoc IModule
    function onInstall(bytes calldata data) external override {
        (uint32 entityId, uint256 x, uint256 y) = abi.decode(data, (uint32, uint256, uint256));
        _transferSigner(entityId, x, y);
    }

    /// @inheritdoc IModule
    function onUninstall(bytes calldata data) external override {
        uint32 entityId = abi.decode(data, (uint32));
        _transferSigner(entityId, 0, 0);
    }

    /// @inheritdoc IValidationModule
    function validateUserOp(uint32 entityId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        if (_validateSignature(entityId, userOp.sender, userOpHash.toEthSignedMessageHash(), userOp.signature)) {
            return _SIG_VALIDATION_PASSED;
        }

        return _SIG_VALIDATION_FAILED;
    }

    /// @inheritdoc IValidationModule
    /// @dev The signature is valid if it is signed by the owner's private key
    /// (if the owner is an EOA) or if it is a valid ERC-1271 signature from the
    /// owner (if the owner is a contract).
    /// Note that the digest is wrapped in an EIP-712 struct to prevent cross-account replay attacks. The
    /// replay-safe hash may be retrieved by calling the public function `replaySafeHash`.
    function validateSignature(address account, uint32 entityId, address, bytes32 digest, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        bytes32 _replaySafeHash = replaySafeHash(account, digest);
        if (_validateSignature(entityId, account, _replaySafeHash, signature)) {
            return _1271_MAGIC_VALUE;
        }
        return _1271_INVALID;
    }

    /// @inheritdoc IValidationModule
    function validateRuntime(address, uint32, address, uint256, bytes calldata, bytes calldata)
        external
        pure
        override
    {
        revert NotAuthorized();
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Module interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IModule
    function moduleId() external pure returns (string memory) {
        return "alchemy.webauthn-validation-module.1.0.0";
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ModuleBase, IERC165)
        returns (bool)
    {
        return (interfaceId == type(IValidationModule).interfaceId || super.supportsInterface(interfaceId));
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Internal / Private functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function _transferSigner(uint32 entityId, uint256 newX, uint256 newY) internal {
        PubKey memory oldPubKey = signers[entityId][msg.sender];
        signers[entityId][msg.sender] = PubKey(newX, newY);
        emit SignerTransferred(msg.sender, entityId, newX, newY, oldPubKey.x, oldPubKey.y);
    }

    function _validateSignature(uint32 entityId, address account, bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        WebAuthn.WebAuthnAuth memory webAuthnAuth = abi.decode(signature, (WebAuthn.WebAuthnAuth));
        PubKey storage key = signers[entityId][account];

        if (WebAuthn.verify(abi.encode(hash), false, webAuthnAuth, key.x, key.y)) {
            return true;
        }

        return false;
    }
}
