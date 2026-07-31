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

import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {FALLBACK_VALIDATION_LOOKUP_KEY} from "../helpers/Constants.sol";
import {ExecutionInstallDelegate} from "../helpers/ExecutionInstallDelegate.sol";
import {getAccountStorage} from "./AccountStorage.sol";
import {SemiModularAccountBase} from "./SemiModularAccountBase.sol";

/// @title Semi-Modular Account for EIP-7702 EOAs
/// @author Alchemy
/// @notice An implementation of a semi-modular account which reads the signer as the address(this).
/// @dev Inherits SemiModularAccountBase. This account can be used as the delegate contract of an EOA with
/// EIP-7702, where address(this) (aka the EOA address) is the default fallback signer.
contract SemiModularAccount7702 is SemiModularAccountBase {
    // Length of a standard ECDSA signature, encoded as `abi.encodePacked(r, s, v)`.
    uint256 internal constant _ECDSA_SIGNATURE_LENGTH = 65;
    // Length of a compact ECDSA signature, encoded as `abi.encodePacked(r, vs)`. See ERC-2098.
    uint256 internal constant _ECDSA_COMPACT_SIGNATURE_LENGTH = 64;

    error UpgradeNotAllowed();

    constructor(IEntryPoint entryPoint, ExecutionInstallDelegate executionInstallDelegate)
        SemiModularAccountBase(entryPoint, executionInstallDelegate)
    {}

    /// @inheritdoc IModularAccount
    function accountId() external pure override returns (string memory) {
        return "alchemy.sma-7702.1.1.0";
    }

    function upgradeToAndCall(address, bytes calldata) public payable override {
        revert UpgradeNotAllowed();
    }

    /// @inheritdoc IERC1271
    /// @notice Validates an ERC-1271 signature, accepting bare ECDSA signatures from the delegating EOA in
    /// addition to the account's regular signature encoding.
    ///
    /// @dev With zero-valued account storage, raw mode is active by default. It remains active only while fallback
    /// signing is enabled and the resolved fallback signer is `address(this)`. Native `FALLBACK_VALIDATION` must
    /// also have no pre-validation hooks.
    ///
    /// While active, exact 64- and 65-byte inputs are reserved for bare ECDSA over `hash`; invalid signatures
    /// return the ERC-1271 failure value without reverting. All other inputs use standard modular validation.
    ///
    /// This bare dispatcher exists only in public ERC-1271 validation. Runtime, UserOperation, and deferred-action
    /// validation retain their existing encoding and digest rules. When native fallback resolves to
    /// `address(this)`, its `CONTRACT_OWNER` signature type is rejected; those paths must use `EOA`.
    ///
    /// Bare signatures are not wrapped in the account replay-safe domain. See the README section
    /// "SemiModularAccount7702 bare EOA signatures" for integration behavior, opt-outs, length collisions, and
    /// migration guidance.
    function isValidSignature(bytes32 hash, bytes calldata signature) public view override returns (bytes4) {
        if (signature.length == _ECDSA_SIGNATURE_LENGTH || signature.length == _ECDSA_COMPACT_SIGNATURE_LENGTH) {
            SemiModularAccountStorage storage _storage = _getSemiModularAccountStorage();

            if (
                !_storage.fallbackSignerDisabled && _retrieveFallbackSignerUnchecked(_storage) == address(this)
                    && getAccountStorage().validationStorage[FALLBACK_VALIDATION_LOOKUP_KEY].validationHookCount == 0
            ) {
                return _isValidEOASignature(hash, signature) ? _1271_MAGIC_VALUE : _1271_INVALID;
            }
        }

        return super.isValidSignature(hash, signature);
    }

    /// @dev If the fallback signer is set in storage, means the fallback signer has been updated. We ignore the
    /// address(this) EOA signer.
    function _retrieveFallbackSignerUnchecked(SemiModularAccountStorage storage _storage)
        internal
        view
        override
        returns (address)
    {
        address storageFallbackSigner = _storage.fallbackSigner;
        if (storageFallbackSigner != address(0)) {
            return storageFallbackSigner;
        }

        return address(this);
    }

    /// @dev Recovers a bare ECDSA signature over `digest` and checks it against the delegating EOA.
    ///
    /// No account-specific replay-safe wrapping is applied: the recovered address is compared against
    /// address(this), which binds the signature to this account address. The path has ordinary EOA semantics for
    /// digest binding and relies on the caller-provided digest for chain and protocol replay protection. Recovery
    /// is deliberately canonical: 65-byte signatures require low-s and v equal to 27 or 28, while 64-byte
    /// signatures use ERC-2098.
    ///
    /// The public ERC-1271 entry point only calls this helper while the EOA is still the active fallback signer
    /// and the native fallback validation has no associated pre-validation hooks. A bare signature has no
    /// encoding for per-hook data, so accepting it while hooks are installed would bypass any additional proof or
    /// policy they enforce.
    function _isValidEOASignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        bytes32 r = bytes32(signature[0:32]);
        bytes32 sOrVs = bytes32(signature[32:64]);

        address recovered;
        ECDSA.RecoverError err;

        if (signature.length == _ECDSA_SIGNATURE_LENGTH) {
            (recovered, err,) = ECDSA.tryRecover(digest, uint8(signature[64]), r, sOrVs);
        } else {
            (recovered, err,) = ECDSA.tryRecover(digest, r, sOrVs);
        }

        return err == ECDSA.RecoverError.NoError && recovered == address(this);
    }
}
