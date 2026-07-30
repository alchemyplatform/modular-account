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
    /// @dev Unlike the other account variants, this one is delegated to from an EOA that retains its private key.
    /// Contracts that route signature checks through ERC-1271 whenever the signer address has code - Permit2,
    /// OpenZeppelin's `SignatureChecker`, Seaport, and others - hand this account the plain 64- or 65-byte ECDSA
    /// signature that the EOA's wallet produced, with no knowledge that the address is delegated. Those
    /// signatures are accepted here directly over the unwrapped digest, so that delegating does not break flows
    /// which treat the address as the EOA it still is.
    ///
    /// Only this public ERC-1271 function adds length-based bare-signature dispatch. Runtime validation has no
    /// bare-signature form. UserOperation and deferred-action validation retain their existing outer framing and
    /// digest rules. When either path selects native `FALLBACK_VALIDATION`, its existing `CONTRACT_OWNER`
    /// signature
    /// type calls ERC-1271 on the resolved fallback signer. If that signer is `address(this)`, those paths can use
    /// a bare inner ECDSA signature transitively. UserOperations retain selector checks and pre-validation hooks;
    /// deferred actions retain selector checks and reject validations with pre-validation hooks. The fallback
    /// enabled/signer checks and each path's original digest still apply.
    ///
    /// The raw path is active only while the EOA is the enabled fallback signer and the reserved native
    /// `FALLBACK_VALIDATION` has no associated pre-validation hooks. Such a hook is therefore the composable
    /// opt-out when the account should retain its EOA fallback but require the standard signature pipeline.
    /// Calling `uninstallValidation` for `FALLBACK_VALIDATION` does not remove the built-in fallback or alter its
    /// signer state. It clears the flags, selectors, and all hooks stored under that key. Removing all
    /// pre-validation hooks makes raw mode eligible again only if the signer is enabled and resolves to
    /// `address(this)`.
    ///
    /// Execution hooks, hooks on a direct-call or different validation key, and the native fallback validation's
    /// flags do not control raw mode. A zero stored signer resolves to `address(this)` in this implementation; the
    /// disabled flag is what turns fallback signing off.
    ///
    /// Other ERC-1271 signatures use the standard encoding, which selects a validation function and runs its
    /// configured hooks. Native fallback validation applies the account replay-safe hash; installed modules
    /// define their own hashing. A bare ECDSA signature is not self-describing, so while raw mode is active, these
    /// two total outer lengths are reserved exclusively for this path. Module signatures have variable length, so
    /// standard-encoded signatures must avoid totaling 64 or 65 bytes in that configuration. When raw mode is
    /// inactive, signatures of either length fall through to standard signature validation, including its
    /// existing revert behavior for malformed modular encodings.
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
    /// address(this), which binds the signature to this account. The path otherwise has ordinary EOA signature
    /// semantics and relies on the caller-provided digest for chain and protocol replay protection.
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
