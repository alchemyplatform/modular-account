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

import {ExecutionInstallDelegate} from "../helpers/ExecutionInstallDelegate.sol";
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
    /// Signatures of any other length are handled by the standard encoding, which selects a validation function
    /// and applies replay-safe hashing. A bare ECDSA signature is not self-describing, so these two lengths are
    /// reserved for this path. No signature accepted by the standard encoding is 64 or 65 bytes long, as that
    /// encoding adds at least 6 bytes of overhead on top of the inner signature.
    function isValidSignature(bytes32 hash, bytes calldata signature) public view override returns (bytes4) {
        if (signature.length == _ECDSA_SIGNATURE_LENGTH || signature.length == _ECDSA_COMPACT_SIGNATURE_LENGTH) {
            return _isValidEOASignature(hash, signature) ? _1271_MAGIC_VALUE : _1271_INVALID;
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
    /// No replay-safe wrapping is applied, and none is needed: the recovered address is compared against
    /// address(this), which binds the signature to this account just as the replay-safe domain separator would.
    /// Replay across chains is a property of the EOA's key rather than of this account, and is unchanged by
    /// delegating.
    ///
    /// The EOA is only honored while it is still the account's active fallback signer, so the signers accepted
    /// here are a subset of those accepted by fallback validation - only the encoding and the hash wrapping
    /// differ. This path consequently skips any pre-signature-validation hooks installed on fallback validation.
    /// Those hooks were never a boundary against this key: an EOA delegated with EIP-7702 keeps the ability to
    /// sign ordinary transactions from its own address, which no hook can gate.
    function _isValidEOASignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        SemiModularAccountStorage storage _storage = _getSemiModularAccountStorage();

        if (_storage.fallbackSignerDisabled || _retrieveFallbackSignerUnchecked(_storage) != address(this)) {
            return false;
        }

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
