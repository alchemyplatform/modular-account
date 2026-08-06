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
    /// @notice Also accepts canonical bare 64- or 65-byte ECDSA signatures from the delegating EOA while raw mode
    /// is active.
    /// @dev Bare signatures cover `hash` directly and are not replay-safe wrapped. See
    /// `doc/SMA7702-Raw-ERC1271-Signatures.md` for activation and integration behavior.
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

    /// @dev Returns whether canonical ECDSA recovery over `digest` equals the delegating EOA (`address(this)`).
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
