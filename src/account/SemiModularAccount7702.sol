// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {SemiModularAccountBase} from "./SemiModularAccountBase.sol";

/// @title Semi-Modular Account for EIP-7702 EOAs
/// @author Alchemy
/// @notice An implementation of a semi-modular account which reads the signer as the address(this).
/// @dev Inherits SemiModularAccountBase. This account can be used as the delegate contract of an EOA with
/// EIP-7702, where address(this) (aka the EOA address) is the default fallback signer.
contract SemiModularAccount7702 is SemiModularAccountBase {
    error UpgradeNotAllowed();

    constructor(IEntryPoint anEntryPoint) SemiModularAccountBase(anEntryPoint) {}

    /// @inheritdoc IModularAccount
    function accountId() external pure override returns (string memory) {
        return "alchemy.sma-7702.1.0.0";
    }

    function upgradeToAndCall(address, bytes calldata) public payable override {
        revert UpgradeNotAllowed();
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
}
