// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {LibClone} from "solady/utils/LibClone.sol";

import {SemiModularAccountBase} from "./SemiModularAccountBase.sol";

/// @title SemiModularAccountBytecode
/// @author Alchemy
///
/// @notice An implementation of a semi-modular account with a fallback that reads the signer from proxy bytecode.
///
/// @dev This account requires that its proxy is compliant with Solady's LibClone ERC1967WithImmutableArgs bytecode.
contract SemiModularAccountBytecode is SemiModularAccountBase {
    constructor(IEntryPoint anEntryPoint) SemiModularAccountBase(anEntryPoint) {}

    /// @dev If the fallback signer is set in storage, we ignore the bytecode signer.
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

        // If the signer in storage is zero, default to
        bytes memory appendedData = LibClone.argsOnERC1967(address(this), 0, 20);

        return address(uint160(bytes20(appendedData)));
    }
}
