// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {LibClone} from "solady/utils/LibClone.sol";

import {SemiModularAccountBase} from "./SemiModularAccountBase.sol";

/// @title SemiModularAccountBytecode
/// @author Alchemy
///
/// @notice An implementation of a semi-modular account with a fallback that reads the signer from proxy bytecode.
///
/// @dev This account requires that its proxy is compliant with Solady's LibClone ERC1967WithImmutableArgs
/// bytecode.
contract SemiModularAccountBytecode is SemiModularAccountBase {
    constructor(IEntryPoint anEntryPoint) SemiModularAccountBase(anEntryPoint) {}

    /// @inheritdoc IModularAccount
    function accountId() external pure override returns (string memory) {
        return "alchemy.sma-bytecode.1.0.0";
    }

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
