// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {SemiModularAccountBase} from "./SemiModularAccountBase.sol";

contract SemiModularAccountStorage is SemiModularAccountBase {
    constructor(IEntryPoint anEntryPoint) SemiModularAccountBase(anEntryPoint) {}

    function initialize(address initialSigner) external initializer {
        _getSemiModularAccountStorage().fallbackSigner = initialSigner;

        // Note that it's technically possible for the fallback signer in storage to be nonzero before
        // initialization. However, reading it here would add costs in the vast majority of cases.
        emit FallbackSignerSet(address(0), initialSigner);
    }

    /// @dev If the fallback signer is set in storage, we ignore the bytecode signer.
    function _retrieveFallbackSignerUnchecked(SemiModularAccountStorage storage _storage)
        internal
        view
        override
        returns (address)
    {
        return _storage.fallbackSigner;
    }
}
