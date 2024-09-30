// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {SemiModularAccountBase} from "./SemiModularAccountBase.sol";

/// @title SemiModularAccountStorage
/// @author Alchemy
///
/// @notice A basic Semi-Modular Account with an initializer to set the fallback signer in storage.
///
/// @dev Note that the initializer has no access control and should be called via `upgradeToAndCall()`.
/// It's recommended to opt for the variant `SemiModularAccountBytecode` instead for new accounts.
contract SemiModularAccountStorage is SemiModularAccountBase {
    constructor(IEntryPoint anEntryPoint) SemiModularAccountBase(anEntryPoint) {}

    function initialize(address initialSigner) external initializer {
        _getSemiModularAccountStorage().fallbackSigner = initialSigner;

        // Note that it's technically possible for the fallback signer in storage to be nonzero before
        // initialization. However, reading it here would add costs in the vast majority of cases.
        emit FallbackSignerSet(address(0), initialSigner);
    }
}
