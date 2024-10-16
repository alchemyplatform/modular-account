// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {SemiModularAccountBase} from "./SemiModularAccountBase.sol";

/// @title SemiModularAccountStorageOnly
/// @author Alchemy
///
/// @notice An implementation of a semi-modular account which includes an initializer to set the fallback signer in
/// storage upon initialization.
///
/// @dev Inherits SemiModularAccountBase. Note that the initializer has no access control and should be called via `upgradeToAndCall()`.
/// Use the `SemiModularAccountBytecode` instead for new accounts, this implementation should only be used for
/// account upgrades.
contract SemiModularAccountStorageOnly is SemiModularAccountBase {
    constructor(IEntryPoint anEntryPoint) SemiModularAccountBase(anEntryPoint) {}

    function initialize(address initialSigner) external initializer {
        SemiModularAccountStorage storage smaStorage = _getSemiModularAccountStorage();

        smaStorage.fallbackSigner = initialSigner;
        smaStorage.fallbackSignerDisabled = false;

        emit FallbackSignerUpdated(initialSigner, false);
    }

    /// @inheritdoc IModularAccount
    function accountId() external pure override returns (string memory) {
        return "alchemy.sma-storage.1.0.0";
    }
}
