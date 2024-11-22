// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {
    IModularAccount, ValidationConfig
} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {ExecutionInstallDelegate} from "../helpers/ExecutionInstallDelegate.sol";
import {ModularAccountBase} from "./ModularAccountBase.sol";

/// @title Modular Account
/// @author Alchemy
/// @notice This contract allows initializing with a validation config (of a validation module) to be installed on
/// the account.
contract ModularAccount is ModularAccountBase {
    constructor(IEntryPoint entryPoint, ExecutionInstallDelegate executionInstallDelegate)
        ModularAccountBase(entryPoint, executionInstallDelegate)
    {}

    /// @notice Initializes the account with a validation function.
    /// @dev This function is only callable once.
    function initializeWithValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) external virtual initializer {
        _installValidation(validationConfig, selectors, installData, hooks);
    }

    /// @inheritdoc IModularAccount
    function accountId() external pure override returns (string memory) {
        return "alchemy.modular-account.2.0.0";
    }

    /// @dev Overrides ModularAccountView.
    function _isNativeFunction(uint32 selector) internal view override returns (bool) {
        return super._isNativeFunction(selector) || selector == uint32(this.initializeWithValidation.selector);
    }
}
