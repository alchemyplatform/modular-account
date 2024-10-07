// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.26;

import {ValidationConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {ModularAccountBase} from "./ModularAccountBase.sol";

contract ModularAccount is ModularAccountBase {
    constructor(IEntryPoint anEntryPoint) ModularAccountBase(anEntryPoint) {}

    /// @notice Initializes the account with a validation function added to the global pool.
    /// @dev This function is only callable once.
    function initializeWithValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) external virtual initializer {
        _installValidation(validationConfig, selectors, installData, hooks);
    }
}
