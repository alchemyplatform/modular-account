// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {IAccount} from "@eth-infinitism/account-abstraction/interfaces/IAccount.sol";
import {IAggregator} from "@eth-infinitism/account-abstraction/interfaces/IAggregator.sol";
import {IPaymaster} from "@eth-infinitism/account-abstraction/interfaces/IPaymaster.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {IExecutionModule} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModularAccountView} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";

/// @dev Library to help to check if a selector is a know function selector of the modular account or ERC-4337
/// contract.
library KnownSelectorsLib {
    function isNativeFunction(bytes4 selector) internal pure returns (bool) {
        return
        // check against IAccount methods
        selector == IAccount.validateUserOp.selector
        // check against IModularAccount methods
        || selector == IModularAccount.installExecution.selector
            || selector == IModularAccount.uninstallExecution.selector
            || selector == IModularAccount.installValidation.selector
            || selector == IModularAccount.uninstallValidation.selector || selector == IModularAccount.execute.selector
            || selector == IModularAccount.executeBatch.selector
            || selector == IModularAccount.executeWithAuthorization.selector
            || selector == IModularAccount.accountId.selector
        // check against IERC165 methods
        || selector == IERC165.supportsInterface.selector
        // check against UUPSUpgradeable methods
        || selector == UUPSUpgradeable.proxiableUUID.selector
            || selector == UUPSUpgradeable.upgradeToAndCall.selector
        // check against IModularAccountView methods
        || selector == IModularAccountView.getExecutionData.selector
            || selector == IModularAccountView.getValidationData.selector;
    }

    function isErc4337Function(bytes4 selector) internal pure returns (bool) {
        return selector == IAggregator.validateSignatures.selector
            || selector == IAggregator.validateUserOpSignature.selector
            || selector == IAggregator.aggregateSignatures.selector
            || selector == IPaymaster.validatePaymasterUserOp.selector || selector == IPaymaster.postOp.selector;
    }

    function isIModuleFunction(bytes4 selector) internal pure returns (bool) {
        return selector == IModule.onInstall.selector || selector == IModule.onUninstall.selector
            || selector == IModule.moduleId.selector || selector == IExecutionModule.executionManifest.selector
            || selector == IExecutionHookModule.preExecutionHook.selector
            || selector == IExecutionHookModule.postExecutionHook.selector
            || selector == IValidationModule.validateUserOp.selector
            || selector == IValidationModule.validateRuntime.selector
            || selector == IValidationModule.validateSignature.selector
            || selector == IValidationHookModule.preUserOpValidationHook.selector
            || selector == IValidationHookModule.preRuntimeValidationHook.selector;
    }
}
