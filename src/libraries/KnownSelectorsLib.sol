// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {IExecutionModule} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModularAccountView} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {IAccount} from "@eth-infinitism/account-abstraction/interfaces/IAccount.sol";
import {IAggregator} from "@eth-infinitism/account-abstraction/interfaces/IAggregator.sol";
import {IPaymaster} from "@eth-infinitism/account-abstraction/interfaces/IPaymaster.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {ModularAccountBase} from "../account/ModularAccountBase.sol";

/// @dev Library to help to check if a selector is a know function selector of the modular account or ERC-4337
/// contract.
library KnownSelectorsLib {
    function isNativeFunction(uint32 selector) external pure returns (bool) {
        return
        // check against IAccount methods
        selector == uint32(IAccount.validateUserOp.selector)
        // check against IModularAccount methods
        || selector == uint32(IModularAccount.installExecution.selector)
            || selector == uint32(IModularAccount.uninstallExecution.selector)
            || selector == uint32(IModularAccount.installValidation.selector)
            || selector == uint32(IModularAccount.uninstallValidation.selector)
            || selector == uint32(IModularAccount.execute.selector)
            || selector == uint32(IModularAccount.executeBatch.selector)
            || selector == uint32(IModularAccount.executeWithRuntimeValidation.selector)
            || selector == uint32(IModularAccount.accountId.selector)
        // check against IERC165 methods
        || selector == uint32(IERC165.supportsInterface.selector)
        // check against UUPSUpgradeable methods
        || selector == uint32(UUPSUpgradeable.proxiableUUID.selector)
            || selector == uint32(UUPSUpgradeable.upgradeToAndCall.selector)
        // check against IModularAccountView methods
        || selector == uint32(IModularAccountView.getExecutionData.selector)
            || selector == uint32(IModularAccountView.getValidationData.selector)
        // check against ModularAccount methods
        || selector == uint32(ModularAccountBase.performCreate.selector);
    }

    function isErc4337Function(uint32 selector) internal pure returns (bool) {
        return selector == uint32(IAggregator.validateSignatures.selector)
            || selector == uint32(IAggregator.validateUserOpSignature.selector)
            || selector == uint32(IAggregator.aggregateSignatures.selector)
            || selector == uint32(IPaymaster.validatePaymasterUserOp.selector)
            || selector == uint32(IPaymaster.postOp.selector);
    }

    function isIModuleFunction(uint32 selector) internal pure returns (bool) {
        return selector == uint32(IModule.onInstall.selector) || selector == uint32(IModule.onUninstall.selector)
            || selector == uint32(IModule.moduleId.selector)
            || selector == uint32(IExecutionModule.executionManifest.selector)
            || selector == uint32(IExecutionHookModule.preExecutionHook.selector)
            || selector == uint32(IExecutionHookModule.postExecutionHook.selector)
            || selector == uint32(IValidationModule.validateUserOp.selector)
            || selector == uint32(IValidationModule.validateRuntime.selector)
            || selector == uint32(IValidationModule.validateSignature.selector)
            || selector == uint32(IValidationHookModule.preUserOpValidationHook.selector)
            || selector == uint32(IValidationHookModule.preRuntimeValidationHook.selector);
    }
}
