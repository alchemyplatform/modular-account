// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {UUPSUpgradeable} from "../../ext/UUPSUpgradeable.sol";

import {IAccount} from "../../src/interfaces/erc4337/IAccount.sol";
import {IAccountInitializable} from "../interfaces/IAccountInitializable.sol";
import {IAccountLoupe} from "../../src/interfaces/IAccountLoupe.sol";
import {IAccountView} from "../../src/interfaces/IAccountView.sol";
import {IAggregator} from "../../src/interfaces/erc4337/IAggregator.sol";
import {IPaymaster} from "../../src/interfaces/erc4337/IPaymaster.sol";
import {IPlugin} from "../interfaces/IPlugin.sol";
import {IPluginExecutor} from "../interfaces/IPluginExecutor.sol";
import {IPluginManager} from "../../src/interfaces/IPluginManager.sol";
import {IStandardExecutor} from "../interfaces/IStandardExecutor.sol";

/// @title Known Selectors
/// @author Alchemy
/// @notice Library to help to check if a selector is a know function selector of the modular account or ERC-4337
/// contract.
library KnownSelectors {
    function isNativeFunction(bytes4 selector) internal pure returns (bool) {
        return
        // check against IAccount methods
        selector == IAccount.validateUserOp.selector
        // check against IAccountView methods
        || selector == IAccountView.entryPoint.selector || selector == IAccountView.getNonce.selector
        // check against IPluginManager methods
        || selector == IPluginManager.installPlugin.selector || selector == IPluginManager.uninstallPlugin.selector
        // check against IERC165 methods
        || selector == IERC165.supportsInterface.selector
        // check against UUPSUpgradeable methods
        || selector == UUPSUpgradeable.proxiableUUID.selector
            || selector == UUPSUpgradeable.upgradeToAndCall.selector
        // check against IStandardExecutor methods
        || selector == IStandardExecutor.execute.selector || selector == IStandardExecutor.executeBatch.selector
        // check against IPluginExecutor methods
        || selector == IPluginExecutor.executeFromPlugin.selector
            || selector == IPluginExecutor.executeFromPluginExternal.selector
        // check against IAccountInitializable methods
        || selector == IAccountInitializable.initialize.selector
        // check against IAccountLoupe methods
        || selector == IAccountLoupe.getExecutionFunctionConfig.selector
            || selector == IAccountLoupe.getExecutionHooks.selector
            || selector == IAccountLoupe.getPermittedCallHooks.selector
            || selector == IAccountLoupe.getPreValidationHooks.selector
            || selector == IAccountLoupe.getInstalledPlugins.selector;
    }

    function isErc4337Function(bytes4 selector) internal pure returns (bool) {
        return selector == IAggregator.validateSignatures.selector
            || selector == IAggregator.validateUserOpSignature.selector
            || selector == IAggregator.aggregateSignatures.selector
            || selector == IPaymaster.validatePaymasterUserOp.selector || selector == IPaymaster.postOp.selector;
    }

    function isIPluginFunction(bytes4 selector) internal pure returns (bool) {
        return selector == IPlugin.onInstall.selector || selector == IPlugin.onUninstall.selector
            || selector == IPlugin.preUserOpValidationHook.selector
            || selector == IPlugin.userOpValidationFunction.selector
            || selector == IPlugin.preRuntimeValidationHook.selector
            || selector == IPlugin.runtimeValidationFunction.selector || selector == IPlugin.preExecutionHook.selector
            || selector == IPlugin.postExecutionHook.selector || selector == IPlugin.onHookApply.selector
            || selector == IPlugin.onHookUnapply.selector || selector == IPlugin.pluginManifest.selector
            || selector == IPlugin.pluginMetadata.selector;
    }
}
