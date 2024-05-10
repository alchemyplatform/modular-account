// This file is part of Modular Account.
//
// Copyright 2024 Alchemy Insights, Inc.
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General
// Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.22;

import {UserOperation} from "modular-account-libs/interfaces/UserOperation.sol";
import {
    PluginManifest,
    ManifestExecutionHook,
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction
} from "modular-account-libs/interfaces/IPlugin.sol";

import {BaseTestPlugin} from "./BaseTestPlugin.sol";

// Used in conjunction with AccountStatePhasesTest to verify that the account state is consistent when plugins are
// updated mid-execution.
contract AccountStateMutatingPlugin is BaseTestPlugin {
    enum FunctionId {
        PRE_USER_OP_VALIDATION_HOOK,
        USER_OP_VALIDATION,
        PRE_RUNTIME_VALIDATION_HOOK,
        RUNTIME_VALIDATION,
        PRE_EXECUTION_HOOK,
        EXECUTION_FUNCTION, // Not actually used as a function id in the manifest, just makes it easier to write
            // the callback setter
        POST_EXECUTION_HOOK
    }

    bool hasUOValidation;
    bool hasPreUOValidation;
    bool hasRTValidation;
    bool hasPreRTValidation;
    bool hasPreExec;
    bool hasPostExec;

    bytes UOValidationCallback;
    bytes preUOValidationCallback;
    bytes RTValidationCallback;
    bytes preRTValidationCallback;
    bytes preExecCallback;
    bytes execCallback;
    bytes postExecCallback;

    // Specify what functions should be added when this is installed.
    function configureInstall(
        bool setUOValidation,
        bool setPreUOValidation,
        bool setRTValidation,
        bool setPreRTValidation,
        bool setPreExec,
        bool setPostExec
    ) public {
        hasUOValidation = setUOValidation;
        hasPreUOValidation = setPreUOValidation;
        hasRTValidation = setRTValidation;
        hasPreRTValidation = setPreRTValidation;
        hasPreExec = setPreExec;
        hasPostExec = setPostExec;
    }

    function setCallback(bytes calldata callback, FunctionId where) external {
        if (where == FunctionId.PRE_USER_OP_VALIDATION_HOOK) {
            preUOValidationCallback = callback;
        } else if (where == FunctionId.USER_OP_VALIDATION) {
            UOValidationCallback = callback;
        } else if (where == FunctionId.PRE_RUNTIME_VALIDATION_HOOK) {
            preRTValidationCallback = callback;
        } else if (where == FunctionId.RUNTIME_VALIDATION) {
            RTValidationCallback = callback;
        } else if (where == FunctionId.PRE_EXECUTION_HOOK) {
            preExecCallback = callback;
        } else if (where == FunctionId.EXECUTION_FUNCTION) {
            execCallback = callback;
        } else if (where == FunctionId.POST_EXECUTION_HOOK) {
            postExecCallback = callback;
        } else {
            revert NotImplemented(msg.sig, uint8(where));
        }
    }

    function pluginManifest() external pure override returns (PluginManifest memory) {
        return _castToPure(_getManifest)();
    }

    function _castToPure(function() internal view returns (PluginManifest memory) fnIn)
        internal
        pure
        returns (function() internal pure returns (PluginManifest memory) fnOut)
    {
        assembly {
            fnOut := fnIn
        }
    }

    function _getManifest() internal view returns (PluginManifest memory) {
        PluginManifest memory m;

        // Always add the execution function
        m.executionFunctions = new bytes4[](1);
        m.executionFunctions[0] = this.executionFunction.selector;

        // Conditionally add the other functions

        if (hasPreUOValidation) {
            m.preUserOpValidationHooks = new ManifestAssociatedFunction[](1);
            m.preUserOpValidationHooks[0] = ManifestAssociatedFunction({
                executionSelector: this.executionFunction.selector,
                associatedFunction: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.SELF,
                    functionId: uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK),
                    dependencyIndex: 0 // Unused
                })
            });
        }

        if (hasUOValidation) {
            m.userOpValidationFunctions = new ManifestAssociatedFunction[](1);
            m.userOpValidationFunctions[0] = ManifestAssociatedFunction({
                executionSelector: this.executionFunction.selector,
                associatedFunction: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.SELF,
                    functionId: uint8(FunctionId.USER_OP_VALIDATION),
                    dependencyIndex: 0 // Unused
                })
            });
        }

        if (hasPreRTValidation) {
            m.preRuntimeValidationHooks = new ManifestAssociatedFunction[](1);
            m.preRuntimeValidationHooks[0] = ManifestAssociatedFunction({
                executionSelector: this.executionFunction.selector,
                associatedFunction: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.SELF,
                    functionId: uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK),
                    dependencyIndex: 0 // Unused
                })
            });
        }

        if (hasRTValidation) {
            m.runtimeValidationFunctions = new ManifestAssociatedFunction[](1);
            m.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
                executionSelector: this.executionFunction.selector,
                associatedFunction: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.SELF,
                    functionId: uint8(FunctionId.RUNTIME_VALIDATION),
                    dependencyIndex: 0 // Unused
                })
            });
        }

        if (hasPreExec && hasPostExec) {
            m.executionHooks = new ManifestExecutionHook[](1);
            m.executionHooks[0] = ManifestExecutionHook({
                executionSelector: this.executionFunction.selector,
                preExecHook: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.SELF,
                    functionId: uint8(FunctionId.PRE_EXECUTION_HOOK),
                    dependencyIndex: 0 // Unused
                }),
                postExecHook: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.SELF,
                    functionId: uint8(FunctionId.POST_EXECUTION_HOOK),
                    dependencyIndex: 0 // Unused
                })
            });
        } else if (hasPreExec) {
            m.executionHooks = new ManifestExecutionHook[](1);
            m.executionHooks[0] = ManifestExecutionHook({
                executionSelector: this.executionFunction.selector,
                preExecHook: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.SELF,
                    functionId: uint8(FunctionId.PRE_EXECUTION_HOOK),
                    dependencyIndex: 0 // Unused
                }),
                postExecHook: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.NONE,
                    functionId: 0, // Unused
                    dependencyIndex: 0 // Unused
                })
            });
        } else if (hasPostExec) {
            m.executionHooks = new ManifestExecutionHook[](1);
            m.executionHooks[0] = ManifestExecutionHook({
                executionSelector: this.executionFunction.selector,
                preExecHook: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.NONE,
                    functionId: 0, // Unused
                    dependencyIndex: 0 // Unused
                }),
                postExecHook: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.SELF,
                    functionId: uint8(FunctionId.POST_EXECUTION_HOOK),
                    dependencyIndex: 0 // Unused
                })
            });
        }

        return m;
    }

    // Empty implementations of install/uninstall

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    // Plugin functions

    function preUserOpValidationHook(uint8 functionId, UserOperation calldata, bytes32)
        external
        override
        returns (uint256)
    {
        if (functionId == uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK)) {
            _performCallbackIfNonempty(preUOValidationCallback);
            return 0;
        }
        revert NotImplemented(msg.sig, functionId);
    }

    function userOpValidationFunction(uint8 functionId, UserOperation calldata, bytes32)
        external
        override
        returns (uint256)
    {
        if (functionId == uint8(FunctionId.USER_OP_VALIDATION)) {
            _performCallbackIfNonempty(UOValidationCallback);
            return 0;
        }
        revert NotImplemented(msg.sig, functionId);
    }

    function preRuntimeValidationHook(uint8 functionId, address, uint256, bytes calldata) external override {
        if (functionId == uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK)) {
            _performCallbackIfNonempty(preRTValidationCallback);
            return;
        }
        revert NotImplemented(msg.sig, functionId);
    }

    function runtimeValidationFunction(uint8 functionId, address, uint256, bytes calldata) external override {
        if (functionId == uint8(FunctionId.RUNTIME_VALIDATION)) {
            _performCallbackIfNonempty(RTValidationCallback);
            return;
        }
        revert NotImplemented(msg.sig, functionId);
    }

    function preExecutionHook(uint8 functionId, address, uint256, bytes calldata)
        external
        override
        returns (bytes memory)
    {
        if (functionId == uint8(FunctionId.PRE_EXECUTION_HOOK)) {
            _performCallbackIfNonempty(preExecCallback);
            return "";
        }
        revert NotImplemented(msg.sig, functionId);
    }

    function executionFunction() external {
        _performCallbackIfNonempty(execCallback);
    }

    function postExecutionHook(uint8 functionId, bytes calldata) external override {
        if (functionId == uint8(FunctionId.POST_EXECUTION_HOOK)) {
            _performCallbackIfNonempty(postExecCallback);
            return;
        }
        revert NotImplemented(msg.sig, functionId);
    }

    function _performCallbackIfNonempty(bytes storage callback) internal {
        if (callback.length > 0) {
            (bool success,) = msg.sender.call(callback);
            require(success, "Callback failed");
        }
    }
}
