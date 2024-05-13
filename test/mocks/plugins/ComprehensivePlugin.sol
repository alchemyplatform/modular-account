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
    ManifestExecutionHook,
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    PluginMetadata
} from "modular-account-libs/interfaces/IPlugin.sol";
import {IStandardExecutor} from "modular-account-libs/interfaces/IStandardExecutor.sol";

import {BaseTestPlugin} from "./BaseTestPlugin.sol";

contract ComprehensivePlugin is BaseTestPlugin {
    enum FunctionId {
        PRE_USER_OP_VALIDATION_HOOK_1,
        PRE_USER_OP_VALIDATION_HOOK_2,
        USER_OP_VALIDATION,
        PRE_RUNTIME_VALIDATION_HOOK_1,
        PRE_RUNTIME_VALIDATION_HOOK_2,
        RUNTIME_VALIDATION,
        PRE_EXECUTION_HOOK,
        PRE_PERMITTED_CALL_EXECUTION_HOOK,
        POST_EXECUTION_HOOK,
        POST_PERMITTED_CALL_EXECUTION_HOOK
    }

    string internal constant _NAME = "Comprehensive Plugin";
    string internal constant _VERSION = "1.0.0";
    string internal constant _AUTHOR = "Alchemy";

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function foo() external {}

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function preUserOpValidationHook(uint8 functionId, UserOperation calldata, bytes32)
        external
        pure
        override
        returns (uint256)
    {
        if (functionId == uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_1)) {
            return 0;
        } else if (functionId == uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_2)) {
            return 0;
        }
        revert NotImplemented(msg.sig, functionId);
    }

    function userOpValidationFunction(uint8 functionId, UserOperation calldata, bytes32)
        external
        pure
        override
        returns (uint256)
    {
        if (functionId == uint8(FunctionId.USER_OP_VALIDATION)) {
            return 0;
        }
        revert NotImplemented(msg.sig, functionId);
    }

    function preRuntimeValidationHook(uint8 functionId, address, uint256, bytes calldata) external pure override {
        if (functionId == uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_1)) {
            return;
        } else if (functionId == uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_2)) {
            return;
        }
        revert NotImplemented(msg.sig, functionId);
    }

    function runtimeValidationFunction(uint8 functionId, address, uint256, bytes calldata)
        external
        pure
        override
    {
        if (functionId == uint8(FunctionId.RUNTIME_VALIDATION)) {
            return;
        }
        revert NotImplemented(msg.sig, functionId);
    }

    function preExecutionHook(uint8 functionId, address, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes memory)
    {
        if (functionId == uint8(FunctionId.PRE_EXECUTION_HOOK)) {
            return "";
        } else if (functionId == uint8(FunctionId.PRE_PERMITTED_CALL_EXECUTION_HOOK)) {
            return "";
        }
        revert NotImplemented(msg.sig, functionId);
    }

    function postExecutionHook(uint8 functionId, bytes calldata) external pure override {
        if (functionId == uint8(FunctionId.POST_EXECUTION_HOOK)) {
            return;
        } else if (functionId == uint8(FunctionId.POST_PERMITTED_CALL_EXECUTION_HOOK)) {
            return;
        }
        revert NotImplemented(msg.sig, functionId);
    }

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.permittedExecutionSelectors = new bytes4[](1);
        manifest.permittedExecutionSelectors[0] = this.foo.selector;

        manifest.executionFunctions = new bytes4[](1);
        manifest.executionFunctions[0] = this.foo.selector;

        ManifestFunction memory fooUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.USER_OP_VALIDATION),
            dependencyIndex: 0 // Unused.
        });
        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: fooUserOpValidationFunction
        });

        ManifestFunction memory fooRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.RUNTIME_VALIDATION),
            dependencyIndex: 0 // Unused.
        });
        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: fooRuntimeValidationFunction
        });

        manifest.preUserOpValidationHooks = new ManifestAssociatedFunction[](4);
        manifest.preUserOpValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_1),
                dependencyIndex: 0 // Unused.
            })
        });
        manifest.preUserOpValidationHooks[1] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_2),
                dependencyIndex: 0 // Unused.
            })
        });
        manifest.preUserOpValidationHooks[2] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_1),
                dependencyIndex: 0 // Unused.
            })
        });
        manifest.preUserOpValidationHooks[3] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_2),
                dependencyIndex: 0 // Unused.
            })
        });

        manifest.preRuntimeValidationHooks = new ManifestAssociatedFunction[](4);
        manifest.preRuntimeValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_1),
                dependencyIndex: 0 // Unused.
            })
        });
        manifest.preRuntimeValidationHooks[1] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_2),
                dependencyIndex: 0 // Unused.
            })
        });
        manifest.preRuntimeValidationHooks[2] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_1),
                dependencyIndex: 0 // Unused.
            })
        });
        manifest.preRuntimeValidationHooks[3] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_2),
                dependencyIndex: 0 // Unused.
            })
        });

        manifest.executionHooks = new ManifestExecutionHook[](2);
        manifest.executionHooks[0] = ManifestExecutionHook({
            executionSelector: this.foo.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_EXECUTION_HOOK),
                dependencyIndex: 0 // Unused.
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.POST_EXECUTION_HOOK),
                dependencyIndex: 0 // Unused.
            })
        });
        manifest.executionHooks[1] = ManifestExecutionHook({
            executionSelector: this.foo.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.NONE,
                functionId: 0, // Unused.
                dependencyIndex: 0 // Unused.
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.POST_EXECUTION_HOOK),
                dependencyIndex: 0 // Unused.
            })
        });

        return manifest;
    }

    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = _NAME;
        metadata.version = _VERSION;
        metadata.author = _AUTHOR;
        return metadata;
    }
}
