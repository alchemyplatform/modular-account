// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {UserOperation} from "../../../src/interfaces/erc4337/UserOperation.sol";
import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest
} from "../../../src/interfaces/IPlugin.sol";
import {BaseTestPlugin} from "./BaseTestPlugin.sol";

abstract contract MockBaseUserOpValidationPlugin is BaseTestPlugin {
    enum FunctionId {
        USER_OP_VALIDATION,
        PRE_USER_OP_VALIDATION_HOOK_1,
        PRE_USER_OP_VALIDATION_HOOK_2
    }

    uint256 internal _userOpValidationFunctionData;
    uint256 internal _preUserOpValidationHook1Data;
    uint256 internal _preUserOpValidationHook2Data;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function preUserOpValidationHook(uint8 functionId, UserOperation calldata, bytes32)
        external
        view
        override
        returns (uint256)
    {
        if (functionId == uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_1)) {
            return _preUserOpValidationHook1Data;
        } else if (functionId == uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_2)) {
            return _preUserOpValidationHook2Data;
        }
        revert NotImplemented();
    }

    function userOpValidationFunction(uint8 functionId, UserOperation calldata, bytes32)
        external
        view
        override
        returns (uint256)
    {
        if (functionId == uint8(FunctionId.USER_OP_VALIDATION)) {
            return _userOpValidationFunctionData;
        }
        revert NotImplemented();
    }
}

contract MockUserOpValidationPlugin is MockBaseUserOpValidationPlugin {
    function setValidationData(uint256 userOpValidationFunctionData) external {
        _userOpValidationFunctionData = userOpValidationFunctionData;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function foo() external {}

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](1);
        manifest.executionFunctions[0] = this.foo.selector;

        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.USER_OP_VALIDATION),
                dependencyIndex: 0 // Unused.
            })
        });

        return manifest;
    }
}

contract MockUserOpValidation1HookPlugin is MockBaseUserOpValidationPlugin {
    function setValidationData(uint256 userOpValidationFunctionData, uint256 preUserOpValidationHook1Data)
        external
    {
        _userOpValidationFunctionData = userOpValidationFunctionData;
        _preUserOpValidationHook1Data = preUserOpValidationHook1Data;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function bar() external {}

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](1);
        manifest.executionFunctions[0] = this.bar.selector;

        ManifestFunction memory userOpValidationFunctionRef = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.USER_OP_VALIDATION),
            dependencyIndex: 0 // Unused.
        });
        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.bar.selector,
            associatedFunction: userOpValidationFunctionRef
        });

        manifest.preUserOpValidationHooks = new ManifestAssociatedFunction[](1);
        manifest.preUserOpValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: this.bar.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_1),
                dependencyIndex: 0 // Unused.
            })
        });

        return manifest;
    }
}

contract MockUserOpValidation2HookPlugin is MockBaseUserOpValidationPlugin {
    function setValidationData(
        uint256 userOpValidationFunctionData,
        uint256 preUserOpValidationHook1Data,
        uint256 preUserOpValidationHook2Data
    ) external {
        _userOpValidationFunctionData = userOpValidationFunctionData;
        _preUserOpValidationHook1Data = preUserOpValidationHook1Data;
        _preUserOpValidationHook2Data = preUserOpValidationHook2Data;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function baz() external {}

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](1);
        manifest.executionFunctions[0] = this.baz.selector;

        ManifestFunction memory userOpValidationFunctionRef = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.USER_OP_VALIDATION),
            dependencyIndex: 0 // Unused.
        });
        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.baz.selector,
            associatedFunction: userOpValidationFunctionRef
        });

        manifest.preUserOpValidationHooks = new ManifestAssociatedFunction[](2);
        manifest.preUserOpValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: this.baz.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_1),
                dependencyIndex: 0 // Unused.
            })
        });
        manifest.preUserOpValidationHooks[1] = ManifestAssociatedFunction({
            executionSelector: this.baz.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_2),
                dependencyIndex: 0 // Unused.
            })
        });

        return manifest;
    }
}
