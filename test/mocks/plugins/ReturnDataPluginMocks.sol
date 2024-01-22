// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    ManifestExternalCallPermission,
    PluginManifest
} from "../../../src/interfaces/IPlugin.sol";
import {IStandardExecutor} from "../../../src/interfaces/IStandardExecutor.sol";
import {IPluginExecutor} from "../../../src/interfaces/IPluginExecutor.sol";
import {IPlugin} from "../../../src/interfaces/IPlugin.sol";
import {BaseTestPlugin} from "./BaseTestPlugin.sol";
import {FunctionReference} from "../../../src/libraries/FunctionReferenceLib.sol";

contract RegularResultContract {
    function foo() external pure returns (bytes32) {
        return keccak256("bar");
    }

    function bar() external pure returns (bytes32) {
        return keccak256("foo");
    }
}

contract ResultCreatorPlugin is BaseTestPlugin {
    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function foo() external pure returns (bytes32) {
        return keccak256("bar");
    }

    function bar() external pure returns (bytes32) {
        return keccak256("foo");
    }

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](2);
        manifest.executionFunctions[0] = this.foo.selector;
        manifest.executionFunctions[1] = this.bar.selector;

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        return manifest;
    }
}

contract ResultConsumerPlugin is BaseTestPlugin {
    ResultCreatorPlugin public immutable resultCreator;
    RegularResultContract public immutable regularResultContract;

    constructor(ResultCreatorPlugin _resultCreator, RegularResultContract _regularResultContract) {
        resultCreator = _resultCreator;
        regularResultContract = _regularResultContract;
    }

    // Check the return data through the executeFromPlugin fallback case
    function checkResultEFPFallback(bytes32 expected) external returns (bool) {
        // This result should be allowed based on the manifest permission request
        IPluginExecutor(msg.sender).executeFromPlugin(abi.encodeCall(ResultCreatorPlugin.foo, ()));

        bytes32 actual = ResultCreatorPlugin(msg.sender).foo();

        return actual == expected;
    }

    // Check the rturn data through the executeFromPlugin std exec case
    function checkResultEFPExternal(address target, bytes32 expected) external returns (bool) {
        // This result should be allowed based on the manifest permission request
        bytes memory returnData = IPluginExecutor(msg.sender).executeFromPluginExternal(
            target, 0, abi.encodeCall(RegularResultContract.foo, ())
        );

        bytes32 actual = abi.decode(returnData, (bytes32));

        return actual == expected;
    }

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function pluginManifest() external pure override returns (PluginManifest memory) {
        // We want to return the address of the immutable RegularResultContract in the permitted external calls
        // area of the manifest.
        // However, reading from immutable values is not permitted in pure functions. So we use this hack to get
        // around that.
        // In regular, non-mock plugins, external call targets in the plugin manifest should be constants, not just
        // immutbales.
        // But to make testing easier, we do this.

        function() internal pure returns (PluginManifest memory) pureManifestGetter;

        function() internal view returns (PluginManifest memory) viewManifestGetter = _innerPluginManifest;

        assembly ("memory-safe") {
            pureManifestGetter := viewManifestGetter
        }

        return pureManifestGetter();
    }

    function _innerPluginManifest() internal view returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](2);
        manifest.executionFunctions[0] = this.checkResultEFPFallback.selector;
        manifest.executionFunctions[1] = this.checkResultEFPExternal.selector;

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](2);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.checkResultEFPFallback.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
                functionId: 0,
                dependencyIndex: 0
            })
        });
        manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.checkResultEFPExternal.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        manifest.permittedExecutionSelectors = new bytes4[](1);
        manifest.permittedExecutionSelectors[0] = ResultCreatorPlugin.foo.selector;

        manifest.permittedExternalCalls = new ManifestExternalCallPermission[](1);

        bytes4[] memory allowedSelectors = new bytes4[](1);
        allowedSelectors[0] = RegularResultContract.foo.selector;
        manifest.permittedExternalCalls[0] = ManifestExternalCallPermission({
            externalAddress: address(regularResultContract),
            permitAnySelector: false,
            selectors: allowedSelectors
        });

        return manifest;
    }
}
