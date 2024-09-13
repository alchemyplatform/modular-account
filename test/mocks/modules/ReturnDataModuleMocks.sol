// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {
    ExecutionManifest,
    IExecutionModule,
    ManifestExecutionFunction
} from "@erc-6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IModularAccount} from "@erc-6900/reference-implementation/interfaces/IModularAccount.sol";
import {IValidationModule} from "@erc-6900/reference-implementation/interfaces/IValidationModule.sol";

import {DIRECT_CALL_VALIDATION_ENTITYID} from "../../../src/helpers/Constants.sol";

import {BaseModule} from "../../../src/modules/BaseModule.sol";

contract RegularResultContract {
    function foo() external pure returns (bytes32) {
        return keccak256("bar");
    }

    function bar() external pure returns (bytes32) {
        return keccak256("foo");
    }
}

contract ResultCreatorModule is IExecutionModule, BaseModule {
    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function foo() external pure returns (bytes32) {
        return keccak256("bar");
    }

    function bar() external pure returns (bytes32) {
        return keccak256("foo");
    }

    function executionManifest() external pure override returns (ExecutionManifest memory) {
        ExecutionManifest memory manifest;

        manifest.executionFunctions = new ManifestExecutionFunction[](2);
        manifest.executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: this.foo.selector,
            skipRuntimeValidation: true,
            allowGlobalValidation: false
        });
        manifest.executionFunctions[1] = ManifestExecutionFunction({
            executionSelector: this.bar.selector,
            skipRuntimeValidation: false,
            allowGlobalValidation: false
        });

        return manifest;
    }

    function moduleId() external pure returns (string memory) {
        return "erc6900.result-creator-module.1.0.0";
    }
}

contract ResultConsumerModule is IExecutionModule, BaseModule, IValidationModule {
    ResultCreatorModule public immutable RESULT_CREATOR;
    RegularResultContract public immutable REGULAR_RESULT_CONTRACT;

    error NotAuthorized();

    constructor(ResultCreatorModule _resultCreator, RegularResultContract _regularResultContract) {
        RESULT_CREATOR = _resultCreator;
        REGULAR_RESULT_CONTRACT = _regularResultContract;
    }

    // Validation function implementations. We only care about the runtime validation function, to authorize
    // itself.

    function validateUserOp(uint32, PackedUserOperation calldata, bytes32) external pure returns (uint256) {
        revert NotImplemented();
    }

    function validateRuntime(address, uint32, address sender, uint256, bytes calldata, bytes calldata)
        external
        view
    {
        if (sender != address(this)) {
            revert NotAuthorized();
        }
    }

    function validateSignature(address, uint32, address, bytes32, bytes calldata) external pure returns (bytes4) {
        revert NotImplemented();
    }

    // Check the return data through the fallback
    function checkResultFallback(bytes32 expected) external view returns (bool) {
        // This result should be allowed based on the manifest permission request
        bytes32 actual = ResultCreatorModule(msg.sender).foo();

        return actual == expected;
    }

    // Check the return data through the execute with authorization case
    function checkResultExecuteWithAuthorization(address target, bytes32 expected) external returns (bool) {
        // This result should be allowed based on the manifest permission request
        bytes memory returnData = IModularAccount(msg.sender).executeWithAuthorization(
            abi.encodeCall(IModularAccount.execute, (target, 0, abi.encodeCall(RegularResultContract.foo, ()))),
            abi.encodePacked(this, DIRECT_CALL_VALIDATION_ENTITYID, uint8(0), uint32(1), uint8(255)) // Validation
                // function of self,
                // selector-associated, with no auth data
        );

        bytes32 actual = abi.decode(abi.decode(returnData, (bytes)), (bytes32));

        return actual == expected;
    }

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function executionManifest() external pure override returns (ExecutionManifest memory) {
        ExecutionManifest memory manifest;

        manifest.executionFunctions = new ManifestExecutionFunction[](2);
        manifest.executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: this.checkResultFallback.selector,
            skipRuntimeValidation: true,
            allowGlobalValidation: false
        });
        manifest.executionFunctions[1] = ManifestExecutionFunction({
            executionSelector: this.checkResultExecuteWithAuthorization.selector,
            skipRuntimeValidation: true,
            allowGlobalValidation: false
        });

        return manifest;
    }

    function moduleId() external pure returns (string memory) {
        return "erc6900.result-consumer-module.1.0.0";
    }
}
