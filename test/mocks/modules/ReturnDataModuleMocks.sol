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

pragma solidity ^0.8.26;

import {DIRECT_CALL_VALIDATION_ENTITY_ID} from "@erc6900/reference-implementation/helpers/Constants.sol";
import {
    ExecutionManifest,
    IExecutionModule,
    ManifestExecutionFunction
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {ModuleBase} from "../../../src/modules/ModuleBase.sol";
import {ModuleSignatureUtils} from "../../utils/ModuleSignatureUtils.sol";

contract RegularResultContract {
    function foo() external pure returns (bytes32) {
        return keccak256("bar");
    }

    function bar() external pure returns (bytes32) {
        return keccak256("foo");
    }
}

contract ResultCreatorModule is IExecutionModule, ModuleBase {
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

contract ResultConsumerModule is IExecutionModule, ModuleBase, IValidationModule, ModuleSignatureUtils {
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
    function checkResultExecuteWithRuntimeValidation(address target, bytes32 expected) external returns (bool) {
        // This result should be allowed based on the manifest permission request
        bytes memory returnData = IModularAccount(msg.sender).executeWithRuntimeValidation(
            abi.encodeCall(IModularAccount.execute, (target, 0, abi.encodeCall(RegularResultContract.foo, ()))),
            _encodeSignature(ModuleEntityLib.pack(address(this), DIRECT_CALL_VALIDATION_ENTITY_ID), uint8(0), "")
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
            executionSelector: this.checkResultExecuteWithRuntimeValidation.selector,
            skipRuntimeValidation: true,
            allowGlobalValidation: false
        });

        return manifest;
    }

    function moduleId() external pure returns (string memory) {
        return "erc6900.result-consumer-module.1.0.0";
    }
}
