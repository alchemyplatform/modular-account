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

import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {HookConfig, HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntity, ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {
    ValidationConfig,
    ValidationConfigLib
} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import {FALLBACK_VALIDATION} from "../../src/helpers/Constants.sol";
import {ExecutionLib} from "../../src/libraries/ExecutionLib.sol";

import {MockModule} from "../mocks/modules/MockModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract SigCallBufferTest is AccountTestBase {
    using ValidationConfigLib for ValidationConfig;
    // installed entity id is their index

    MockModule[] public validationHooks;

    // installed with entity id 0
    MockModule public validationModule;

    ModuleEntity internal _validationFunction;

    struct FuzzConfig {
        uint8 validationHookCount;
        bytes[256] preValidationHookData;
        bytes signature;
    }

    function setUp() public override {
        _allowTestDirectCalls();
    }

    function test_sigCallBuffer_noData() public withSMATest {
        bytes32 hash = keccak256("test");

        _setUp4ValidationHooks();

        for (uint256 i = 0; i < 3; i++) {
            vm.expectCall(
                address(validationHooks[i]),
                abi.encodeCall(
                    IValidationHookModule.preSignatureValidationHook, (uint32(i), beneficiary, hash, "")
                )
            );
        }

        if (!_isSMATest) {
            vm.expectCall(
                address(validationModule),
                abi.encodeCall(
                    IValidationModule.validateSignature,
                    (address(account1), uint32(0), beneficiary, hash, abi.encodePacked(EOA_TYPE_SIGNATURE))
                )
            );
        }

        vm.prank(beneficiary);
        account1.isValidSignature(
            hash, _encode1271Signature(_validationFunction, abi.encodePacked(EOA_TYPE_SIGNATURE))
        );
    }

    function test_sigCallBuffer_withData() public withSMATest {
        bytes32 hash = keccak256("test");

        FuzzConfig memory fuzzConfig;
        fuzzConfig.validationHookCount = 4;
        fuzzConfig.signature = "abcdefghijklmnopqrstuvwxyz";

        fuzzConfig.preValidationHookData[0] = hex"abcd";
        fuzzConfig.preValidationHookData[1] = hex"";
        fuzzConfig.preValidationHookData[2] = hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        fuzzConfig.preValidationHookData[3] =
            hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffabcd";

        _setUp4ValidationHooks();

        _expectCalls(fuzzConfig, hash);

        PreValidationHookData[] memory preValidationHookDatasToSend = _generatePreHooksDatasArray(fuzzConfig);

        bytes memory signature;
        if (_isSMATest) {
            // Signature will fail (return 0xffffffff), but all hooks will run and the call will not revert.
            signature = abi.encodePacked(EOA_TYPE_SIGNATURE);
        } else {
            signature = fuzzConfig.signature;
        }
        vm.prank(beneficiary);
        account1.isValidSignature(
            hash, _encode1271Signature(_validationFunction, preValidationHookDatasToSend, signature)
        );
    }

    function testFuzz_sigCallBuffer(bytes32 hash, FuzzConfig memory fuzzConfig) public withSMATest {
        _installValidationAndAssocHook(fuzzConfig);

        _expectCalls(fuzzConfig, hash);

        PreValidationHookData[] memory preValidationHookDatasToSend = _generatePreHooksDatasArray(fuzzConfig);

        bytes memory signature;
        if (_isSMATest) {
            // Signature will fail, but not revert.
            signature = abi.encodePacked(EOA_TYPE_SIGNATURE);
        } else {
            signature = fuzzConfig.signature;
        }

        vm.prank(beneficiary);
        account1.isValidSignature(
            hash, _encode1271Signature(_validationFunction, preValidationHookDatasToSend, signature)
        );
    }

    // Assert the call reverts if insufficient return data is provided for signature validation itself.
    // This is only possible in non-SMA tests, as the signature validation function is done internally within SMA.
    function test_sigCallBuffer_shortReturnData() public {
        bytes32 hash = keccak256("test");

        _setUp4ValidationHooks();

        // Mock a call with <32 bytes of return data. This overrides an existing mock from the setup.
        vm.mockCall(
            address(validationModule),
            abi.encodeWithSelector(IValidationModule.validateSignature.selector),
            hex"abcdabcd"
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionLib.SignatureValidationFunctionReverted.selector,
                ModuleEntityLib.pack(address(validationModule), uint32(0)),
                hex"abcdabcd"
            )
        );
        vm.prank(beneficiary);
        account1.isValidSignature(
            hash, _encode1271Signature(_validationFunction, abi.encodePacked(EOA_TYPE_SIGNATURE))
        );

        vm.clearMockedCalls();
    }

    function _setUp4ValidationHooks() internal {
        FuzzConfig memory fuzzConfig;
        fuzzConfig.validationHookCount = 4;

        _installValidationAndAssocHook(fuzzConfig);
    }

    function _installValidationAndAssocHook(FuzzConfig memory fuzzConfig) internal {
        HookConfig[] memory hooks = new HookConfig[](fuzzConfig.validationHookCount);
        bytes[] memory hookInstalls = new bytes[](fuzzConfig.validationHookCount);

        ExecutionManifest memory m; // empty manifest
        validationHooks = new MockModule[](fuzzConfig.validationHookCount);

        for (uint256 i = 0; i < fuzzConfig.validationHookCount; i++) {
            // To get different addresses for vm.expectCall between SMA and non-SMA tests, we need to deploy new
            // validation hooks at different addresses
            validationHooks[i] = new MockModule{salt: keccak256(abi.encode(i, _isSMATest))}(m);
            // These modules emit events, but signature validation happens as a staticcall, so we can't expect the
            // events. Instead, we mock all of the calls coming into these contracts, and expect calls to them. They
            // are also re-deployed for the SMA test, so the tests should be distinct.
            vm.mockCall(address(validationHooks[i]), "", "");

            hooks[i] =
                HookConfigLib.packValidationHook({_module: address(validationHooks[i]), _entityId: uint32(i)});

            hookInstalls[i] = abi.encodePacked(hooks[i]);
        }

        validationModule = new MockModule(m);

        ValidationConfig validationConfig;

        if (_isSMATest) {
            validationConfig = ValidationConfigLib.pack({
                _validationFunction: FALLBACK_VALIDATION,
                _isGlobal: true,
                _isSignatureValidation: true,
                _isUserOpValidation: false
            });
        } else {
            validationConfig = ValidationConfigLib.pack({
                _module: address(validationModule),
                _entityId: 0,
                _isGlobal: true,
                _isSignatureValidation: true,
                _isUserOpValidation: false
            });

            vm.mockCall(address(validationModule), "", abi.encode(IERC1271.isValidSignature.selector));
        }

        _validationFunction = validationConfig.moduleEntity();

        account1.installValidation(validationConfig, new bytes4[](0), "", hookInstalls);
    }

    function _expectCalls(FuzzConfig memory fuzzConfig, bytes32 hash) internal {
        for (uint256 i = 0; i < fuzzConfig.validationHookCount; i++) {
            vm.expectCall(
                address(validationHooks[i]),
                abi.encodeCall(
                    IValidationHookModule.preSignatureValidationHook,
                    (uint32(i), beneficiary, hash, fuzzConfig.preValidationHookData[i])
                )
            );
        }

        if (!_isSMATest) {
            vm.expectCall(
                address(validationModule),
                abi.encodeCall(
                    IValidationModule.validateSignature,
                    (address(account1), uint32(0), beneficiary, hash, fuzzConfig.signature)
                )
            );
        }
    }

    function _generatePreHooksDatasArray(FuzzConfig memory fuzzConfig)
        internal
        pure
        returns (PreValidationHookData[] memory)
    {
        bytes[] memory hookDataDynamicArray = new bytes[](fuzzConfig.validationHookCount);
        for (uint256 i = 0; i < fuzzConfig.validationHookCount; i++) {
            hookDataDynamicArray[i] = fuzzConfig.preValidationHookData[i];
        }

        return _generatePreHooksDatasArray(hookDataDynamicArray);
    }
}
