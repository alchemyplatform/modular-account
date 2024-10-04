// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";

import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntity, ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";

import {MockModule} from "../mocks/modules/MockModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract RTCallBufferTest is AccountTestBase {
    // installed entity id is their index
    MockModule[] public validationHooks;

    // installed with entity id 0
    MockModule public validationModule;

    ModuleEntity internal _validationFunction;

    event ReceivedCall(bytes msgData, uint256 msgValue);

    function setUp() public override {
        _allowTestDirectCalls();
    }

    function test_multipleRTCalls() public withSMATest {
        _setup5ValidationHooks();

        bytes memory callData = abi.encodeCall(account1.execute, (beneficiary, 0 wei, ""));
        bytes memory authorization =
            _encodeSignature(_validationFunction, GLOBAL_VALIDATION, "abcdefghijklmnopqrstuvwxyz");

        // Line up the "expect emit" calls
        for (uint256 i = 0; i < 5; i++) {
            vm.expectEmit(address(validationHooks[i]));
            emit ReceivedCall(
                abi.encodeCall(
                    IValidationHookModule.preRuntimeValidationHook,
                    (uint32(i), address(entryPoint), 0 wei, callData, "")
                ),
                0
            );
        }

        vm.expectEmit(address(validationModule));
        emit ReceivedCall(
            abi.encodeCall(
                IValidationModule.validateRuntime,
                (address(account1), 0, address(entryPoint), 0 wei, callData, "abcdefghijklmnopqrstuvwxyz")
            ),
            0
        );

        vm.prank(address(entryPoint));
        account1.executeWithRuntimeValidation(callData, authorization);
    }

    function testFuzz_multipleRTCalls(bytes[5] memory preValidationHookData, bytes memory validationData)
        public
        withSMATest
    {
        _setup5ValidationHooks();

        bytes memory callData = abi.encodeCall(account1.execute, (beneficiary, 0 wei, ""));

        bytes[] memory hookDataDynamicArray = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            hookDataDynamicArray[i] = preValidationHookData[i];
        }

        PreValidationHookData[] memory preValidationHookDatasToSend =
            _generatePreHooksDatasArray(hookDataDynamicArray);

        // Line up the "expect emit" calls, putting the per-hook data into the userOp.signature field for each.

        for (uint256 i = 0; i < 5; i++) {
            vm.expectEmit(address(validationHooks[i]));
            emit ReceivedCall(
                abi.encodeCall(
                    IValidationHookModule.preRuntimeValidationHook,
                    (uint32(i), address(entryPoint), 0 wei, callData, preValidationHookData[i])
                ),
                0
            );
        }

        vm.expectEmit(address(validationModule));
        emit ReceivedCall(
            abi.encodeCall(
                IValidationModule.validateRuntime,
                (address(account1), uint32(0), address(entryPoint), 0 wei, callData, validationData)
            ),
            0
        );

        bytes memory authorization =
            _encodeSignature(_validationFunction, GLOBAL_VALIDATION, preValidationHookDatasToSend, validationData);

        vm.prank(address(entryPoint));
        account1.executeWithRuntimeValidation(callData, authorization);
    }

    function testFuzz_variableLengthRTCalls(
        uint8 preValidationHookCount,
        bytes[254] memory preValidationHookData,
        bytes memory validationData
    ) public withSMATest {
        preValidationHookCount = uint8(bound(preValidationHookCount, 0, 254));

        ExecutionManifest memory m; // empty manifest

        // Install the pre validation hooks
        validationHooks = new MockModule[](preValidationHookCount);
        for (uint256 i = 0; i < preValidationHookCount; i++) {
            validationHooks[i] = new MockModule(m);
        }

        // Install the validation module
        validationModule = new MockModule(m);

        // Install the validation hooks
        bytes[] memory hooks = new bytes[](preValidationHookCount);
        for (uint256 i = 0; i < preValidationHookCount; i++) {
            hooks[i] = abi.encodePacked(
                HookConfigLib.packValidationHook({_module: address(validationHooks[i]), _entityId: uint32(i)})
            );
        }

        account1.installValidation(
            ValidationConfigLib.pack({
                _module: address(validationModule),
                _entityId: 0,
                _isGlobal: true,
                _isSignatureValidation: true,
                _isUserOpValidation: true
            }),
            new bytes4[](0),
            "",
            hooks
        );

        _validationFunction = ModuleEntityLib.pack(address(validationModule), 0);

        bytes memory callData = abi.encodeCall(account1.execute, (beneficiary, 0 wei, ""));

        // Set up the pre-validation hook data
        bytes[] memory hookDataDynamicArray = new bytes[](preValidationHookCount);
        for (uint256 i = 0; i < preValidationHookCount; i++) {
            hookDataDynamicArray[i] = preValidationHookData[i];
        }

        PreValidationHookData[] memory preValidationHookDatasToSend =
            _generatePreHooksDatasArray(hookDataDynamicArray);

        // Line up the "expect emit" calls, putting the per-hook data into the userOp.signature field for each.

        for (uint256 i = 0; i < preValidationHookCount; i++) {
            vm.expectEmit(address(validationHooks[i]));
            emit ReceivedCall(
                abi.encodeCall(
                    IValidationHookModule.preRuntimeValidationHook,
                    (uint32(i), address(entryPoint), 0 wei, callData, preValidationHookData[i])
                ),
                0
            );
        }

        vm.expectEmit(address(validationModule));
        emit ReceivedCall(
            abi.encodeCall(
                IValidationModule.validateRuntime,
                (address(account1), uint32(0), address(entryPoint), 0 wei, callData, validationData)
            ),
            0
        );

        bytes memory authorization =
            _encodeSignature(_validationFunction, GLOBAL_VALIDATION, preValidationHookDatasToSend, validationData);

        vm.prank(address(entryPoint));
        account1.executeWithRuntimeValidation(callData, authorization);
    }

    function _setup5ValidationHooks() internal {
        ExecutionManifest memory m; // empty manifest

        validationHooks = new MockModule[](5);
        for (uint256 i = 0; i < 5; i++) {
            validationHooks[i] = new MockModule(m);
        }

        validationModule = new MockModule(m);

        bytes[] memory hooks = new bytes[](5);

        for (uint256 i = 0; i < 5; i++) {
            hooks[i] = abi.encodePacked(
                HookConfigLib.packValidationHook({_module: address(validationHooks[i]), _entityId: uint32(i)})
            );
        }

        account1.installValidation(
            ValidationConfigLib.pack({
                _module: address(validationModule),
                _entityId: 0,
                _isGlobal: true,
                _isSignatureValidation: true,
                _isUserOpValidation: true
            }),
            new bytes4[](0),
            "",
            hooks
        );

        _validationFunction = ModuleEntityLib.pack(address(validationModule), 0);
    }
}
