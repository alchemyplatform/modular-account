// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";

import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntity, ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {MockModule} from "../mocks/modules/MockModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract UOCallBufferTest is AccountTestBase {
    // installed entity id is their index
    MockModule[] public validationHooks;

    // installed with entity id 0
    MockModule public validationModule;

    ModuleEntity internal _validationFunction;

    event ReceivedCall(bytes msgData, uint256 msgValue);

    function setUp() public override {
        _allowTestDirectCalls();
    }

    function test_multipleUOCalls() public withSMATest {
        _setup5ValidationHooks();

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(account1.execute, (beneficiary, 0 wei, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 2),
            paymasterAndData: "",
            signature: "" // keep the signature empty for now, because each individual hook receives no data in
                // this test.
        });
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        // Line up the "expect emit" calls

        for (uint256 i = 0; i < 5; i++) {
            vm.expectEmit(address(validationHooks[i]));
            emit ReceivedCall(
                abi.encodeCall(IValidationHookModule.preUserOpValidationHook, (uint32(i), userOp, userOpHash)), 0
            );
        }

        userOp.signature = "abcdefghijklmnopqrstuvwxyz";

        vm.expectEmit(address(validationModule));
        emit ReceivedCall(abi.encodeCall(IValidationModule.validateUserOp, (uint32(0), userOp, userOpHash)), 0);

        // Now, fill in the signature
        userOp.signature = _encodeSignature(_validationFunction, GLOBAL_VALIDATION, "abcdefghijklmnopqrstuvwxyz");

        vm.prank(address(entryPoint));
        account1.validateUserOp(userOp, userOpHash, 1 wei);
    }

    function testFuzz_multipleUOCalls(bytes[5] memory preValidationHookData, bytes memory validationData)
        public
        withSMATest
    {
        _setup5ValidationHooks();

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(account1.execute, (beneficiary, 0 wei, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 2),
            paymasterAndData: "",
            signature: "" // keep the signature empty for now, because each individual hook receives no data in
                // this test.
        });
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        bytes[] memory hookDataDynamicArray = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            hookDataDynamicArray[i] = preValidationHookData[i];
        }

        PreValidationHookData[] memory preValidationHookDatasToSend =
            _generatePreHooksDatasArray(hookDataDynamicArray);

        // Line up the "expect emit" calls, putting the per-hook data into the userOp.signature field for each.

        for (uint256 i = 0; i < 5; i++) {
            userOp.signature = preValidationHookData[i];
            vm.expectEmit(address(validationHooks[i]));
            emit ReceivedCall(
                abi.encodeCall(IValidationHookModule.preUserOpValidationHook, (uint32(i), userOp, userOpHash)), 0
            );
        }

        userOp.signature = validationData;
        vm.expectEmit(address(validationModule));
        emit ReceivedCall(abi.encodeCall(IValidationModule.validateUserOp, (uint32(0), userOp, userOpHash)), 0);

        // Now, fill in the signature
        userOp.signature =
            _encodeSignature(_validationFunction, GLOBAL_VALIDATION, preValidationHookDatasToSend, validationData);

        vm.prank(address(entryPoint));
        account1.validateUserOp(userOp, userOpHash, 1 wei);
    }

    function testFuzz_variableLengthUOCalls(
        uint8 preValidationHookCount,
        bytes[256] memory preValidationHookData,
        bytes memory validationData
    ) public withSMATest {
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

        // Set up the user op
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(account1.execute, (beneficiary, 0 wei, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 2),
            paymasterAndData: "",
            signature: "" // keep the signature empty for now, because each individual hook receives separate data
                // in this test.
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        // Set up the pre-validation hook data
        bytes[] memory hookDataDynamicArray = new bytes[](preValidationHookCount);
        for (uint256 i = 0; i < preValidationHookCount; i++) {
            hookDataDynamicArray[i] = preValidationHookData[i];
        }

        PreValidationHookData[] memory preValidationHookDatasToSend =
            _generatePreHooksDatasArray(hookDataDynamicArray);

        // Line up the "expect emit" calls, putting the per-hook data into the userOp.signature field for each.

        for (uint256 i = 0; i < preValidationHookCount; i++) {
            userOp.signature = preValidationHookData[i];
            vm.expectEmit(address(validationHooks[i]));
            emit ReceivedCall(
                abi.encodeCall(IValidationHookModule.preUserOpValidationHook, (uint32(i), userOp, userOpHash)), 0
            );
        }

        userOp.signature = validationData;
        vm.expectEmit(address(validationModule));
        emit ReceivedCall(abi.encodeCall(IValidationModule.validateUserOp, (uint32(0), userOp, userOpHash)), 0);

        // Now, fill in the signature
        userOp.signature =
            _encodeSignature(_validationFunction, GLOBAL_VALIDATION, preValidationHookDatasToSend, validationData);

        vm.prank(address(entryPoint));
        account1.validateUserOp(userOp, userOpHash, 1 wei);
    }

    function test_uoCallBuffer_shortReturnData() public withSMATest {
        _setup5ValidationHooks();

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(account1.execute, (beneficiary, 0 wei, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 2),
            paymasterAndData: "",
            signature: _encodeSignature(_validationFunction, GLOBAL_VALIDATION, "abcdefghijklmnopqrstuvwxyz")
        });
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        // mock a call to return less than 32 bytes of return data. This should cause validation to revert.

        vm.mockCall(
            address(validationHooks[0]),
            abi.encodeWithSelector(IValidationHookModule.preUserOpValidationHook.selector),
            hex"abcdabcd"
        );

        vm.prank(address(entryPoint));
        vm.expectRevert(bytes(hex"abcdabcd"));
        account1.validateUserOp(userOp, userOpHash, 1 wei);

        vm.clearMockedCalls();
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
