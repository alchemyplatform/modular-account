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

import {DIRECT_CALL_VALIDATION_ENTITYID} from "@erc6900/reference-implementation/helpers/Constants.sol";
import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {
    ExecutionManifest,
    ManifestExecutionHook
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntity} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {
    ValidationConfig,
    ValidationConfigLib
} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {IAccountExecute} from "@eth-infinitism/account-abstraction/interfaces/IAccountExecute.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {FALLBACK_VALIDATION} from "../../src/helpers/Constants.sol";

import {MockModule} from "../mocks/modules/MockModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

// Cases to test:
// - pre hooks in `executeUserOp` (freshly allocated buffer)
// - pre hooks in `executeWithRuntimeValidation` (freshly allocated buffer from SMA)
// - pre hooks in `executeWithRuntimeValidation` (reusing RT buffer from pre RT hooks only in SMA)
// - pre hooks in `executeWithRuntimeValidation` (reusing RT buffer from RT validation use)
// - pre hooks in `_checkPermittedCallerAndAssociatedHooks` (from EP, no pre RT hooks)
// - pre hooks in `_checkPermittedCallerAndAssociatedHooks` (direct call validation, with pre RT hooks)
contract PHCallBufferTest is AccountTestBase {
    // installed entity id is their index
    MockModule[] public execHooks;

    uint32 public constant NEW_VALIDATION_ENTITY_ID = 1;
    // installed with entity id 1
    MockModule public validationModule;

    // installed with entity id 1
    MockModule public preValidationHook;

    ModuleEntity internal _validationFunction;

    event ReceivedCall(bytes msgData, uint256 msgValue);

    function setUp() public override {
        _allowTestDirectCalls();
    }

    // pre hooks in `executeUserOp` (freshly allocated buffer)
    function test_preExecHooksRun_execUO() public withSMATest {
        _install3ValAssocExecHooks();

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: _encodeNonce(_validationFunction, GLOBAL_V, 0),
            initCode: "",
            callData: abi.encodePacked(
                IAccountExecute.executeUserOp.selector, abi.encodeCall(account1.execute, (beneficiary, 0 wei, ""))
            ),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 2),
            paymasterAndData: "",
            signature: ""
        });
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        userOp.signature = _encodeUOSignature(userOpHash);

        // Line up the "expect emit" calls
        for (uint256 i = 0; i < 3; i++) {
            vm.expectEmit(address(execHooks[i]));
            emit ReceivedCall(
                abi.encodeCall(
                    IExecutionHookModule.preExecutionHook,
                    (
                        uint32(i),
                        address(entryPoint),
                        0 wei,
                        abi.encodeCall(IAccountExecute.executeUserOp, (userOp, userOpHash))
                    )
                ),
                0
            );
        }

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        vm.prank(beneficiary);
        entryPoint.handleOps(userOps, beneficiary);
    }

    // pre hooks in `executeWithRuntimeValidation` (freshly allocated buffer from SMA)
    // SMA allows for skipping allocation of an RT call buffer, even in the RT validation case.
    function test_preExecHooksWithRtValidation_freshBuffer_regularCallData() public {
        _switchToSMA();
        _allowTestDirectCalls();
        _install3ValAssocExecHooks();

        bytes memory callData = abi.encodeCall(account1.execute, (beneficiary, 0 wei, ""));
        bytes memory authorization = _encodeSignature(_validationFunction, GLOBAL_VALIDATION, "");

        // Line up the "expect emit" calls
        for (uint256 i = 0; i < 3; i++) {
            vm.expectEmit(address(execHooks[i]));
            emit ReceivedCall(
                abi.encodeCall(
                    IExecutionHookModule.preExecutionHook, (uint32(i), address(owner1), 0 wei, callData)
                ),
                0
            );
        }

        vm.prank(owner1);
        account1.executeWithRuntimeValidation(callData, authorization);
    }

    // pre hooks in `executeWithRuntimeValidation` (freshly allocated buffer from SMA)
    // SMA allows for skipping allocation of an RT call buffer, even in the RT validation case.
    // This alternate version of the tests checks behavior when the provided calldata is incorrectly abi-encoded
    // and not word-aligned.
    function test_preExecHooksWithRtValidation_freshBuffer_unalignedCallData() public {
        _switchToSMA();
        _allowTestDirectCalls();
        _install3ValAssocExecHooks();

        bytes memory callData =
            abi.encodePacked(abi.encodeCall(account1.execute, (beneficiary, 0 wei, "")), "abcdefghijk");
        bytes memory authorization = _encodeSignature(_validationFunction, GLOBAL_VALIDATION, "");

        // Line up the "expect emit" calls
        for (uint256 i = 0; i < 3; i++) {
            vm.expectEmit(address(execHooks[i]));
            emit ReceivedCall(
                abi.encodeCall(
                    IExecutionHookModule.preExecutionHook, (uint32(i), address(owner1), 0 wei, callData)
                ),
                0
            );
        }

        vm.prank(owner1);
        account1.executeWithRuntimeValidation(callData, authorization);
    }

    function test_preExecHooksWithRtValidation_reusePRTOnlyBuffer_regularCalldata() public {
        _switchToSMA();
        _allowTestDirectCalls();
        _install3ValAssocExecHooks();
        _addPreRuntimeValidationHook();

        bytes memory callData = abi.encodeCall(account1.execute, (beneficiary, 0 wei, ""));
        bytes memory authorization = _encodeSignature(_validationFunction, GLOBAL_VALIDATION, "");

        // pre RT validation expect emit
        vm.expectEmit(address(preValidationHook));
        emit ReceivedCall(
            abi.encodeCall(
                IValidationHookModule.preRuntimeValidationHook, (uint32(1), address(owner1), 0 wei, callData, "")
            ),
            0
        );

        // pre exec emits
        for (uint256 i = 0; i < 3; i++) {
            vm.expectEmit(address(execHooks[i]));
            emit ReceivedCall(
                abi.encodeCall(
                    IExecutionHookModule.preExecutionHook, (uint32(i), address(owner1), 0 wei, callData)
                ),
                0
            );
        }

        vm.prank(owner1);
        account1.executeWithRuntimeValidation(callData, authorization);
    }

    function test_preExecHooksWithRtValidation_reusePRTOnlyBuffer_unalignedCalldata() public withSMATest {
        _switchToSMA();
        _allowTestDirectCalls();
        _install3ValAssocExecHooks();
        _addPreRuntimeValidationHook();

        bytes memory callData =
            abi.encodePacked(abi.encodeCall(account1.execute, (beneficiary, 0 wei, "")), "abcdefghijk");
        bytes memory authorization = _encodeSignature(_validationFunction, GLOBAL_VALIDATION, "");

        // pre RT validation expect emit
        vm.expectEmit(address(preValidationHook));
        emit ReceivedCall(
            abi.encodeCall(
                IValidationHookModule.preRuntimeValidationHook, (uint32(1), address(owner1), 0 wei, callData, "")
            ),
            0
        );

        // pre exec emits
        for (uint256 i = 0; i < 3; i++) {
            vm.expectEmit(address(execHooks[i]));
            emit ReceivedCall(
                abi.encodeCall(
                    IExecutionHookModule.preExecutionHook, (uint32(i), address(owner1), 0 wei, callData)
                ),
                0
            );
        }

        vm.prank(owner1);
        account1.executeWithRuntimeValidation(callData, authorization);
    }

    // pre hooks in `executeWithRuntimeValidation` (reusing RT buffer from RT validation use)
    function test_preExecHooksWithRtValidation_reuseRTOnlyBuffer_regularCallData() public withSMATest {
        _install3ValAssocExecHooks();

        bytes memory callData = abi.encodeCall(account1.execute, (beneficiary, 0 wei, ""));
        bytes memory authorization = _encodeSignature(_validationFunction, GLOBAL_VALIDATION, "");

        // RT validation emit, only if not SMA
        if (!_isSMATest) {
            vm.expectEmit(address(validationModule));
            emit ReceivedCall(
                abi.encodeCall(
                    IValidationModule.validateRuntime,
                    (address(account1), NEW_VALIDATION_ENTITY_ID, address(owner1), 0 wei, callData, "")
                ),
                0
            );
        }

        // pre exec emits
        for (uint256 i = 0; i < 3; i++) {
            vm.expectEmit(address(execHooks[i]));
            emit ReceivedCall(
                abi.encodeCall(
                    IExecutionHookModule.preExecutionHook, (uint32(i), address(owner1), 0 wei, callData)
                ),
                0
            );
        }

        vm.prank(owner1);
        account1.executeWithRuntimeValidation(callData, authorization);
    }

    function test_preExecHooksWithRtValidation_reuseRTOnlyBuffer_unalignedCallData() public withSMATest {
        _install3ValAssocExecHooks();

        bytes memory callData =
            abi.encodePacked(abi.encodeCall(account1.execute, (beneficiary, 0 wei, "")), "abcdefghijk");
        bytes memory authorization = _encodeSignature(_validationFunction, GLOBAL_VALIDATION, "");

        // RT validation emit, only if not SMA
        if (!_isSMATest) {
            vm.expectEmit(address(validationModule));
            emit ReceivedCall(
                abi.encodeCall(
                    IValidationModule.validateRuntime,
                    (address(account1), NEW_VALIDATION_ENTITY_ID, address(owner1), 0 wei, callData, "")
                ),
                0
            );
        }

        // pre exec emits
        for (uint256 i = 0; i < 3; i++) {
            vm.expectEmit(address(execHooks[i]));
            emit ReceivedCall(
                abi.encodeCall(
                    IExecutionHookModule.preExecutionHook, (uint32(i), address(owner1), 0 wei, callData)
                ),
                0
            );
        }

        vm.prank(owner1);
        account1.executeWithRuntimeValidation(callData, authorization);
    }

    function test_preExecHooksWithRtValidation_reuseConvertedRTBuffer_regularCallData() public withSMATest {
        _install3ValAssocExecHooks();
        _addPreRuntimeValidationHook();

        bytes memory callData = abi.encodeCall(account1.execute, (beneficiary, 0 wei, ""));
        bytes memory authorization = _encodeSignature(_validationFunction, GLOBAL_VALIDATION, "");

        // pre RT validation emit
        vm.expectEmit(address(preValidationHook));
        emit ReceivedCall(
            abi.encodeCall(
                IValidationHookModule.preRuntimeValidationHook, (uint32(1), address(owner1), 0 wei, callData, "")
            ),
            0
        );

        // RT validation emit, only if not SMA
        if (!_isSMATest) {
            vm.expectEmit(address(validationModule));
            emit ReceivedCall(
                abi.encodeCall(
                    IValidationModule.validateRuntime,
                    (address(account1), NEW_VALIDATION_ENTITY_ID, address(owner1), 0 wei, callData, "")
                ),
                0
            );
        }

        // pre exec emits
        for (uint256 i = 0; i < 3; i++) {
            vm.expectEmit(address(execHooks[i]));
            emit ReceivedCall(
                abi.encodeCall(
                    IExecutionHookModule.preExecutionHook, (uint32(i), address(owner1), 0 wei, callData)
                ),
                0
            );
        }

        vm.prank(owner1);
        account1.executeWithRuntimeValidation(callData, authorization);
    }

    function test_preExecHooksWithRtValidation_reuseConvertedRTBuffer_unalignedCallData() public withSMATest {
        _install3ValAssocExecHooks();
        _addPreRuntimeValidationHook();

        bytes memory callData =
            abi.encodePacked(abi.encodeCall(account1.execute, (beneficiary, 0 wei, "")), "abcdefghijk");
        bytes memory authorization = _encodeSignature(_validationFunction, GLOBAL_VALIDATION, "");

        // pre RT validation emit
        vm.expectEmit(address(preValidationHook));
        emit ReceivedCall(
            abi.encodeCall(
                IValidationHookModule.preRuntimeValidationHook, (uint32(1), address(owner1), 0 wei, callData, "")
            ),
            0
        );

        // RT validation emit, only if not SMA
        if (!_isSMATest) {
            vm.expectEmit(address(validationModule));
            emit ReceivedCall(
                abi.encodeCall(
                    IValidationModule.validateRuntime,
                    (address(account1), NEW_VALIDATION_ENTITY_ID, address(owner1), 0 wei, callData, "")
                ),
                0
            );
        }

        // pre exec emits
        for (uint256 i = 0; i < 3; i++) {
            vm.expectEmit(address(execHooks[i]));
            emit ReceivedCall(
                abi.encodeCall(
                    IExecutionHookModule.preExecutionHook, (uint32(i), address(owner1), 0 wei, callData)
                ),
                0
            );
        }

        vm.prank(owner1);
        account1.executeWithRuntimeValidation(callData, authorization);
    }

    // pre hooks in `_checkPermittedCallerAndAssociatedHooks` (from EP, no pre RT hooks)
    // Therefore, the hooks must be installed as selector-association exec hooks
    function test_preExecHooks_EPCall_regularCallData() public withSMATest {
        _install3SelAssocExecHooks();

        bytes memory callData = abi.encodeCall(account1.execute, (beneficiary, 0 wei, ""));

        // Line up the "expect emit" calls
        for (uint256 i = 0; i < 3; i++) {
            vm.expectEmit(address(execHooks[i]));
            emit ReceivedCall(
                abi.encodeCall(
                    IExecutionHookModule.preExecutionHook, (uint32(i), address(entryPoint), 0 wei, callData)
                ),
                0
            );
        }

        vm.prank(address(entryPoint));
        (bool success,) = address(account1).call(callData);

        require(success, "call failed (possibly due to event mismatch)");
    }

    function test_preExecHooks_EPCall_unalignedCallData() public withSMATest {
        _install3SelAssocExecHooks();

        bytes memory callData =
            abi.encodePacked(abi.encodeCall(account1.execute, (beneficiary, 0 wei, "")), "abcdefghijk");

        // Line up the "expect emit" calls
        for (uint256 i = 0; i < 3; i++) {
            vm.expectEmit(address(execHooks[i]));
            emit ReceivedCall(
                abi.encodeCall(
                    IExecutionHookModule.preExecutionHook, (uint32(i), address(entryPoint), 0 wei, callData)
                ),
                0
            );
        }

        vm.prank(address(entryPoint));
        (bool success,) = address(account1).call(callData);

        require(success, "call failed (possibly due to event mismatch)");
    }

    // pre hooks in `_checkPermittedCallerAndAssociatedHooks` (direct call validation, with pre RT hooks)
    function test_preExecHooks_directCallValidation_withPRTHooks() public withSMATest {
        _install3ValAssocExecHooks(DIRECT_CALL_VALIDATION_ENTITYID, true);
        _addPreRuntimeValidationHook();

        bytes memory callData = abi.encodeCall(account1.execute, (beneficiary, 0 wei, ""));

        // pre RT validation emit
        vm.expectEmit(address(preValidationHook));
        emit ReceivedCall(
            abi.encodeCall(
                IValidationHookModule.preRuntimeValidationHook,
                (uint32(1), address(validationModule), 0 wei, callData, "")
            ),
            0
        );

        // Line up the "expect emit" calls
        for (uint256 i = 0; i < 3; i++) {
            vm.expectEmit(address(execHooks[i]));
            emit ReceivedCall(
                abi.encodeCall(
                    IExecutionHookModule.preExecutionHook, (uint32(i), address(validationModule), 0 wei, callData)
                ),
                0
            );
        }

        vm.prank(address(validationModule));
        (bool success,) = address(account1).call(callData);

        require(success, "call failed (possibly due to event mismatch)");
    }

    function _encodeUOSignature(bytes32 userOpHash) internal view returns (bytes memory) {
        if (_isSMATest) {
            (uint8 v, bytes32 r, bytes32 s) =
                vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
            bytes memory smaSig = abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v);

            return _encodeSignature(smaSig);
        } else {
            return _encodeSignature("");
        }
    }

    function _install3ValAssocExecHooks() internal {
        _install3ValAssocExecHooks(NEW_VALIDATION_ENTITY_ID, false);
    }

    function _install3ValAssocExecHooks(uint32 validationEntityId, bool forceInstall) internal {
        ExecutionManifest memory m; // empty manifest

        execHooks = new MockModule[](3);
        for (uint256 i = 0; i < 3; i++) {
            execHooks[i] = new MockModule(m);
        }

        validationModule = new MockModule(m);

        bytes[] memory hooks = new bytes[](3);

        for (uint256 i = 0; i < 3; i++) {
            hooks[i] = abi.encodePacked(
                HookConfigLib.packExecHook({
                    _module: address(execHooks[i]),
                    _entityId: uint32(i),
                    _hasPre: true,
                    _hasPost: false
                })
            );
        }

        ValidationConfig validationConfig;

        if (_isSMATest && !forceInstall) {
            // Only use the SMA for skipping the validation step, so install this with the fallback validation
            // instead.
            validationConfig = ValidationConfigLib.pack({
                _validationFunction: FALLBACK_VALIDATION,
                _isGlobal: true,
                _isSignatureValidation: true,
                _isUserOpValidation: true
            });
        } else {
            validationConfig = ValidationConfigLib.pack({
                _module: address(validationModule),
                _entityId: validationEntityId,
                _isGlobal: true,
                _isSignatureValidation: true,
                _isUserOpValidation: true
            });
        }

        account1.installValidation({
            validationConfig: validationConfig,
            selectors: new bytes4[](0),
            installData: "",
            hooks: hooks
        });

        _validationFunction = ValidationConfigLib.moduleEntity(validationConfig);
    }

    function _install3SelAssocExecHooks() internal {
        execHooks = new MockModule[](3);

        for (uint256 i = 0; i < 3; i++) {
            ExecutionManifest memory m;

            execHooks[i] = new MockModule(m);

            m.executionHooks = new ManifestExecutionHook[](1);
            m.executionHooks[0] = ManifestExecutionHook({
                executionSelector: account1.execute.selector,
                entityId: uint32(i),
                isPreHook: true,
                isPostHook: false
            });

            account1.installExecution({module: address(execHooks[i]), manifest: m, moduleInstallData: ""});
        }
    }

    function _addPreRuntimeValidationHook() internal {
        ExecutionManifest memory m; // empty manifest

        preValidationHook = new MockModule(m);

        bytes[] memory hooks = new bytes[](1);
        hooks[0] =
            abi.encodePacked(HookConfigLib.packValidationHook({_module: address(preValidationHook), _entityId: 1}));

        account1.installValidation({
            validationConfig: ValidationConfigLib.pack({
                _validationFunction: _validationFunction,
                _isGlobal: true,
                _isSignatureValidation: true,
                _isUserOpValidation: true
            }),
            selectors: new bytes4[](0),
            installData: "",
            hooks: hooks
        });
    }
}
