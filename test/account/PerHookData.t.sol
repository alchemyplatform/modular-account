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

import {ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {SparseCalldataSegmentLib} from "@erc6900/reference-implementation/libraries/SparseCalldataSegmentLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {ExecutionLib} from "../../src/libraries/ExecutionLib.sol";

import {Counter} from "../mocks/Counter.sol";
import {MockAccessControlHookModule} from "../mocks/modules/MockAccessControlHookModule.sol";
import {CustomValidationTestBase} from "../utils/CustomValidationTestBase.sol";

contract PerHookDataTest is CustomValidationTestBase {
    using MessageHashUtils for bytes32;

    MockAccessControlHookModule internal _accessControlHookModule;

    Counter internal _counter;

    uint32 internal constant _VALIDATION_ENTITY_ID = 0;
    uint32 internal constant _PRE_HOOK_ENTITY_ID_1 = 0;
    uint32 internal constant _PRE_HOOK_ENTITY_ID_2 = 1;

    function setUp() public override {
        _revertSnapshot = vm.snapshotState();
        _counter = new Counter();

        _accessControlHookModule = new MockAccessControlHookModule();

        _customValidationSetup();
    }

    function test_passAccessControl_userOp() public withSMATest {
        assertEq(_counter.number(), 0);

        (PackedUserOperation memory userOp, bytes32 userOpHash) = _getCounterUserOP();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());

        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: abi.encodePacked(_counter)});

        userOp.signature = _encodeSignature(
            _signerValidation,
            GLOBAL_VALIDATION,
            preValidationHookData,
            abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v)
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(_counter.number(), 1);
    }

    function test_failAccessControl_badSigData_userOp() public withSMATest {
        (PackedUserOperation memory userOp, bytes32 userOpHash) = _getCounterUserOP();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());

        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({
            index: 0,
            validationData: abi.encodePacked(address(0x1234123412341234123412341234123412341234))
        });

        userOp.signature = _encodeSignature(
            _signerValidation, GLOBAL_VALIDATION, preValidationHookData, abi.encodePacked(r, s, v)
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(
                    ExecutionLib.PreUserOpValidationHookReverted.selector,
                    ModuleEntityLib.pack(address(_accessControlHookModule), _PRE_HOOK_ENTITY_ID_1),
                    abi.encodeWithSignature("Error(string)", "Proof doesn't match target")
                )
            )
        );
        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_failAccessControl_noSigData_userOp() public withSMATest {
        (PackedUserOperation memory userOp, bytes32 userOpHash) = _getCounterUserOP();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());

        userOp.signature = _encodeSignature(_signerValidation, GLOBAL_VALIDATION, abi.encodePacked(r, s, v));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(
                    ExecutionLib.PreUserOpValidationHookReverted.selector,
                    ModuleEntityLib.pack(address(_accessControlHookModule), _PRE_HOOK_ENTITY_ID_1),
                    abi.encodeWithSignature("Error(string)", "Proof doesn't match target")
                )
            )
        );
        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_failAccessControl_badIndexProvided_userOp() public withSMATest {
        (PackedUserOperation memory userOp, bytes32 userOpHash) = _getCounterUserOP();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());

        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](2);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: abi.encodePacked(_counter)});
        preValidationHookData[1] = PreValidationHookData({index: 1, validationData: abi.encodePacked(_counter)});

        userOp.signature = _encodeSignature(
            _signerValidation, GLOBAL_VALIDATION, preValidationHookData, abi.encodePacked(r, s, v)
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(SparseCalldataSegmentLib.ValidationSignatureSegmentMissing.selector)
            )
        );
        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_passAccessControl_twoHooks_userOp() public withSMATest {
        _installSecondPreHook();

        assertEq(_counter.number(), 0);

        (PackedUserOperation memory userOp, bytes32 userOpHash) = _getCounterUserOP();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());

        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](2);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: abi.encodePacked(_counter)});
        preValidationHookData[1] = PreValidationHookData({index: 1, validationData: abi.encodePacked(_counter)});

        userOp.signature = _encodeSignature(
            _signerValidation,
            GLOBAL_VALIDATION,
            preValidationHookData,
            abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v)
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(_counter.number(), 1);
    }

    function test_failAccessControl_indexOutOfOrder_userOp() public withSMATest {
        _installSecondPreHook();

        (PackedUserOperation memory userOp, bytes32 userOpHash) = _getCounterUserOP();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());

        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](3);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: abi.encodePacked(_counter)});
        preValidationHookData[1] = PreValidationHookData({index: 0, validationData: abi.encodePacked(_counter)});

        userOp.signature = _encodeSignature(
            _signerValidation, GLOBAL_VALIDATION, preValidationHookData, abi.encodePacked(r, s, v)
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(SparseCalldataSegmentLib.SegmentOutOfOrder.selector)
            )
        );
        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_failAccessControl_badTarget_userOp() public withSMATest {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(ModularAccountBase.execute, (beneficiary, 1 wei, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());

        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: abi.encodePacked(beneficiary)});

        userOp.signature = _encodeSignature(
            _signerValidation, GLOBAL_VALIDATION, preValidationHookData, abi.encodePacked(r, s, v)
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(
                    ExecutionLib.PreUserOpValidationHookReverted.selector,
                    ModuleEntityLib.pack(address(_accessControlHookModule), _PRE_HOOK_ENTITY_ID_1),
                    abi.encodeWithSignature("Error(string)", "Target not allowed")
                )
            )
        );
        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_failPerHookData_nonCanonicalEncoding_userOp() public withSMATest {
        (PackedUserOperation memory userOp, bytes32 userOpHash) = _getCounterUserOP();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());

        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: ""});

        userOp.signature = _encodeSignature(
            _signerValidation, GLOBAL_VALIDATION, preValidationHookData, abi.encodePacked(r, s, v)
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(SparseCalldataSegmentLib.NonCanonicalEncoding.selector)
            )
        );
        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_passAccessControl_runtime() public withSMATest {
        assertEq(_counter.number(), 0);

        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: abi.encodePacked(_counter)});

        vm.prank(owner1);
        account1.executeWithRuntimeValidation(
            abi.encodeCall(
                ModularAccountBase.execute, (address(_counter), 0 wei, abi.encodeCall(Counter.increment, ()))
            ),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, preValidationHookData, "")
        );

        assertEq(_counter.number(), 1);
    }

    function test_failAccessControl_badSigData_runtime() public withSMATest {
        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({
            index: 0,
            validationData: abi.encodePacked(address(0x1234123412341234123412341234123412341234))
        });

        vm.prank(owner1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionLib.PreRuntimeValidationHookReverted.selector,
                ModuleEntityLib.pack(address(_accessControlHookModule), _PRE_HOOK_ENTITY_ID_1),
                abi.encodeWithSignature("Error(string)", "Proof doesn't match target")
            )
        );
        account1.executeWithRuntimeValidation(
            abi.encodeCall(
                ModularAccountBase.execute, (address(_counter), 0 wei, abi.encodeCall(Counter.increment, ()))
            ),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, preValidationHookData, "")
        );
    }

    function test_failAccessControl_noSigData_runtime() public withSMATest {
        vm.prank(owner1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionLib.PreRuntimeValidationHookReverted.selector,
                ModuleEntityLib.pack(address(_accessControlHookModule), _PRE_HOOK_ENTITY_ID_1),
                abi.encodeWithSignature("Error(string)", "Proof doesn't match target")
            )
        );
        account1.executeWithRuntimeValidation(
            abi.encodeCall(
                ModularAccountBase.execute, (address(_counter), 0 wei, abi.encodeCall(Counter.increment, ()))
            ),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
        );
    }

    function test_failAccessControl_badIndexProvided_runtime() public withSMATest {
        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](2);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: abi.encodePacked(_counter)});
        preValidationHookData[1] = PreValidationHookData({index: 1, validationData: abi.encodePacked(_counter)});

        vm.prank(owner1);
        vm.expectRevert(
            abi.encodeWithSelector(SparseCalldataSegmentLib.ValidationSignatureSegmentMissing.selector)
        );
        account1.executeWithRuntimeValidation(
            abi.encodeCall(
                ModularAccountBase.execute, (address(_counter), 0 wei, abi.encodeCall(Counter.increment, ()))
            ),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, preValidationHookData, "")
        );
    }

    function test_passAccessControl_twoHooks_runtime() public withSMATest {
        _installSecondPreHook();

        assertEq(_counter.number(), 0);

        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](2);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: abi.encodePacked(_counter)});
        preValidationHookData[1] = PreValidationHookData({index: 1, validationData: abi.encodePacked(_counter)});

        vm.prank(owner1);
        account1.executeWithRuntimeValidation(
            abi.encodeCall(
                ModularAccountBase.execute, (address(_counter), 0 wei, abi.encodeCall(Counter.increment, ()))
            ),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, preValidationHookData, "")
        );

        assertEq(_counter.number(), 1);
    }

    function test_failAccessControl_indexOutOfOrder_runtime() public withSMATest {
        _installSecondPreHook();

        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](3);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: abi.encodePacked(_counter)});
        preValidationHookData[1] = PreValidationHookData({index: 0, validationData: abi.encodePacked(_counter)});

        vm.prank(owner1);
        vm.expectRevert(abi.encodeWithSelector(SparseCalldataSegmentLib.SegmentOutOfOrder.selector));
        account1.executeWithRuntimeValidation(
            abi.encodeCall(
                ModularAccountBase.execute, (address(_counter), 0 wei, abi.encodeCall(Counter.increment, ()))
            ),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, preValidationHookData, "")
        );
    }

    function test_failAccessControl_badTarget_runtime() public withSMATest {
        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: abi.encodePacked(beneficiary)});

        vm.prank(owner1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionLib.PreRuntimeValidationHookReverted.selector,
                ModuleEntityLib.pack(address(_accessControlHookModule), _PRE_HOOK_ENTITY_ID_1),
                abi.encodeWithSignature("Error(string)", "Target not allowed")
            )
        );
        account1.executeWithRuntimeValidation(
            abi.encodeCall(ModularAccountBase.execute, (beneficiary, 1 wei, "")),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, preValidationHookData, "")
        );
    }

    function test_failPerHookData_nonCanonicalEncoding_runtime() public withSMATest {
        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: ""});

        vm.prank(owner1);
        vm.expectRevert(abi.encodeWithSelector(SparseCalldataSegmentLib.NonCanonicalEncoding.selector));
        account1.executeWithRuntimeValidation(
            abi.encodeCall(
                ModularAccountBase.execute, (address(_counter), 0 wei, abi.encodeCall(Counter.increment, ()))
            ),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, preValidationHookData, "")
        );
    }

    function test_pass1271AccessControl() public withSMATest {
        bytes memory message = "Hello, world!";
        bytes32 messageHash = keccak256(message);

        // we use module validation for both cases
        bytes32 replaySafeHash =
            _getModuleReplaySafeHash(address(account1), address(singleSignerValidationModule), messageHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, replaySafeHash);

        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: message});

        bytes4 result = account1.isValidSignature(
            messageHash,
            _encode1271Signature(
                _signerValidation, preValidationHookData, abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v)
            )
        );

        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_fail1271AccessControl_badSigData() public withSMATest {
        string memory message = "Hello, world!";

        bytes32 messageHash = keccak256(abi.encodePacked(message));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, messageHash);

        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({
            index: 0,
            validationData: abi.encodePacked(address(0x1234123412341234123412341234123412341234))
        });

        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionLib.PreSignatureValidationHookReverted.selector,
                ModuleEntityLib.pack(address(_accessControlHookModule), _PRE_HOOK_ENTITY_ID_1),
                abi.encodeWithSignature("Error(string)", "Preimage not provided")
            )
        );
        account1.isValidSignature(
            messageHash,
            _encode1271Signature(
                _signerValidation, preValidationHookData, abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v)
            )
        );
    }

    function test_fail1271AccessControl_noSigData() public withSMATest {
        string memory message = "Hello, world!";

        bytes32 messageHash = keccak256(abi.encodePacked(message));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, messageHash);

        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionLib.PreSignatureValidationHookReverted.selector,
                ModuleEntityLib.pack(address(_accessControlHookModule), _PRE_HOOK_ENTITY_ID_1),
                abi.encodeWithSignature("Error(string)", "Preimage not provided")
            )
        );
        account1.isValidSignature(messageHash, _encode1271Signature(_signerValidation, abi.encodePacked(r, s, v)));
    }

    function _installSecondPreHook() internal {
        // depends on the ability of `installValidation` to append hooks
        bytes[] memory hooks = new bytes[](1);
        hooks[0] = abi.encodePacked(
            HookConfigLib.packValidationHook(address(_accessControlHookModule), _PRE_HOOK_ENTITY_ID_2),
            abi.encode(_PRE_HOOK_ENTITY_ID_2, _counter)
        );
        vm.prank(address(entryPoint));
        account1.installValidation(
            ValidationConfigLib.pack(_signerValidation, true, false, true), new bytes4[](0), "", hooks
        );
    }

    function _getCounterUserOP() internal view returns (PackedUserOperation memory, bytes32) {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(
                ModularAccountBase.execute, (address(_counter), 0 wei, abi.encodeCall(Counter.increment, ()))
            ),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        return (userOp, userOpHash);
    }

    // Test config

    function _initialValidationConfig()
        internal
        virtual
        override
        returns (ModuleEntity, bool, bool, bool, bytes4[] memory, bytes memory, bytes[] memory)
    {
        bytes[] memory hooks = new bytes[](1);
        hooks[0] = abi.encodePacked(
            HookConfigLib.packValidationHook(address(_accessControlHookModule), _PRE_HOOK_ENTITY_ID_1),
            abi.encode(_PRE_HOOK_ENTITY_ID_1, _counter)
        );
        // patched to work during SMA tests by enforcing that the new validation is not the fallback validation.
        _signerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), _VALIDATION_ENTITY_ID);
        return (
            _signerValidation, true, true, true, new bytes4[](0), abi.encode(_VALIDATION_ENTITY_ID, owner1), hooks
        );
    }
}
