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

import {
    IModularAccount,
    ModuleEntity,
    ValidationConfig
} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract DeferredValidationTest is AccountTestBase {
    using ValidationConfigLib for ValidationConfig;

    bytes internal _encodedCall;
    ModuleEntity internal _deferredValidation;
    // The ABI-encoded call to `installValidation(...)` to be used with deferred validation install
    bytes internal _deferredValidationInstallCall;
    ValidationConfig internal _newUOValidation;

    // The new signing key to be added via deferred validation install.
    // The public address is included as part of _deferredValidationInstallCall
    uint256 internal _newSignerKey;

    function setUp() public override {
        _revertSnapshot = vm.snapshotState();
        _encodedCall = abi.encodeCall(ModularAccountBase.execute, (makeAddr("dead"), 0, ""));
        _deferredValidation = ModuleEntityLib.pack(address(_deploySingleSignerValidationModule()), 0);
        uint32 entityId = 0;

        (address newSigner, uint256 newSignerKey) = makeAddrAndKey("newSigner");
        _newSignerKey = newSignerKey;
        bytes memory deferredValidationInstallData = abi.encode(entityId, newSigner);

        _newUOValidation = ValidationConfigLib.pack({
            _validationFunction: _deferredValidation,
            _isGlobal: true,
            _isSignatureValidation: false,
            _isUserOpValidation: true
        });

        _deferredValidationInstallCall = abi.encodeCall(
            IModularAccount.installValidation,
            (_newUOValidation, new bytes4[](0), deferredValidationInstallData, new bytes[](0))
        );
    }

    // Negatives

    function test_fail_deferredValidation_nonceUsed() external withSMATest {
        uint256 nonce = entryPoint.getNonce(address(account1), 0);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: nonce,
            initCode: hex"",
            callData: _encodedCall,
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(_newSignerKey, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        bytes memory uoSig = _packFinalSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        uint256 deferredInstallNonce = 0;
        uint48 deferredInstallDeadline = 0;

        userOp.signature = _buildFullDeferredInstallSig(
            deferredInstallNonce,
            deferredInstallDeadline,
            _deferredValidationInstallCall,
            _newUOValidation,
            account1,
            owner1Key,
            uoSig
        );

        _sendOp(userOp, "");

        bytes memory expectedRevertData = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodeWithSelector(ModularAccountBase.DeferredActionNonceInvalid.selector)
        );

        _sendOp(userOp, expectedRevertData);
    }

    function test_fail_deferredValidation_pastDeadline() external withSMATest {
        // Note that a deadline of 0 implies no expiry
        vm.warp(2);

        uint256 nonce = entryPoint.getNonce(address(account1), 0);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: nonce,
            initCode: hex"",
            callData: _encodedCall,
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(_newSignerKey, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        bytes memory uoSig = _packFinalSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        uint256 deferredInstallNonce = 0;
        uint48 deferredInstallDeadline = 1;

        userOp.signature = _buildFullDeferredInstallSig(
            deferredInstallNonce,
            deferredInstallDeadline,
            _deferredValidationInstallCall,
            _newUOValidation,
            account1,
            owner1Key,
            uoSig
        );

        bytes memory expectedRevertData =
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA22 expired or not due");

        _sendOp(userOp, expectedRevertData);
    }

    function test_fail_deferredValidation_invalidSig() external withSMATest {
        uint256 nonce = entryPoint.getNonce(address(account1), 0);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: nonce,
            initCode: hex"",
            callData: _encodedCall,
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(_newSignerKey, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        bytes memory uoSig = _packFinalSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        uint256 deferredInstallNonce = 0;
        uint48 deferredInstallDeadline = 0;

        (, uint256 badSigningKey) = makeAddrAndKey("bad");

        userOp.signature = _buildFullDeferredInstallSig(
            deferredInstallNonce,
            deferredInstallDeadline,
            _deferredValidationInstallCall,
            _newUOValidation,
            account1,
            badSigningKey,
            uoSig
        );

        bytes memory expectedRevertData = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodeWithSelector(ModularAccountBase.DeferredActionSignatureInvalid.selector)
        );

        _sendOp(userOp, expectedRevertData);
    }

    function test_fail_deferredValidation_nonceInvalidated() external withSMATest {
        vm.prank(address(entryPoint));
        account1.invalidateDeferredValidationInstallNonce(0);

        uint256 nonce = entryPoint.getNonce(address(account1), 0);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: nonce,
            initCode: hex"",
            callData: _encodedCall,
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(_newSignerKey, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        bytes memory uoSig = _packFinalSignature(abi.encodePacked(r, s, v));

        uint256 deferredInstallNonce = 0;
        uint48 deferredInstallDeadline = 0;

        userOp.signature = _buildFullDeferredInstallSig(
            deferredInstallNonce,
            deferredInstallDeadline,
            _deferredValidationInstallCall,
            _newUOValidation,
            account1,
            owner1Key,
            uoSig
        );

        bytes memory expectedRevertData = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodeWithSelector(ModularAccountBase.DeferredActionNonceInvalid.selector)
        );

        _sendOp(userOp, expectedRevertData);
    }

    function test_fail_deferredValidation_invalidDeferredValidationSig() external withSMATest {
        uint256 nonce = entryPoint.getNonce(address(account1), 0);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: nonce,
            initCode: hex"",
            callData: _encodedCall,
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v,, bytes32 s) = vm.sign(_newSignerKey, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        bytes32 r = keccak256("invalid");
        bytes memory uoSig = _packFinalSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        uint256 deferredInstallNonce = 0;
        uint48 deferredInstallDeadline = 0;

        userOp.signature = _buildFullDeferredInstallSig(
            deferredInstallNonce,
            deferredInstallDeadline,
            _deferredValidationInstallCall,
            _newUOValidation,
            account1,
            owner1Key,
            uoSig
        );

        bytes memory expectedRevertData =
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error");

        _sendOp(userOp, expectedRevertData);
    }

    // Positives

    function test_deferredValidation_deployed() external withSMATest {
        uint256 nonce = entryPoint.getNonce(address(account1), 0);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: nonce,
            initCode: hex"",
            callData: _encodedCall,
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(_newSignerKey, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        bytes memory uoSig = _packFinalSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        uint256 deferredInstallNonce = 0;
        uint48 deferredInstallDeadline = 0;

        userOp.signature = _buildFullDeferredInstallSig(
            deferredInstallNonce,
            deferredInstallDeadline,
            _deferredValidationInstallCall,
            _newUOValidation,
            account1,
            owner1Key,
            uoSig
        );

        _sendOp(userOp, "");
    }

    function test_deferredValidation_initCode() external withSMATest {
        ModularAccount account2;
        bytes memory initCode;

        if (_isSMATest) {
            account2 = ModularAccount(payable(factory.getAddressSemiModular(owner1, 1)));
            initCode =
                abi.encodePacked(address(factory), abi.encodeCall(factory.createSemiModularAccount, (owner1, 1)));
        } else {
            account2 = ModularAccount(payable(factory.getAddress(owner1, 1, TEST_DEFAULT_VALIDATION_ENTITY_ID)));
            initCode = abi.encodePacked(
                address(factory),
                abi.encodeCall(factory.createAccount, (owner1, 1, TEST_DEFAULT_VALIDATION_ENTITY_ID))
            );
        }

        // prefund
        vm.deal(address(account2), 100 ether);

        uint256 nonce = entryPoint.getNonce(address(account1), 0);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account2),
            nonce: nonce,
            initCode: initCode,
            callData: _encodedCall,
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(_newSignerKey, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        bytes memory uoSig = _packFinalSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        uint256 deferredInstallNonce = 0;
        uint48 deferredInstallDeadline = 0;

        userOp.signature = _buildFullDeferredInstallSig(
            deferredInstallNonce,
            deferredInstallDeadline,
            _deferredValidationInstallCall,
            _newUOValidation,
            account2,
            owner1Key,
            uoSig
        );

        _sendOp(userOp, "");
    }

    function _sendOp(PackedUserOperation memory userOp, bytes memory expectedRevertData) internal {
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        if (expectedRevertData.length > 0) {
            vm.expectRevert(expectedRevertData);
        }
        entryPoint.handleOps(userOps, beneficiary);
    }
}
