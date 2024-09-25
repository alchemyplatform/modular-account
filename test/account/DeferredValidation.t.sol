// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {ModularAccount} from "../../src/account/ModularAccount.sol";

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ModuleEntity, ModuleEntityLib} from "../../src/libraries/ModuleEntityLib.sol";
import {ValidationConfig, ValidationConfigLib} from "../../src/libraries/ValidationConfigLib.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract DeferredValidationTest is AccountTestBase {
    using ValidationConfigLib for ValidationConfig;

    bytes32 private constant _INSTALL_VALIDATION_TYPEHASH = keccak256(
        // solhint-disable-next-line max-line-length
        "InstallValidation(bytes25 validationConfig,bytes4[] selectors,bytes installData,bytes[] hooks,uint256 nonce,uint48 deadline)"
    );

    bytes internal _encodedCall;
    ModuleEntity internal _deferredValidation;
    bool internal _isSmaTest;
    bytes internal _deferredValidationInstallData;

    function setUp() external {
        _encodedCall = abi.encodeCall(ModularAccount.execute, (makeAddr("dead"), 0, ""));
        _deferredValidation = ModuleEntityLib.pack(address(_deploySingleSignerValidationModule()), 0);
        _isSmaTest = vm.envOr("SMA_TEST", false);

        uint32 entityId = 0;
        _deferredValidationInstallData = abi.encode(entityId, owner1);
    }

    // Negatives

    function test_fail_deferredValidation_nonceUsed() external {
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        bytes memory deferredValidationSig = abi.encodePacked(r, s, v);

        userOp.signature = _buildFullDeferredInstallSig(
            vm,
            owner1Key,
            _isSmaTest,
            account1,
            _signerValidation,
            _deferredValidation,
            _deferredValidationInstallData,
            deferredValidationSig,
            0,
            0
        );

        _sendOp(userOp, "");

        bytes memory expectedRevertdata = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodeWithSelector(ModularAccount.DeferredInstallNonceInvalid.selector)
        );

        _sendOp(userOp, expectedRevertdata);
    }

    function test_fail_deferredValidation_pastDeadline() external {
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        bytes memory deferredValidationSig = abi.encodePacked(r, s, v);

        userOp.signature = _buildFullDeferredInstallSig(
            vm,
            owner1Key,
            _isSmaTest,
            account1,
            _signerValidation,
            _deferredValidation,
            _deferredValidationInstallData,
            deferredValidationSig,
            0,
            1
        );

        bytes memory expectedRevertdata =
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA22 expired or not due");

        _sendOp(userOp, expectedRevertdata);
    }

    function test_fail_deferredValidation_invalidSig() external {
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        bytes memory deferredValidationSig = abi.encodePacked(r, s, v);

        userOp.signature = _buildFullDeferredInstallSig(
            vm,
            owner1Key,
            _isSmaTest,
            ModularAccount(payable(0)),
            _signerValidation,
            _deferredValidation,
            _deferredValidationInstallData,
            deferredValidationSig,
            0,
            0
        );

        bytes memory expectedRevertData = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodeWithSelector(ModularAccount.DeferredInstallSignatureInvalid.selector)
        );

        _sendOp(userOp, expectedRevertData);
    }

    function test_fail_deferredValidation_nonceInvalidated() external {
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        bytes memory deferredValidationSig = abi.encodePacked(r, s, v);

        userOp.signature = _buildFullDeferredInstallSig(
            vm,
            owner1Key,
            _isSmaTest,
            account1,
            _signerValidation,
            _deferredValidation,
            _deferredValidationInstallData,
            deferredValidationSig,
            0,
            0
        );

        bytes memory expectedRevertdata = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodeWithSelector(ModularAccount.DeferredInstallNonceInvalid.selector)
        );

        _sendOp(userOp, expectedRevertdata);
    }

    function test_fail_deferredValidation_invalidDeferredValidationSig() external {
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
        (uint8 v,, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        bytes32 r = keccak256("invalid");
        bytes memory deferredValidationSig = abi.encodePacked(r, s, v);

        userOp.signature = _buildFullDeferredInstallSig(
            vm,
            owner1Key,
            _isSmaTest,
            account1,
            _signerValidation,
            _deferredValidation,
            _deferredValidationInstallData,
            deferredValidationSig,
            0,
            0
        );

        bytes memory expectedRevertdata =
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error");

        _sendOp(userOp, expectedRevertdata);
    }

    // Positives

    function test_deferredValidation() external {
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        bytes memory deferredValidationSig = abi.encodePacked(r, s, v);

        userOp.signature = _buildFullDeferredInstallSig(
            vm,
            owner1Key,
            _isSmaTest,
            account1,
            _signerValidation,
            _deferredValidation,
            _deferredValidationInstallData,
            deferredValidationSig,
            0,
            0
        );

        _sendOp(userOp, "");
    }

    function test_deferredValidation_initCode() external {
        ModularAccount account2;
        bytes memory initCode;

        if (_isSmaTest) {
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        bytes memory deferredValidationSig = abi.encodePacked(r, s, v);

        userOp.signature = _buildFullDeferredInstallSig(
            vm,
            owner1Key,
            _isSmaTest,
            account2,
            _signerValidation,
            _deferredValidation,
            _deferredValidationInstallData,
            deferredValidationSig,
            0,
            0
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
