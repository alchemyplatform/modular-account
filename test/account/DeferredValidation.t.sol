// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {ModularAccount} from "../../src/account/ModularAccount.sol";

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {ModuleEntity, ModuleEntityLib} from "../../src/libraries/ModuleEntityLib.sol";
import {ValidationConfig, ValidationConfigLib} from "../../src/libraries/ValidationConfigLib.sol";

import {MockUserOpValidationModule} from "../mocks/modules/ValidationModuleMocks.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract DeferredValidationTest is AccountTestBase {
    using ValidationConfigLib for ValidationConfig;

    bytes32 private constant _INSTALL_VALIDATION_TYPEHASH = keccak256(
        // solhint-disable-next-line max-line-length
        "InstallValidation(bytes25 validationConfig,bytes4[] selectors,bytes installData,bytes[] hooks,uint256 nonce,uint48 deadline)"
    );

    bytes internal _encodedCall = abi.encodeCall(ModularAccount.execute, (makeAddr("dead"), 0, ""));
    ModuleEntity internal _mockValidation;
    bool internal _isSmaTest;
    bytes internal _deferredValidationSig;

    function setUp() external {
        _mockValidation = ModuleEntityLib.pack(address(new MockUserOpValidationModule()), 0); // todo consider
            // return data
        _isSmaTest = vm.envOr("SMA_TEST", false);
    }

    // Negatives

    function test_fail_deferredValidation_nonceUsed() external {
        _runUserOpWithCustomSig(
            _encodedCall,
            "",
            _buildFullDeferredInstallSig(
                vm,
                owner1Key,
                _isSmaTest,
                account1,
                _signerValidation,
                _mockValidation,
                _deferredValidationSig,
                0,
                0
            )
        );

        bytes memory expectedRevertdata = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodeWithSelector(ModularAccount.DeferredInstallNonceInvalid.selector)
        );

        _runUserOpWithCustomSig(
            _encodedCall,
            expectedRevertdata,
            _buildFullDeferredInstallSig(
                vm,
                owner1Key,
                _isSmaTest,
                account1,
                _signerValidation,
                _mockValidation,
                _deferredValidationSig,
                0,
                0
            )
        );
    }

    function test_fail_deferredValidation_pastDeadline() external {
        bytes memory expectedRevertdata =
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA22 expired or not due");

        // Note that a deadline of 0 implies no expiry
        vm.warp(2);
        _runUserOpWithCustomSig(
            _encodedCall,
            expectedRevertdata,
            _buildFullDeferredInstallSig(
                vm,
                owner1Key,
                _isSmaTest,
                account1,
                _signerValidation,
                _mockValidation,
                _deferredValidationSig,
                0,
                1
            )
        );
    }

    function test_fail_deferredValidation_invalidSig() external {
        bytes memory expectedRevertData = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodeWithSelector(ModularAccount.DeferredInstallSignatureInvalid.selector)
        );
        _runUserOpWithCustomSig(
            _encodedCall,
            expectedRevertData,
            _buildFullDeferredInstallSig(
                vm,
                owner1Key,
                _isSmaTest,
                ModularAccount(payable(0)),
                _signerValidation,
                _mockValidation,
                _deferredValidationSig,
                0,
                0
            )
        );
    }

    function test_fail_deferredValidation_nonceInvalidated() external {
        vm.prank(address(entryPoint));
        account1.invalidateDeferredValidationInstallNonce(0);

        bytes memory expectedRevertdata = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodeWithSelector(ModularAccount.DeferredInstallNonceInvalid.selector)
        );

        _runUserOpWithCustomSig(
            _encodedCall,
            expectedRevertdata,
            _buildFullDeferredInstallSig(
                vm,
                owner1Key,
                _isSmaTest,
                account1,
                _signerValidation,
                _mockValidation,
                _deferredValidationSig,
                0,
                0
            )
        );
    }

    // TODO: Test with hooks
    // Positives

    function test_deferredValidation() external {
        _runUserOpWithCustomSig(
            _encodedCall,
            "",
            _buildFullDeferredInstallSig(
                vm,
                owner1Key,
                _isSmaTest,
                account1,
                _signerValidation,
                _mockValidation,
                _deferredValidationSig,
                0,
                0
            )
        );
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

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account2),
            nonce: 0,
            initCode: initCode,
            callData: _encodedCall,
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 2),
            paymasterAndData: "",
            signature: _buildFullDeferredInstallSig(
                vm, owner1Key, _isSmaTest, account2, _signerValidation, _mockValidation, _deferredValidationSig, 0, 0
            )
        });

        _sendOp(userOp, "");
    }

    function _runUserOpWithCustomSig(bytes memory callData, bytes memory expectedRevertData, bytes memory sig)
        internal
    {
        uint256 nonce = entryPoint.getNonce(address(account1), 0);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: nonce,
            initCode: hex"",
            callData: callData,
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: sig
        });

        _sendOp(userOp, expectedRevertData);
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
