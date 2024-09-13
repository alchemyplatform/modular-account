// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {SemiModularAccount} from "../../src/account/SemiModularAccount.sol";

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {ValidationConfig, ValidationConfigLib} from "../../src/helpers/ValidationConfigLib.sol";

import {MockUserOpValidationModule} from "../mocks/modules/ValidationModuleMocks.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract DeferredValidationTest is AccountTestBase {
    using ValidationConfigLib for ValidationConfig;
    using MessageHashUtils for bytes32;

    bytes32 private constant _INSTALL_VALIDATION_TYPEHASH = keccak256(
        "InstallValidation(bytes25 validationConfig,bytes4[] selectors,bytes installData,bytes[] hooks,uint256 nonce)"
    );

    address internal _mockValidation;

    function setUp() external {
        _mockValidation = address(new MockUserOpValidationModule()); // todo consider return data
    }

    function test_fail_deferredValidation_NonceUsed() external {
        bytes memory encodedCall = abi.encodeCall(ModularAccount.execute, (makeAddr("dead"), 0, ""));
        _runUserOpWithCustomSig(encodedCall, "", _buildSig(0));

        bytes memory expectedRevertdata = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodeWithSelector(ModularAccount.DeferredInstallNonceUsed.selector)
        );

        _runUserOpWithCustomSig(encodedCall, expectedRevertdata, _buildSig(0));
    }

    function test_deferredValidation() external {
        bytes memory encodedCall = abi.encodeCall(ModularAccount.execute, (makeAddr("dead"), 0, ""));
        _runUserOpWithCustomSig(encodedCall, "", _buildSig(0));
    }

    function _buildSig(uint256 nonce) internal view returns (bytes memory) {
        /**
         * Deferred validation signature structure:
         * bytes 0-23: Outer validation moduleEntity (the validation used to validate the installation of the inner
         * validation)
         * byte    24: Validation flags (rightmost bit == isGlobal, second-to-rightmost bit ==
         * isDeferredValidationInstall)
         *
         * This is where things diverge, if this is a deferred validation install, rather than using the remaining
         * signature data
         * as validation data, we decode it as follows:
         *
         * bytes 25-28: uint32, abi-encoded parameters length (e.g. 100)
         * bytes 29-128: (example) : abi-encoded parameters
         * bytes 129-132: deferred install validation sig length (e.g. 68)
         * bytes 133-200 (example): install validation sig data (the data passed to the outer validation to
         * validate the deferred installation)
         * bytes 201...: signature data passed to the newly installed deferred validation to validate the UO
         */
        uint8 outerValidationFlags = 3;

        ValidationConfig deferredConfig = ValidationConfigLib.pack({
            _module: _mockValidation,
            _entityId: uint32(0),
            _isGlobal: true,
            _isSignatureValidation: false,
            _isUserOpValidation: true
        });

        bytes memory deferredInstallData = abi.encode(deferredConfig, new bytes4[](0), "", new bytes[](0), nonce);

        uint32 encodedDeferredInstallDataLength = uint32(deferredInstallData.length);

        bytes32 domainSeparator = account1.getDomainSeparator();

        bytes32 structHash = keccak256(
            abi.encode(_INSTALL_VALIDATION_TYPEHASH, deferredConfig, new bytes4[](0), "", new bytes[](0), nonce)
        );
        bytes32 typedDataHash = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

        bytes32 replaySafeHash = vm.envOr("SMA_TEST", false)
            ? SemiModularAccount(payable(account1)).replaySafeHash(typedDataHash)
            : singleSignerValidationModule.replaySafeHash(address(account1), typedDataHash);

        bytes memory deferredInstallSig = _getDeferredInstallSig(replaySafeHash);

        bytes memory innerUoValidationSig = _packValidationResWithIndex(255, hex"1234");

        bytes memory encodedDeferredInstall = abi.encodePacked(
            _signerValidation,
            outerValidationFlags,
            encodedDeferredInstallDataLength,
            deferredInstallData,
            uint32(deferredInstallSig.length),
            deferredInstallSig,
            innerUoValidationSig
        );

        return encodedDeferredInstall;
    }

    function _getDeferredInstallSig(bytes32 replaySafeHash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, replaySafeHash);

        bytes memory rawDeferredInstallSig = abi.encodePacked(r, s, v);

        bytes memory deferredInstallSig = _packValidationResWithIndex(255, rawDeferredInstallSig);
        return deferredInstallSig;
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

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        if (expectedRevertData.length > 0) {
            vm.expectRevert(expectedRevertData);
        }
        entryPoint.handleOps(userOps, beneficiary);
    }
}
