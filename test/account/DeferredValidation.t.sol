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
        // solhint-disable-next-line max-line-length
        "InstallValidation(bytes25 validationConfig,bytes4[] selectors,bytes installData,bytes[] hooks,uint256 nonce,uint48 deadline)"
    );

    bytes internal _encodedCall = abi.encodeCall(ModularAccount.execute, (makeAddr("dead"), 0, ""));
    address internal _mockValidation;

    function setUp() external {
        _mockValidation = address(new MockUserOpValidationModule()); // todo consider return data
    }

    // Negatives

    function test_fail_deferredValidation_NonceUsed() external {
        _runUserOpWithCustomSig(_encodedCall, "", _buildSig(account1, 0, 0));

        bytes memory expectedRevertdata = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodeWithSelector(ModularAccount.DeferredInstallNonceUsed.selector)
        );

        _runUserOpWithCustomSig(
            _encodedCall, expectedRevertdata, _buildSig(account1, 0, 0)
        );
    }

    // TODO: Test deadline

    // Positives

    function test_deferredValidation() external {
        _runUserOpWithCustomSig(_encodedCall, "", _buildSig(account1, 0, 0));
    }

    function test_deferredValidation_initCode() external {
        ModularAccount account2;
        bytes memory initCode;
        if (vm.envOr("SMA_TEST", false)) {
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
            signature: _buildSig(account2, 0, 0)
        });

        _sendOp(userOp, "");
    }

    // Internal Helpers

    function _buildSig(ModularAccount account, uint256 nonce, uint48 deadline)
        internal
        view
        returns (bytes memory)
    {
        /**
         * Deferred validation signature structure:
         * bytes 0-23: Outer validation moduleEntity (the validation used to validate the installation of the inner
         * validation)
         * byte 24   : Validation flags (rightmost bit == isGlobal, second-to-rightmost bit ==
         * isDeferredValidationInstall)
         *
         * This is where things diverge, if this is a deferred validation install, rather than using the remaining
         * signature data as validation data, we decode it as follows:
         *
         * bytes 25-28            : uint32, abi-encoded parameters length (e.g. 100)
         * bytes 29-128 (example) : abi-encoded parameters
         * bytes 129-132          : deferred install validation sig length (e.g. 68)
         * bytes 133-200 (example): install validation sig data (the data passed to the outer validation to
         * validate the deferred installation)
         * bytes 201...           : signature data passed to the newly installed deferred validation to validate
         * the UO
         */
        uint8 outerValidationFlags = 3;

        ValidationConfig deferredConfig = ValidationConfigLib.pack({
            _module: _mockValidation,
            _entityId: uint32(0),
            _isGlobal: true,
            _isSignatureValidation: false,
            _isUserOpValidation: true
        });

        bytes memory deferredInstallData =
            abi.encode(deferredConfig, new bytes4[](0), "", new bytes[](0), nonce, deadline);

        bytes32 domainSeparator;

        // Needed for initCode txs
        if (address(account).code.length > 0) {
            domainSeparator = account.getDomainSeparator();
        } else {
            domainSeparator = _computeDomainSeparatorNotDeployed(account);
        }

        bytes32 structHash = keccak256(
            abi.encode(
                _INSTALL_VALIDATION_TYPEHASH, deferredConfig, new bytes4[](0), "", new bytes[](0), nonce, deadline
            )
        );
        bytes32 typedDataHash = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

        bytes32 replaySafeHash = vm.envOr("SMA_TEST", false)
            ? _getSmaReplaySafeHash(account, typedDataHash)
            : singleSignerValidationModule.replaySafeHash(address(account), typedDataHash);

        bytes memory deferredInstallSig = _getDeferredInstallSig(replaySafeHash);

        bytes memory innerUoValidationSig = _packValidationResWithIndex(255, hex"1234");

        bytes memory encodedDeferredInstall = abi.encodePacked(
            _signerValidation,
            outerValidationFlags,
            uint32(deferredInstallData.length),
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

    function _computeDomainSeparatorNotDeployed(ModularAccount account) internal view returns (bytes32) {
        bytes32 domainSeparatorTypehash = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;
        return keccak256(abi.encode(domainSeparatorTypehash, block.chainid, address(account)));
    }

    function _getSmaReplaySafeHash(ModularAccount account, bytes32 typedDataHash)
        internal
        view
        returns (bytes32)
    {
        if (address(account).code.length > 0) {
            return SemiModularAccount(payable(account)).replaySafeHash(typedDataHash);
        } else {
            // precompute it as the SMA is not yet deployed
            // for SMA, the domain separator used for the deferred validation installation is the same as the one
            // used to compute the replay safe hash.
            return MessageHashUtils.toTypedDataHash({
                domainSeparator: _computeDomainSeparatorNotDeployed(account),
                structHash: _hashStruct(typedDataHash)
            });
        }
    }

    function _hashStruct(bytes32 hash) internal pure virtual returns (bytes32) {
        bytes32 replaySafeTypehash = keccak256("ReplaySafeHash(bytes32 hash)"); // const 0x.. in contract
        bytes32 res;
        assembly ("memory-safe") {
            mstore(0x00, replaySafeTypehash)
            mstore(0x20, hash)
            res := keccak256(0, 0x40)
        }
        return res;
    }
}
