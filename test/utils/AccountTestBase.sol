// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {
    Call, IModularAccount, ModuleEntity
} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {SemiModularAccountBytecode} from "../../src/account/SemiModularAccountBytecode.sol";
import {AccountFactory} from "../../src/factory/AccountFactory.sol";
import {DIRECT_CALL_VALIDATION_ENTITYID} from "../../src/helpers/Constants.sol";
import {FALLBACK_VALIDATION} from "../../src/helpers/Constants.sol";
import {ECDSAValidationModule} from "../../src/modules/validation/ECDSAValidationModule.sol";

import {ModuleSignatureUtils} from "./ModuleSignatureUtils.sol";
import {OptimizedTest} from "./OptimizedTest.sol";
import {TEST_DEFAULT_VALIDATION_ENTITY_ID as EXT_CONST_TEST_DEFAULT_VALIDATION_ENTITY_ID} from
    "./TestConstants.sol";

/// @dev This contract handles common boilerplate setup for tests using ModularAccount with
/// ECDSAValidationModule.
abstract contract AccountTestBase is OptimizedTest, ModuleSignatureUtils {
    using ModuleEntityLib for ModuleEntity;
    using MessageHashUtils for bytes32;

    EntryPoint public entryPoint;
    address payable public beneficiary;

    ECDSAValidationModule public ecdsaValidationModule;
    ModularAccount public accountImplementation;
    SemiModularAccountBytecode public semiModularAccountImplementation;
    AccountFactory public factory;

    address public factoryOwner;

    address public owner1;
    uint256 public owner1Key;
    ModularAccount public account1;

    bool internal _isSMATest;

    ModuleEntity internal _signerValidation;
    uint256 internal _revertSnapshot;

    // Re-declare the constant to prevent derived test contracts from having to import it
    uint32 public constant TEST_DEFAULT_VALIDATION_ENTITY_ID = EXT_CONST_TEST_DEFAULT_VALIDATION_ENTITY_ID;

    uint256 public constant CALL_GAS_LIMIT = 100_000;
    uint256 public constant VERIFICATION_GAS_LIMIT = 1_200_000;

    function setUp() public virtual {
        // Intentionally left blank
        // This should be overriden when needed and will be called again by the `withSMATest` modifier.
    }

    modifier withSMATest() {
        _;

        vm.revertTo(_revertSnapshot);

        _switchToSMA();

        setUp();

        _;
    }

    constructor() {
        entryPoint = _deployEntryPoint070();
        (owner1, owner1Key) = makeAddrAndKey("owner1");
        factoryOwner = makeAddr("factoryOwner");
        beneficiary = payable(makeAddr("beneficiary"));

        // address deployedECDSAValidationModule = address(_deployECDSAValidationModule());

        // We etch the single signer validation to the max address, such that it coincides with the fallback
        // validation module entity for semi modular account tests.
        ecdsaValidationModule = _deployECDSAValidationModule();
        // vm.etch(address(0), deployedECDSAValidationModule.code);

        accountImplementation = _deployModularAccount(entryPoint);

        semiModularAccountImplementation =
            SemiModularAccountBytecode(payable(_deploySemiModularAccountBytecode(entryPoint)));

        factory = new AccountFactory(
            entryPoint,
            accountImplementation,
            semiModularAccountImplementation,
            address(ecdsaValidationModule),
            factoryOwner
        );

        account1 = factory.createAccount(owner1, 0, TEST_DEFAULT_VALIDATION_ENTITY_ID);

        vm.deal(address(account1), 100 ether);

        _signerValidation = ModuleEntityLib.pack(address(ecdsaValidationModule), TEST_DEFAULT_VALIDATION_ENTITY_ID);

        _revertSnapshot = vm.snapshot();
    }

    function _runExecUserOp(address target, bytes memory callData) internal {
        _runUserOp(abi.encodeCall(IModularAccount.execute, (target, 0, callData)));
    }

    function _runExecUserOp(address target, bytes memory callData, bytes memory revertReason) internal {
        _runUserOp(abi.encodeCall(IModularAccount.execute, (target, 0, callData)), revertReason);
    }

    function _runExecBatchUserOp(Call[] memory calls) internal {
        _runUserOp(abi.encodeCall(IModularAccount.executeBatch, (calls)));
    }

    function _runExecBatchUserOp(Call[] memory calls, bytes memory revertReason) internal {
        _runUserOp(abi.encodeCall(IModularAccount.executeBatch, (calls)), revertReason);
    }

    function _runUserOp(bytes memory callData) internal {
        // Run user op without expecting a revert
        _runUserOp(callData, hex"");
    }

    function _runUserOp(bytes memory callData, bytes memory expectedRevertData) internal {
        _runUserOpFrom(address(account1), owner1Key, callData, expectedRevertData);
    }

    function _runUserOpFrom(
        address account,
        uint256 ownerKey,
        bytes memory callData,
        bytes memory expectedRevertData
    ) internal {
        uint256 nonce = entryPoint.getNonce(address(account), 0);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: account,
            nonce: nonce,
            initCode: hex"",
            callData: callData,
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash.toEthSignedMessageHash());

        userOp.signature =
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        if (expectedRevertData.length > 0) {
            vm.expectRevert(expectedRevertData);
        }
        entryPoint.handleOps(userOps, beneficiary);
    }

    function _runtimeExec(address target, bytes memory callData) internal {
        _runtimeCall(abi.encodeCall(IModularAccount.execute, (target, 0, callData)));
    }

    function _runtimeExec(address target, bytes memory callData, bytes memory expectedRevertData) internal {
        _runtimeCall(abi.encodeCall(IModularAccount.execute, (target, 0, callData)), expectedRevertData);
    }

    function _runtimeExecExpFail(address target, bytes memory callData, bytes memory expectedRevertData)
        internal
    {
        _runtimeCallExpFail(abi.encodeCall(IModularAccount.execute, (target, 0, callData)), expectedRevertData);
    }

    function _runtimeExecBatch(Call[] memory calls) internal {
        _runtimeCall(abi.encodeCall(IModularAccount.executeBatch, (calls)));
    }

    function _runtimeExecBatch(Call[] memory calls, bytes memory expectedRevertData) internal {
        _runtimeCall(abi.encodeCall(IModularAccount.executeBatch, (calls)), expectedRevertData);
    }

    function _runtimeExecBatchExpFail(Call[] memory calls, bytes memory expectedRevertData) internal {
        _runtimeCallExpFail(abi.encodeCall(IModularAccount.executeBatch, (calls)), expectedRevertData);
    }

    function _runtimeCall(bytes memory callData) internal {
        _runtimeCall(callData, "");
    }

    function _runtimeCall(bytes memory callData, bytes memory expectedRevertData) internal {
        if (expectedRevertData.length > 0) {
            vm.expectRevert(expectedRevertData);
        }

        vm.prank(owner1);
        account1.executeWithRuntimeValidation(callData, _encodeSignature(_signerValidation, GLOBAL_VALIDATION, ""));
    }

    // Always expects a revert, even if the revert data is zero-length.
    function _runtimeCallExpFail(bytes memory callData, bytes memory expectedRevertData) internal {
        vm.expectRevert(expectedRevertData);

        vm.prank(owner1);
        account1.executeWithRuntimeValidation(callData, _encodeSignature(_signerValidation, GLOBAL_VALIDATION, ""));
    }

    function _transferOwnershipToTest() internal {
        // Transfer ownership to test contract for easier invocation.
        vm.prank(owner1);

        if (_isSMATest) {
            account1.executeWithRuntimeValidation(
                abi.encodeCall(SemiModularAccountBytecode(payable(account1)).updateFallbackSigner, (address(this))),
                _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
            );
            return;
        }

        account1.executeWithRuntimeValidation(
            abi.encodeCall(
                account1.execute,
                (
                    address(ecdsaValidationModule),
                    0,
                    abi.encodeCall(
                        ECDSAValidationModule.transferSigner, (TEST_DEFAULT_VALIDATION_ENTITY_ID, address(this))
                    )
                )
            ),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
        );
    }

    function _allowTestDirectCalls() internal {
        vm.prank(owner1);
        account1.executeWithRuntimeValidation(
            abi.encodeCall(
                account1.installValidation,
                (
                    ValidationConfigLib.pack(address(this), DIRECT_CALL_VALIDATION_ENTITYID, true, false, false),
                    new bytes4[](0),
                    "",
                    new bytes[](0)
                )
            ),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
        );
    }

    function _switchToSMA() internal {
        _isSMATest = true;
        account1 = ModularAccount(payable(factory.createSemiModularAccount(owner1, 0)));
        vm.deal(address(account1), 100 ether);
        _signerValidation = FALLBACK_VALIDATION;
    }

    // Uses state vars:
    // - _signerValidation
    // - ecdsaValidation, when not SMA
    // for 1271 signing the deferred action of install
    function _buildFullDeferredInstallSig(
        uint256 deferredInstallNonce,
        uint48 deferredInstallDeadline,
        bytes memory deferredValidationInstallCall,
        ModularAccount account,
        uint256 signingKey,
        bytes memory uoSig
    ) internal view returns (bytes memory) {
        bytes memory deferredValidationSig = _packFinalSignature(
            _signEcdsaAccountAgnostic(
                _getDeferredInstallHash(
                    account, deferredInstallNonce, deferredInstallDeadline, deferredValidationInstallCall
                ),
                signingKey,
                account,
                ecdsaValidationModule
            )
        );

        return _encodeDeferredInstallUOSignature(
            _signerValidation,
            GLOBAL_VALIDATION,
            _packDeferredInstallData(deferredInstallNonce, deferredInstallDeadline, deferredValidationInstallCall),
            deferredValidationSig,
            uoSig
        );
    }

    function _signEcdsaAccountAgnostic(
        bytes32 hash,
        uint256 signingKey,
        ModularAccount account,
        ECDSAValidationModule validationModule
    ) internal view returns (bytes memory) {
        bytes32 replaySafeHash;
        if (_isSMATest) {
            replaySafeHash = _getSMAReplaySafeHash(account, hash);
        } else {
            replaySafeHash = validationModule.replaySafeHash(address(account), hash);
        }

        return _signRawHash(vm, signingKey, replaySafeHash);
    }

    // helper function to compress 2 gas values into a single bytes32
    function _encodeGas(uint256 g1, uint256 g2) internal pure returns (bytes32) {
        return bytes32(uint256((g1 << 128) + uint128(g2)));
    }
}
