// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {Call, IModularAccount} from "@erc-6900/reference-implementation/interfaces/IModularAccount.sol";

import {AccountFactory} from "../../src/account/AccountFactory.sol";
import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {SemiModularAccount} from "../../src/account/SemiModularAccount.sol";
import {ModuleEntity, ModuleEntityLib} from "../../src/helpers/ModuleEntityLib.sol";
import {SingleSignerValidationModule} from "../../src/modules/validation/SingleSignerValidationModule.sol";
import {OptimizedTest} from "./OptimizedTest.sol";
import {TEST_DEFAULT_VALIDATION_ENTITY_ID as EXT_CONST_TEST_DEFAULT_VALIDATION_ENTITY_ID} from
    "./TestConstants.sol";

/// @dev This contract handles common boilerplate setup for tests using ModularAccount with
/// SingleSignerValidationModule.
abstract contract AccountTestBase is OptimizedTest {
    using ModuleEntityLib for ModuleEntity;
    using MessageHashUtils for bytes32;

    EntryPoint public entryPoint;
    address payable public beneficiary;

    SingleSignerValidationModule public singleSignerValidationModule;
    ModularAccount public accountImplementation;
    SemiModularAccount public semiModularAccountImplementation;
    AccountFactory public factory;

    address public factoryOwner;

    address public owner1;
    uint256 public owner1Key;
    ModularAccount public account1;

    ModuleEntity internal _signerValidation;

    uint8 public constant SELECTOR_ASSOCIATED_VALIDATION = 0;
    uint8 public constant GLOBAL_VALIDATION = 1;

    // Re-declare the constant to prevent derived test contracts from having to import it
    uint32 public constant TEST_DEFAULT_VALIDATION_ENTITY_ID = EXT_CONST_TEST_DEFAULT_VALIDATION_ENTITY_ID;

    uint256 public constant CALL_GAS_LIMIT = 100_000;
    uint256 public constant VERIFICATION_GAS_LIMIT = 1_200_000;

    struct PreValidationHookData {
        uint8 index;
        bytes validationData;
    }

    constructor() {
        entryPoint = _deployEntryPoint070();
        (owner1, owner1Key) = makeAddrAndKey("owner1");
        factoryOwner = makeAddr("factoryOwner");
        beneficiary = payable(makeAddr("beneficiary"));

        address deployedSingleSignerValidation = address(_deploySingleSignerValidationModule());

        // We etch the single signer validation to the max address, such that it coincides with the fallback
        // validation module entity for semi modular account tests.
        singleSignerValidationModule = SingleSignerValidationModule(address(type(uint160).max));
        vm.etch(address(singleSignerValidationModule), deployedSingleSignerValidation.code);

        accountImplementation = _deployModularAccount(entryPoint);

        semiModularAccountImplementation = SemiModularAccount(payable(_deploySemiModularAccount(entryPoint)));

        factory = new AccountFactory(
            entryPoint,
            accountImplementation,
            semiModularAccountImplementation,
            address(singleSignerValidationModule),
            factoryOwner
        );

        account1 = factory.createAccount(owner1, 0, TEST_DEFAULT_VALIDATION_ENTITY_ID);
        vm.deal(address(account1), 100 ether);

        _signerValidation =
            ModuleEntityLib.pack(address(singleSignerValidationModule), TEST_DEFAULT_VALIDATION_ENTITY_ID);
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
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());

        userOp.signature = _encodeSignature(_signerValidation, GLOBAL_VALIDATION, abi.encodePacked(r, s, v));

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
        account1.executeWithAuthorization(callData, _encodeSignature(_signerValidation, GLOBAL_VALIDATION, ""));
    }

    // Always expects a revert, even if the revert data is zero-length.
    function _runtimeCallExpFail(bytes memory callData, bytes memory expectedRevertData) internal {
        vm.expectRevert(expectedRevertData);

        vm.prank(owner1);
        account1.executeWithAuthorization(callData, _encodeSignature(_signerValidation, GLOBAL_VALIDATION, ""));
    }

    function _transferOwnershipToTest() internal {
        // Transfer ownership to test contract for easier invocation.
        vm.prank(owner1);
        if (vm.envOr("SMA_TEST", false)) {
            account1.executeWithAuthorization(
                abi.encodeCall(SemiModularAccount(payable(account1)).updateFallbackSigner, (address(this))),
                _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
            );
            return;
        }
        account1.executeWithAuthorization(
            abi.encodeCall(
                account1.execute,
                (
                    address(singleSignerValidationModule),
                    0,
                    abi.encodeCall(
                        SingleSignerValidationModule.transferSigner,
                        (TEST_DEFAULT_VALIDATION_ENTITY_ID, address(this))
                    )
                )
            ),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
        );
    }

    // helper function to compress 2 gas values into a single bytes32
    function _encodeGas(uint256 g1, uint256 g2) internal pure returns (bytes32) {
        return bytes32(uint256((g1 << 128) + uint128(g2)));
    }

    // helper function to encode a 1271 signature, according to the per-hook and per-validation data format.
    function _encode1271Signature(
        ModuleEntity validationFunction,
        PreValidationHookData[] memory preValidationHookData,
        bytes memory validationData
    ) internal pure returns (bytes memory) {
        bytes memory sig = abi.encodePacked(validationFunction);

        sig = abi.encodePacked(sig, _packPreHookDatas(preValidationHookData));

        sig = abi.encodePacked(sig, _packValidationResWithIndex(255, validationData));

        return sig;
    }

    // helper function to encode a signature, according to the per-hook and per-validation data format.
    function _encodeSignature(
        ModuleEntity validationFunction,
        uint8 globalOrNot,
        PreValidationHookData[] memory preValidationHookData,
        bytes memory validationData
    ) internal pure returns (bytes memory) {
        bytes memory sig = abi.encodePacked(validationFunction, globalOrNot);

        sig = abi.encodePacked(sig, _packPreHookDatas(preValidationHookData));

        sig = abi.encodePacked(sig, _packValidationResWithIndex(255, validationData));

        return sig;
    }

    // overload for the case where there are no pre validation hooks
    function _encodeSignature(ModuleEntity validationFunction, uint8 globalOrNot, bytes memory validationData)
        internal
        pure
        returns (bytes memory)
    {
        PreValidationHookData[] memory emptyPreValidationHookData = new PreValidationHookData[](0);
        return _encodeSignature(validationFunction, globalOrNot, emptyPreValidationHookData, validationData);
    }

    // overload for the case where there are no pre validation hooks
    function _encode1271Signature(ModuleEntity validationFunction, bytes memory validationData)
        internal
        pure
        returns (bytes memory)
    {
        PreValidationHookData[] memory emptyPreValidationHookData = new PreValidationHookData[](0);
        return _encode1271Signature(validationFunction, emptyPreValidationHookData, validationData);
    }

    // helper function to pack pre validation hook datas, according to the sparse calldata segment spec.
    function _packPreHookDatas(PreValidationHookData[] memory preValidationHookData)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory res = "";

        for (uint256 i = 0; i < preValidationHookData.length; ++i) {
            res = abi.encodePacked(
                res,
                _packValidationResWithIndex(
                    preValidationHookData[i].index, preValidationHookData[i].validationData
                )
            );
        }

        return res;
    }

    // helper function to pack validation data with an index, according to the sparse calldata segment spec.
    function _packValidationResWithIndex(uint8 index, bytes memory validationData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(uint32(validationData.length + 1), index, validationData);
    }
}
