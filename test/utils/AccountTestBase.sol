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
import {
    Call, IModularAccount, ModuleEntity
} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {
    ValidationConfig,
    ValidationConfigLib
} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {SemiModularAccountBytecode} from "../../src/account/SemiModularAccountBytecode.sol";
import {AccountFactory} from "../../src/factory/AccountFactory.sol";
import {FALLBACK_VALIDATION} from "../../src/helpers/Constants.sol";
import {SingleSignerValidationModule} from "../../src/modules/validation/SingleSignerValidationModule.sol";

import {ModuleSignatureUtils} from "./ModuleSignatureUtils.sol";
import {OptimizedTest} from "./OptimizedTest.sol";
import {TEST_DEFAULT_VALIDATION_ENTITY_ID as EXT_CONST_TEST_DEFAULT_VALIDATION_ENTITY_ID} from
    "./TestConstants.sol";

/// @dev This contract handles common boilerplate setup for tests using ModularAccount with
/// SingleSignerValidationModule.
abstract contract AccountTestBase is OptimizedTest, ModuleSignatureUtils {
    using ModuleEntityLib for ModuleEntity;
    using MessageHashUtils for bytes32;

    EntryPoint public entryPoint;
    address payable public beneficiary;

    SingleSignerValidationModule public singleSignerValidationModule;
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

        vm.revertToState(_revertSnapshot);

        _switchToSMA();

        setUp();

        _;
    }

    constructor() {
        entryPoint = _deployEntryPoint070();
        (owner1, owner1Key) = makeAddrAndKey("owner1");
        factoryOwner = makeAddr("factoryOwner");
        beneficiary = payable(makeAddr("beneficiary"));

        // address deployedSingleSignerValidationModule = address(_deploySingleSignerValidationModule());

        // We etch the single signer validation to the max address, such that it coincides with the fallback
        // validation module entity for semi modular account tests.
        singleSignerValidationModule = _deploySingleSignerValidationModule();
        // vm.etch(address(0), deployedSingleSignerValidationModule.code);

        accountImplementation = _deployModularAccount(entryPoint);

        semiModularAccountImplementation =
            SemiModularAccountBytecode(payable(_deploySemiModularAccountBytecode(entryPoint)));

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

        _revertSnapshot = vm.snapshotState();
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
                abi.encodeCall(
                    SemiModularAccountBytecode(payable(account1)).updateFallbackSignerData, (address(this), false)
                ),
                _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
            );
            return;
        }

        account1.executeWithRuntimeValidation(
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
        ValidationConfig uoValidationFunction,
        ModularAccount account,
        uint256 signingKey,
        bytes memory uoSig
    ) internal view returns (bytes memory) {
        bytes memory deferredValidationSig;
        bytes memory deferredValidationDatas;
        {
            bytes32 digest = _getDeferredInstallStruct(
                account,
                deferredInstallNonce,
                deferredInstallDeadline,
                uoValidationFunction,
                deferredValidationInstallCall
            );

            bytes32 replaySafeHash;
            if (_isSMATest) {
                replaySafeHash = _getSMAReplaySafeHash(address(account), digest);
            } else {
                replaySafeHash =
                    _getModuleReplaySafeHash(address(account), address(singleSignerValidationModule), digest);
            }

            deferredValidationSig = _packFinalSignature(_signRawHash(vm, signingKey, replaySafeHash));

            deferredValidationDatas = _packDeferredInstallData(
                deferredInstallNonce, deferredInstallDeadline, uoValidationFunction, deferredValidationInstallCall
            );
        }

        return _encodeDeferredInstallUOSignature(
            _signerValidation, GLOBAL_VALIDATION, deferredValidationDatas, deferredValidationSig, uoSig
        );
    }

    // helper function to compress 2 gas values into a single bytes32
    function _encodeGas(uint256 g1, uint256 g2) internal pure returns (bytes32) {
        return bytes32(uint256((g1 << 128) + uint128(g2)));
    }
}
