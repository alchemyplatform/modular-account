// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Call} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ModuleEntity, ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {
    ValidationConfig,
    ValidationConfigLib
} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Vm} from "forge-std/Vm.sol";

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {AccountFactory} from "../../src/factory/AccountFactory.sol";
import {SingleSignerValidationModule} from "../../src/modules/validation/SingleSignerValidationModule.sol";

import {ValidationLocatorLib} from "../../src/libraries/ValidationLocatorLib.sol";
import {ModularAccountBenchmarkBase} from "./ModularAccountBenchmarkBase.sol";

contract ModularAccountGasTest is ModularAccountBenchmarkBase("SemiModularAccount") {
    function test_semiModularAccountGas_runtime_accountCreation() public {
        uint256 salt = 0;

        vm.recordLogs();

        uint256 gasUsed = _runtimeBenchmark(
            owner1, address(factory), abi.encodeCall(factory.createSemiModularAccount, (owner1, salt))
        );

        address accountAddress = factory.getAddressSemiModular(owner1, salt);

        assertTrue(accountAddress.code.length > 0);

        // Also assert that the event emitted by the factory is correct
        Vm.Log[] memory logs = vm.getRecordedLogs();

        assertEq(logs.length, 1);

        assertEq(logs[0].topics.length, 3);
        assertEq(logs[0].topics[0], AccountFactory.SemiModularAccountDeployed.selector);
        assertEq(logs[0].topics[1], bytes32(uint256(uint160(accountAddress))));
        assertEq(logs[0].topics[2], bytes32(uint256(uint160(owner1))));
        assertEq(keccak256(logs[0].data), keccak256(abi.encodePacked(salt)));

        _snap(RUNTIME, "AccountCreation", gasUsed);
    }

    function test_semiModularAccountGas_runtime_nativeTransfer() public {
        _deploySemiModularAccountBytecode1();

        vm.deal(address(account1), 1 ether);

        uint256 gas = _runtimeBenchmark(
            owner1,
            address(account1),
            abi.encodeCall(
                ModularAccountBase.executeWithRuntimeValidation,
                (
                    abi.encodeCall(ModularAccountBase.execute, (recipient, 0.1 ether, "")),
                    _encodeSignature(signerValidation, GLOBAL_VALIDATION, "")
                )
            )
        );

        assertEq(address(recipient).balance, 0.1 ether + 1 wei);

        _snap(RUNTIME, "NativeTransfer", gas);
    }

    function test_semiModularAccountGas_userOp_nativeTransfer() public {
        _deploySemiModularAccountBytecode1();

        vm.deal(address(account1), 1 ether);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: _encodeNonce(signerValidation, GLOBAL_V, 0),
            initCode: "",
            callData: abi.encodeCall(ModularAccountBase.execute, (recipient, 0.1 ether, "")),
            // don't over-estimate by a lot here, otherwise a fee is assessed.
            accountGasLimits: _encodeGasLimits(40_000, 90_000),
            preVerificationGas: 0,
            gasFees: _encodeGasFees(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        userOp.signature = _encodeSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        uint256 gasUsed = _userOpBenchmark(userOp);

        assertEq(address(recipient).balance, 0.1 ether + 1 wei);

        _snap(USER_OP, "NativeTransfer", gasUsed);
    }

    function test_semiModularAccountGas_runtime_erc20Transfer() public {
        _deploySemiModularAccountBytecode1();

        mockErc20.mint(address(account1), 100 ether);

        uint256 gasUsed = _runtimeBenchmark(
            owner1,
            address(account1),
            abi.encodeCall(
                ModularAccountBase.executeWithRuntimeValidation,
                (
                    abi.encodeCall(
                        ModularAccountBase.execute,
                        (address(mockErc20), 0, abi.encodeCall(mockErc20.transfer, (recipient, 10 ether)))
                    ),
                    _encodeSignature(signerValidation, GLOBAL_VALIDATION, "")
                )
            )
        );

        assertEq(mockErc20.balanceOf(recipient), 10 ether);

        _snap(RUNTIME, "Erc20Transfer", gasUsed);
    }

    function test_semiModularAccountGas_userOp_erc20Transfer() public {
        _deploySemiModularAccountBytecode1();

        vm.deal(address(account1), 1 ether);

        mockErc20.mint(address(account1), 100 ether);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: _encodeNonce(signerValidation, GLOBAL_V, 0),
            initCode: "",
            callData: abi.encodeCall(
                ModularAccountBase.execute,
                (address(mockErc20), 0, abi.encodeWithSelector(mockErc20.transfer.selector, recipient, 10 ether))
            ),
            // don't over-estimate by a lot here, otherwise a fee is assessed.
            accountGasLimits: _encodeGasLimits(40_000, 90_000),
            preVerificationGas: 0,
            gasFees: _encodeGasFees(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        userOp.signature = _encodeSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        uint256 gasUsed = _userOpBenchmark(userOp);

        assertEq(mockErc20.balanceOf(recipient), 10 ether);

        _snap(USER_OP, "Erc20Transfer", gasUsed);
    }

    // Batch transfers: both native token transfer and ERC-20 transfer

    function test_semiModularAccountGas_runtime_batchTransers() public {
        _deploySemiModularAccountBytecode1();

        vm.deal(address(account1), 1 ether);
        mockErc20.mint(address(account1), 100 ether);

        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: recipient, value: 0.1 ether, data: ""});
        calls[1] = Call({
            target: address(mockErc20),
            value: 0,
            data: abi.encodeCall(mockErc20.transfer, (recipient, 10 ether))
        });

        uint256 gasUsed = _runtimeBenchmark(
            owner1,
            address(account1),
            abi.encodeCall(
                ModularAccountBase.executeWithRuntimeValidation,
                (
                    abi.encodeCall(ModularAccountBase.executeBatch, (calls)),
                    _encodeSignature(signerValidation, GLOBAL_VALIDATION, "")
                )
            )
        );

        assertEq(address(recipient).balance, 0.1 ether + 1 wei);
        assertEq(mockErc20.balanceOf(recipient), 10 ether);

        _snap(RUNTIME, "BatchTransfers", gasUsed);
    }

    function test_semiModularAccountGas_userOp_batchTransfers() public {
        _deploySemiModularAccountBytecode1();

        vm.deal(address(account1), 1 ether);
        mockErc20.mint(address(account1), 100 ether);

        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: recipient, value: 0.1 ether, data: ""});
        calls[1] = Call({
            target: address(mockErc20),
            value: 0,
            data: abi.encodeCall(mockErc20.transfer, (recipient, 10 ether))
        });

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: _encodeNonce(signerValidation, GLOBAL_V, 0),
            initCode: "",
            callData: abi.encodeCall(ModularAccountBase.executeBatch, (calls)),
            // don't over-estimate by a lot here, otherwise a fee is assessed.
            accountGasLimits: _encodeGasLimits(60_000, 100_000),
            preVerificationGas: 0,
            gasFees: _encodeGasFees(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        userOp.signature = _encodeSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        uint256 gasUsed = _userOpBenchmark(userOp);

        assertEq(address(recipient).balance, 0.1 ether + 1 wei);
        assertEq(mockErc20.balanceOf(recipient), 10 ether);

        _snap(USER_OP, "BatchTransfers", gasUsed);
    }

    function test_semiModularAccountGas_userOp_deferredValidationInstall() public {
        _deploySemiModularAccountBytecode1();

        vm.deal(address(account1), 1 ether);

        SingleSignerValidationModule newValidationModule = _deploySingleSignerValidationModule();
        uint32 newEntityId = 1;
        (address owner2, uint256 owner2Key) = makeAddrAndKey("owner2");

        ModuleEntity newUOValidationEntity = ModuleEntityLib.pack(address(newValidationModule), newEntityId);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: _encodeNonceDefAction(newUOValidationEntity, GLOBAL_V, 0),
            initCode: "",
            callData: abi.encodeCall(ModularAccountBase.execute, (recipient, 0.1 ether, "")),
            // don't over-estimate by a lot here, otherwise a fee is assessed.
            accountGasLimits: _encodeGasLimits(40_000, 200_000),
            preVerificationGas: 0,
            gasFees: _encodeGasFees(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        bytes memory uoValidationSig = _packFinalSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        ValidationConfig newUOValidation =
            ValidationConfigLib.pack(address(newValidationModule), newEntityId, true, false, true);

        bytes[] memory hooks = new bytes[](1);

        // Time range hook
        hooks[0] = abi.encodePacked(
            HookConfigLib.packValidationHook({_module: address(timeRangeModule), _entityId: 1}),
            abi.encode(uint32(1), 1000, 100)
        );


        bytes memory deferredValidationInstallCall = abi.encodeCall(
            ModularAccountBase.installValidation,
            (newUOValidation, new bytes4[](0), abi.encode(newEntityId, owner2), hooks)
        );

        uint48 deferredInstallDeadline = 0;

        bytes32 digest = _getDeferredInstallStruct(
            account1, userOp.nonce, deferredInstallDeadline, deferredValidationInstallCall
        );

        bytes memory deferredValidationSig = _signRawHash(vm, owner1Key, digest);

        userOp.signature = _encodeDeferredInstallUOSignature(
            _packDeferredInstallData(
                deferredInstallDeadline,
                ValidationLocatorLib.packFromModuleEntity(signerValidation, true, false),
                deferredValidationInstallCall
            ),
            deferredValidationSig,
            uoValidationSig
        );

        uint256 gasUsed = _userOpBenchmark(userOp);

        assertEq(address(recipient).balance, 0.1 ether + 1 wei);

        _snap(USER_OP, "deferredValidation", gasUsed);
    }

    function test_semiModularAccountGas_runtime_installSessionKeyCases() public {
        _deploySemiModularAccountBytecode1();

        for (uint256 i = 0; i < _sessionKeyTestCases.length; i++) {
            uint256 vmStateSnapshot = vm.snapshotState();

            SessionKeyTestCase memory testCase = _sessionKeyTestCases[i];

            uint256 gasUsed = _runtimeBenchmark(
                owner1,
                address(account1),
                abi.encodeCall(
                    ModularAccountBase.executeWithRuntimeValidation,
                    (testCase.getInstallData(), _encodeSignature(signerValidation, GLOBAL_VALIDATION, ""))
                )
            );

            testCase.verifyInstallState();

            _snap(RUNTIME, string.concat("InstallSessionKey_Case", vm.toString(i + 1)), gasUsed);

            vm.revertToStateAndDelete(vmStateSnapshot);
        }
    }

    function test_semiModularAccountGas_userOp_installSessionKeyCases() public {
        _deploySemiModularAccountBytecode1();

        for (uint256 i = 0; i < _sessionKeyTestCases.length; i++) {
            uint256 vmStateSnapshot = vm.snapshotState();

            vm.deal(address(account1), 1 ether);

            SessionKeyTestCase memory testCase = _sessionKeyTestCases[i];

            PackedUserOperation memory userOp = PackedUserOperation({
                sender: address(account1),
                nonce: _encodeNonce(signerValidation, GLOBAL_V, 0),
                initCode: "",
                callData: testCase.getInstallData(),
                // don't over-estimate by a lot here, otherwise a fee is assessed.
                accountGasLimits: _encodeGasLimits(500_000, 100_000),
                preVerificationGas: 0,
                gasFees: _encodeGasFees(1, 1),
                paymasterAndData: "",
                signature: ""
            });

            bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
            (uint8 v, bytes32 r, bytes32 s) =
                vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
            userOp.signature = _encodeSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

            uint256 gasUsed = _userOpBenchmark(userOp);

            testCase.verifyInstallState();

            _snap(USER_OP, string.concat("InstallSessionKey_Case", vm.toString(i + 1)), gasUsed);

            vm.revertToStateAndDelete(vmStateSnapshot);
        }
    }

    function test_semiModularAccountGas_runtime_useSessionKeyCases_counter() public {
        _deploySemiModularAccountBytecode1();

        for (uint256 i = 0; i < _sessionKeyTestCases.length; i++) {
            uint256 vmStateSnapshot = vm.snapshotState();

            SessionKeyTestCase memory testCase = _sessionKeyTestCases[i];
            ModuleEntity sessionKeyValidation = testCase.installSessionKey();

            // Jump to within the valid timestamp range
            vm.warp(200);

            uint256 gasUsed = _runtimeBenchmark(
                testCase.sessionSigner,
                address(account1),
                abi.encodeCall(
                    ModularAccountBase.executeWithRuntimeValidation,
                    (
                        abi.encodeCall(
                            ModularAccountBase.execute,
                            (address(counter), 0 wei, abi.encodeCall(counter.increment, ()))
                        ),
                        _encodeSignature(
                            sessionKeyValidation,
                            testCase.isGlobal ? GLOBAL_VALIDATION : SELECTOR_ASSOCIATED_VALIDATION,
                            ""
                        )
                    )
                )
            );

            assertEq(counter.number(), 2);

            _snap(RUNTIME, string.concat("UseSessionKey_Case", vm.toString(i + 1), "_Counter"), gasUsed);

            vm.revertToStateAndDelete(vmStateSnapshot);
        }
    }

    function test_semiModularAccountGas_userOp_useSessionKeyCases_counter() public {
        _deploySemiModularAccountBytecode1();

        for (uint256 i = 0; i < _sessionKeyTestCases.length; i++) {
            uint256 vmStateSnapshot = vm.snapshotState();

            vm.deal(address(account1), 1 ether);

            SessionKeyTestCase memory testCase = _sessionKeyTestCases[i];
            ModuleEntity sessionKeyValidation = testCase.installSessionKey();

            // Jump to within the valid timestamp range
            vm.warp(200);

            PackedUserOperation memory userOp = PackedUserOperation({
                sender: address(account1),
                nonce: _encodeNonce(sessionKeyValidation, testCase.isGlobal ? GLOBAL_V : SELECTOR_ASSOCIATED_V, 0),
                initCode: "",
                callData: abi.encodePacked(
                    ModularAccountBase.executeUserOp.selector,
                    abi.encodeCall(
                        ModularAccountBase.execute, (address(counter), 0 wei, abi.encodeCall(counter.increment, ()))
                    )
                ),
                // don't over-estimate by a lot here, otherwise a fee is assessed.
                accountGasLimits: _encodeGasLimits(200_000, 200_000),
                preVerificationGas: 0,
                gasFees: _encodeGasFees(1, 1),
                paymasterAndData: "",
                signature: ""
            });

            bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
            (uint8 v, bytes32 r, bytes32 s) =
                vm.sign(testCase.sessionSignerKey, MessageHashUtils.toEthSignedMessageHash(userOpHash));
            userOp.signature = _encodeSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

            uint256 gasUsed = _userOpBenchmark(userOp);

            assertEq(counter.number(), 2);

            _snap(USER_OP, string.concat("UseSessionKey_Case", vm.toString(i + 1), "_Counter"), gasUsed);

            vm.revertToStateAndDelete(vmStateSnapshot);
        }
    }

    function test_semiModularAccountGas_runtime_useSessionKeyCases_token() public {
        _deploySemiModularAccountBytecode1();

        for (uint256 i = 0; i < _sessionKeyTestCases.length; i++) {
            uint256 vmStateSnapshot = vm.snapshotState();

            SessionKeyTestCase memory testCase = _sessionKeyTestCases[i];
            ModuleEntity sessionKeyValidation = testCase.installSessionKey();

            mockErc20.mint(address(account1), 100 ether);

            // Jump to within the valid timestamp range
            vm.warp(200);

            uint256 gasUsed = _runtimeBenchmark(
                testCase.sessionSigner,
                address(account1),
                abi.encodeCall(
                    ModularAccountBase.executeWithRuntimeValidation,
                    (
                        abi.encodeCall(
                            ModularAccountBase.execute,
                            (address(mockErc20), 0, abi.encodeCall(mockErc20.transfer, (recipient, 10 ether)))
                        ),
                        _encodeSignature(
                            sessionKeyValidation,
                            testCase.isGlobal ? GLOBAL_VALIDATION : SELECTOR_ASSOCIATED_VALIDATION,
                            ""
                        )
                    )
                )
            );

            assertEq(mockErc20.balanceOf(recipient), 10 ether);

            _snap(RUNTIME, string.concat("UseSessionKey_Case", vm.toString(i + 1), "_Token"), gasUsed);

            vm.revertToStateAndDelete(vmStateSnapshot);
        }
    }

    function test_semiModularAccountGas_userOp_useSessionKeyCases_token() public {
        _deploySemiModularAccountBytecode1();

        for (uint256 i = 0; i < _sessionKeyTestCases.length; i++) {
            uint256 vmStateSnapshot = vm.snapshotState();

            vm.deal(address(account1), 1 ether);

            SessionKeyTestCase memory testCase = _sessionKeyTestCases[i];
            ModuleEntity sessionKeyValidation = testCase.installSessionKey();

            mockErc20.mint(address(account1), 100 ether);

            // Jump to within the valid timestamp range
            vm.warp(200);

            PackedUserOperation memory userOp = PackedUserOperation({
                sender: address(account1),
                nonce: _encodeNonce(sessionKeyValidation, testCase.isGlobal ? GLOBAL_V : SELECTOR_ASSOCIATED_V, 0),
                initCode: "",
                callData: abi.encodePacked(
                    ModularAccountBase.executeUserOp.selector,
                    abi.encodeCall(
                        ModularAccountBase.execute,
                        (address(mockErc20), 0, abi.encodeCall(mockErc20.transfer, (recipient, 10 ether)))
                    )
                ),
                // don't over-estimate by a lot here, otherwise a fee is assessed.
                accountGasLimits: _encodeGasLimits(200_000, 200_000),
                preVerificationGas: 0,
                gasFees: _encodeGasFees(1, 1),
                paymasterAndData: "",
                signature: ""
            });

            bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
            (uint8 v, bytes32 r, bytes32 s) =
                vm.sign(testCase.sessionSignerKey, MessageHashUtils.toEthSignedMessageHash(userOpHash));
            userOp.signature = _encodeSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

            uint256 gasUsed = _userOpBenchmark(userOp);

            assertEq(mockErc20.balanceOf(recipient), 10 ether);

            _snap(USER_OP, string.concat("UseSessionKey_Case", vm.toString(i + 1), "_Token"), gasUsed);

            vm.revertToStateAndDelete(vmStateSnapshot);
        }
    }
}
