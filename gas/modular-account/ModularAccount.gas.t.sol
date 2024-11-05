// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {Call} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {
    ValidationConfig,
    ValidationConfigLib
} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Vm} from "forge-std/Vm.sol";

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {AccountFactory} from "../../src/factory/AccountFactory.sol";
import {SingleSignerValidationModule} from "../../src/modules/validation/SingleSignerValidationModule.sol";

import {ModularAccountBenchmarkBase} from "./ModularAccountBenchmarkBase.sol";

contract ModularAccountGasTest is ModularAccountBenchmarkBase("ModularAccount") {
    function test_modularAccountGas_runtime_accountCreation() public {
        uint256 salt = 0;
        uint32 entityId = 0;

        vm.recordLogs();

        uint256 gasUsed = _runtimeBenchmark(
            owner1, address(factory), abi.encodeCall(factory.createAccount, (owner1, salt, entityId))
        );

        address accountAddress = factory.getAddress(owner1, salt, entityId);

        assertTrue(accountAddress.code.length > 0);

        // Also assert that the event emitted by the factory is correct
        Vm.Log[] memory logs = vm.getRecordedLogs();

        assertEq(logs.length, 4);
        // Logs:
        // 0: SingleSignerValidationModule `SignerTransferred` (anonymous)
        // 1: ModularAccount `ValidationInstalled`
        // 2: ModularAccount `Initialized`
        // 3: AccountFactory `ModularAccountDeployed`

        assertEq(logs[3].topics.length, 3);
        assertEq(logs[3].topics[0], AccountFactory.ModularAccountDeployed.selector);
        assertEq(logs[3].topics[1], bytes32(uint256(uint160(accountAddress))));
        assertEq(logs[3].topics[2], bytes32(uint256(uint160(owner1))));
        assertEq(keccak256(logs[3].data), keccak256(abi.encodePacked(salt)));

        _snap(RUNTIME, "AccountCreation", gasUsed);
    }

    function test_modularAccountGas_runtime_nativeTransfer() public {
        _deployAccount1();

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

    function test_modularAccountGas_userOp_nativeTransfer() public {
        _deployAccount1();

        vm.deal(address(account1), 1 ether);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
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
        userOp.signature =
            _encodeSignature(signerValidation, GLOBAL_VALIDATION, abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        uint256 gasUsed = _userOpBenchmark(userOp);

        assertEq(address(recipient).balance, 0.1 ether + 1 wei);

        _snap(USER_OP, "NativeTransfer", gasUsed);
    }

    function test_modularAccountGas_runtime_erc20Transfer() public {
        _deployAccount1();

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

    function test_modularAccountGas_userOp_erc20Transfer() public {
        _deployAccount1();

        vm.deal(address(account1), 1 ether);

        mockErc20.mint(address(account1), 100 ether);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(
                ModularAccountBase.execute,
                (address(mockErc20), 0, abi.encodeWithSelector(mockErc20.transfer.selector, recipient, 10 ether))
            ),
            // don't over-estimate by a lot here, otherwise a fee is assessed.
            accountGasLimits: _encodeGasLimits(40_000, 100_000),
            preVerificationGas: 0,
            gasFees: _encodeGasFees(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        userOp.signature =
            _encodeSignature(signerValidation, GLOBAL_VALIDATION, abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        uint256 gasUsed = _userOpBenchmark(userOp);

        assertEq(mockErc20.balanceOf(recipient), 10 ether);

        _snap(USER_OP, "Erc20Transfer", gasUsed);
    }

    // Batch transfers: both native token transfer and ERC-20 transfer

    function test_modularAccountGas_runtime_batchTransers() public {
        _deployAccount1();

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

    function test_modularAccountGas_userOp_batchTransfers() public {
        _deployAccount1();

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
            nonce: 0,
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
        userOp.signature =
            _encodeSignature(signerValidation, GLOBAL_VALIDATION, abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        uint256 gasUsed = _userOpBenchmark(userOp);

        assertEq(address(recipient).balance, 0.1 ether + 1 wei);
        assertEq(mockErc20.balanceOf(recipient), 10 ether);

        _snap(USER_OP, "BatchTransfers", gasUsed);
    }

    function test_modularAccountGas_userOp_deferredValidationInstall() public {
        _deployAccount1();

        vm.deal(address(account1), 1 ether);

        SingleSignerValidationModule newValidationModule = _deploySingleSignerValidationModule();
        uint32 newEntityId = 0;
        (address owner2, uint256 owner2Key) = makeAddrAndKey("owner2");

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
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

        bytes memory deferredValidationInstallCall = abi.encodeCall(
            ModularAccountBase.installValidation,
            (newUOValidation, new bytes4[](0), abi.encode(newEntityId, owner2), new bytes[](0))
        );

        uint256 deferredInstallNonce = 0;
        uint48 deferredInstallDeadline = 0;

        bytes32 digest = _getDeferredInstallStruct(
            account1, deferredInstallNonce, deferredInstallDeadline, newUOValidation, deferredValidationInstallCall
        );

        bytes memory deferredValidationSig = _packFinalSignature(
            _signRawHash(
                vm,
                owner1Key,
                _getModuleReplaySafeHash(address(account1), address(singleSignerValidationModule), digest)
            )
        );

        userOp.signature = _encodeDeferredInstallUOSignature(
            ValidationConfigLib.moduleEntity(newUOValidation),
            GLOBAL_VALIDATION,
            _packDeferredInstallData(
                deferredInstallNonce,
                deferredInstallDeadline,
                ValidationConfigLib.pack(signerValidation, true, false, false),
                deferredValidationInstallCall
            ),
            deferredValidationSig,
            uoValidationSig
        );

        uint256 gasUsed = _userOpBenchmark(userOp);

        assertEq(address(recipient).balance, 0.1 ether + 1 wei);

        _snap(USER_OP, "deferredValidation", gasUsed);
    }

    function test_modularAccountGas_runtime_installSessionKey_case1() public {
        _deployAccount1();

        uint256 gasUsed = _runtimeBenchmark(
            owner1,
            address(account1),
            abi.encodeCall(
                ModularAccountBase.executeWithRuntimeValidation,
                (_getInstallDataSessionKeyCase1(), _encodeSignature(signerValidation, GLOBAL_VALIDATION, ""))
            )
        );

        _verifySessionKeyCase1InstallState();

        _snap(RUNTIME, "InstallSessionKey_Case1", gasUsed);
    }

    function test_modularAccountGas_userOp_installSessionKey_case1() public {
        _deployAccount1();

        vm.deal(address(account1), 1 ether);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: _getInstallDataSessionKeyCase1(),
            // don't over-estimate by a lot here, otherwise a fee is assessed.
            accountGasLimits: _encodeGasLimits(500_000, 100_000),
            preVerificationGas: 0,
            gasFees: _encodeGasFees(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        userOp.signature =
            _encodeSignature(signerValidation, GLOBAL_VALIDATION, abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        uint256 gasUsed = _userOpBenchmark(userOp);

        _verifySessionKeyCase1InstallState();

        _snap(USER_OP, "InstallSessionKey_Case1", gasUsed);
    }

    function test_modularAccountGas_runtime_useSessionKey_case1_counter() public {
        _deployAccount1();

        ModuleEntity sessionKeyValidation = _installSessionKey_case1();

        // Jump to within the valid timestamp range
        vm.warp(200);

        uint256 gasUsed = _runtimeBenchmark(
            sessionSigner1,
            address(account1),
            abi.encodeCall(
                ModularAccountBase.executeWithRuntimeValidation,
                (
                    abi.encodeCall(
                        ModularAccountBase.execute,
                        (address(counter), 0 wei, abi.encodeCall(counter.increment, ()))
                    ),
                    _encodeSignature(sessionKeyValidation, SELECTOR_ASSOCIATED_VALIDATION, "")
                )
            )
        );

        assertEq(counter.number(), 2);

        _snap(RUNTIME, "UseSessionKey_Case1_Counter", gasUsed);
    }

    function test_modularAccountGas_userOp_useSessionKey_case1_counter() public {
        _deployAccount1();

        vm.deal(address(account1), 1 ether);

        ModuleEntity sessionKeyValidation = _installSessionKey_case1();

        // Jump to within the valid timestamp range
        vm.warp(200);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
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
            vm.sign(sessionSigner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        userOp.signature = _encodeSignature(
            sessionKeyValidation, SELECTOR_ASSOCIATED_VALIDATION, abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v)
        );

        uint256 gasUsed = _userOpBenchmark(userOp);

        assertEq(counter.number(), 2);

        _snap(USER_OP, "UseSessionKey_Case1_Counter", gasUsed);
    }

    function test_modularAccountGas_runtime_useSessionKey_case1_token() public {
        _deployAccount1();

        ModuleEntity sessionKeyValidation = _installSessionKey_case1();

        mockErc20.mint(address(account1), 100 ether);

        // Jump to within the valid timestamp range
        vm.warp(200);

        uint256 gasUsed = _runtimeBenchmark(
            sessionSigner1,
            address(account1),
            abi.encodeCall(
                ModularAccountBase.executeWithRuntimeValidation,
                (
                    abi.encodeCall(
                        ModularAccountBase.execute,
                        (address(mockErc20), 0, abi.encodeCall(mockErc20.transfer, (recipient, 10 ether)))
                    ),
                    _encodeSignature(sessionKeyValidation, SELECTOR_ASSOCIATED_VALIDATION, "")
                )
            )
        );

        assertEq(mockErc20.balanceOf(recipient), 10 ether);

        _snap(RUNTIME, "UseSessionKey_Case1_Token", gasUsed);
    }

    function test_modularAccountGas_userOp_useSessionKey_case1_token() public {
        _deployAccount1();

        vm.deal(address(account1), 1 ether);

        ModuleEntity sessionKeyValidation = _installSessionKey_case1();

        mockErc20.mint(address(account1), 100 ether);

        // Jump to within the valid timestamp range
        vm.warp(200);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
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
            vm.sign(sessionSigner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        userOp.signature = _encodeSignature(
            sessionKeyValidation, SELECTOR_ASSOCIATED_VALIDATION, abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v)
        );

        uint256 gasUsed = _userOpBenchmark(userOp);

        assertEq(mockErc20.balanceOf(recipient), 10 ether);

        _snap(USER_OP, "UseSessionKey_Case1_Token", gasUsed);
    }
}
