// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Vm} from "forge-std/src/Vm.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {AccountFactory} from "../../src/factory/AccountFactory.sol";

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
        _deploySemiModularAccount1();

        vm.deal(address(account1), 1 ether);

        uint256 gas = _runtimeBenchmark(
            owner1,
            address(account1),
            abi.encodeCall(
                ModularAccount.executeWithAuthorization,
                (
                    abi.encodeCall(ModularAccount.execute, (recipient, 0.1 ether, "")),
                    _encodeSignature(signerValidation, GLOBAL_VALIDATION, "")
                )
            )
        );

        assertEq(address(recipient).balance, 0.1 ether + 1 wei);

        _snap(RUNTIME, "NativeTransfer", gas);
    }

    function test_semiModularAccountGas_userOp_nativeTransfer() public {
        _deploySemiModularAccount1();

        vm.deal(address(account1), 1 ether);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(ModularAccount.execute, (recipient, 0.1 ether, "")),
            // don't over-estimate by a lot here, otherwise a fee is assessed.
            accountGasLimits: _encodeGasLimits(40_000, 90_000),
            preVerificationGas: 0,
            gasFees: _encodeGasFees(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        userOp.signature = _encodeSignature(signerValidation, GLOBAL_VALIDATION, abi.encodePacked(r, s, v));

        uint256 gasUsed = _userOpBenchmark(userOp);

        assertEq(address(recipient).balance, 0.1 ether + 1 wei);

        _snap(USER_OP, "NativeTransfer", gasUsed);
    }

    function test_semiModularAccountGas_runtime_erc20Transfer() public {
        _deploySemiModularAccount1();

        mockErc20.mint(address(account1), 100 ether);

        uint256 gasUsed = _runtimeBenchmark(
            owner1,
            address(account1),
            abi.encodeCall(
                ModularAccount.executeWithAuthorization,
                (
                    abi.encodeCall(
                        ModularAccount.execute,
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
        _deploySemiModularAccount1();

        vm.deal(address(account1), 1 ether);

        mockErc20.mint(address(account1), 100 ether);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(
                ModularAccount.execute,
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
        userOp.signature = _encodeSignature(signerValidation, GLOBAL_VALIDATION, abi.encodePacked(r, s, v));

        uint256 gasUsed = _userOpBenchmark(userOp);

        assertEq(mockErc20.balanceOf(recipient), 10 ether);

        _snap(USER_OP, "Erc20Transfer", gasUsed);
    }

    function test_semiModularAccountGas_userOp_deferredValidationInstall() public {
        _deploySemiModularAccount1();

        vm.deal(address(account1), 1 ether);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(ModularAccount.execute, (recipient, 0.1 ether, "")),
            // don't over-estimate by a lot here, otherwise a fee is assessed.
            accountGasLimits: _encodeGasLimits(40_000, 160_000),
            preVerificationGas: 0,
            gasFees: _encodeGasFees(1, 1),
            paymasterAndData: "",
            signature: _buildFullDeferredInstallSig(
                vm, owner1Key, true, account1, signerValidation, mockValidation, "", 0, 0
            )
        });

        uint256 gasUsed = _userOpBenchmark(userOp);

        assertEq(address(recipient).balance, 0.1 ether + 1 wei);

        _snap(USER_OP, "deferredValidation", gasUsed);
    }
}
