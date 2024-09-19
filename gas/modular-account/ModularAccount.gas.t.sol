// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {VmSafe} from "forge-std/src/Vm.sol";
import {console} from "forge-std/src/console.sol";

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";

import {ModularAccountBenchmarkBase} from "./ModularAccountBenchmarkBase.sol";

contract ModularAccountGasTest is ModularAccountBenchmarkBase {
    function test_modularAccountGas_runtime_accountCreation() public {
        uint256 salt = 0;
        uint32 entityId = 0;

        factory.createAccount(owner1, salt, entityId);

        VmSafe.Gas memory gas = vm.lastCallGas();

        console.log("Runtime: account creation: ");
        console.log("gasTotalUsed: %d", gas.gasTotalUsed);

        snap("ModularAccount_Runtime_AccountCreation", gas.gasTotalUsed);
    }

    function test_modularAccountGas_runtime_nativeTransfer() public {
        _deployAccount1();

        vm.deal(address(account1), 1 ether);

        vm.prank(owner1);
        account1.executeWithAuthorization(
            abi.encodeCall(ModularAccount.execute, (recipient, 0.1 ether, "")),
            _encodeSignature(signerValidation, GLOBAL_VALIDATION, "")
        );

        VmSafe.Gas memory gas = vm.lastCallGas();

        assertEq(address(recipient).balance, 0.1 ether + 1 wei);

        console.log("Runtime: native transfer: ");
        console.log("gasTotalUsed: %d", gas.gasTotalUsed);

        snap("ModularAccount_Runtime_NativeTransfer", gas.gasTotalUsed);
    }

    function test_modularAccountGas_userOp_nativeTransfer() public {
        _deployAccount1();

        vm.deal(address(account1), 1 ether);

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);

        userOps[0] = PackedUserOperation({
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

        bytes32 userOpHash = entryPoint.getUserOpHash(userOps[0]);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        userOps[0].signature = _encodeSignature(signerValidation, GLOBAL_VALIDATION, abi.encodePacked(r, s, v));

        vm.prank(beneficiary);
        entryPoint.handleOps(userOps, beneficiary);

        VmSafe.Gas memory gas = vm.lastCallGas();

        assertEq(address(recipient).balance, 0.1 ether + 1 wei);

        console.log("User Op: native transfer: ");
        console.log("gasTotalUsed: %d", gas.gasTotalUsed);

        snap("ModularAccount_UserOp_NativeTransfer", gas.gasTotalUsed);
    }

    function test_modularAccountGas_runtime_erc20Transfer() public {
        _deployAccount1();

        mockErc20.mint(address(account1), 100 ether);

        vm.prank(owner1);
        account1.executeWithAuthorization(
            abi.encodeCall(
                ModularAccount.execute,
                (address(mockErc20), 0, abi.encodeWithSelector(mockErc20.transfer.selector, recipient, 10 ether))
            ),
            _encodeSignature(signerValidation, GLOBAL_VALIDATION, "")
        );

        VmSafe.Gas memory gas = vm.lastCallGas();

        assertEq(mockErc20.balanceOf(recipient), 10 ether);

        console.log("Runtime: erc20 transfer: ");
        console.log("gasTotalUsed: %d", gas.gasTotalUsed);

        snap("ModularAccount_Runtime_Erc20Transfer", gas.gasTotalUsed);
    }

    function test_modularAccountGas_userOp_erc20Transfer() public {
        _deployAccount1();

        vm.deal(address(account1), 1 ether);

        mockErc20.mint(address(account1), 100 ether);

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);

        userOps[0] = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(
                ModularAccount.execute,
                (address(mockErc20), 0, abi.encodeWithSelector(mockErc20.transfer.selector, recipient, 10 ether))
            ),
            // don't over-estimate by a lot here, otherwise a fee is assessed.
            accountGasLimits: _encodeGasLimits(40_000, 100_000),
            preVerificationGas: 0,
            gasFees: _encodeGasFees(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOps[0]);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        userOps[0].signature = _encodeSignature(signerValidation, GLOBAL_VALIDATION, abi.encodePacked(r, s, v));

        vm.prank(beneficiary);
        entryPoint.handleOps(userOps, beneficiary);

        VmSafe.Gas memory gas = vm.lastCallGas();

        assertEq(mockErc20.balanceOf(recipient), 10 ether);

        console.log("User Op: erc20 transfer: ");
        console.log("gasTotalUsed: %d", gas.gasTotalUsed);

        snap("ModularAccount_UserOp_Erc20Transfer", gas.gasTotalUsed);
    }
}
