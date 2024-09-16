// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {VmSafe} from "forge-std/src/Vm.sol";
import {console} from "forge-std/src/console.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";

import {ModularAccountBenchmarkBase} from "./BenchmarkBase.sol";

contract ModularAccountRuntimeTest is ModularAccountBenchmarkBase {
    function test_modularAccountGas_runtimeAccountCreation() public {
        uint256 salt = 0;
        uint32 entityId = 0;

        factory.createAccount(owner1, salt, entityId);

        VmSafe.Gas memory gas = vm.lastCallGas();

        console.log("Runtime: account creation: ");
        console.log("gasTotalUsed: %d", gas.gasTotalUsed);

        snap("ModularAccount_Runtime_AccountCreation", gas.gasTotalUsed);
    }

    function test_modularAccountGas_runtimeNativeTransfer() public {
        _deployAccount1();

        vm.deal(address(account1), 1 ether);

        vm.prank(owner1);
        account1.executeWithAuthorization(
            abi.encodeCall(ModularAccount.execute, (recipient, 0.1 ether, "")),
            _encodeSignature(signerValidation, GLOBAL_VALIDATION, "")
        );

        VmSafe.Gas memory gas = vm.lastCallGas();

        console.log("Runtime: native transfer: ");
        console.log("gasTotalUsed: %d", gas.gasTotalUsed);

        snap("ModularAccount_Runtime_NativeTransfer", gas.gasTotalUsed);
    }

    function test_modularAccountGas_runtimeErc20Transfer() public {
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

        console.log("Runtime: erc20 transfer: ");
        console.log("gasTotalUsed: %d", gas.gasTotalUsed);

        snap("ModularAccount_Runtime_Erc20Transfer", gas.gasTotalUsed);
    }
}
