// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {BaseModule} from "../../src/modules/BaseModule.sol";
import {PaymasterGuardModule} from "../../src/modules/PaymasterGuardModule.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract PaymasterGuardModuleTest is AccountTestBase {
    PaymasterGuardModule public module = new PaymasterGuardModule();

    address account;
    address paymaster1;
    address paymaster2;
    uint32 constant ENTITY_ID = 1;

    function setUp() public {
        account = payable(makeAddr("account"));
        paymaster1 = payable(makeAddr("paymaster1"));
        paymaster2 = payable(makeAddr("paymaster2"));
    }

    function test_onInstall() public {
        vm.startPrank(address(account));
        module.onInstall(abi.encode(ENTITY_ID, paymaster1));

        assertEq(paymaster1, module.payamsters(ENTITY_ID, account));
    }

    function test_onUinstall() public {
        vm.startPrank(address(account));
        module.onUninstall(abi.encode(ENTITY_ID, paymaster1));

        assertEq(address(0), module.payamsters(ENTITY_ID, account));
    }

    function test_preUserOpValidationHook_success() public {
        PackedUserOperation memory uo = _packUO();

        vm.startPrank(address(account));
        // install the right paymaster
        module.onInstall(abi.encode(ENTITY_ID, paymaster1));
        uint256 res = module.preUserOpValidationHook(ENTITY_ID, uo, "");

        assertEq(res, 0);
    }

    function test_preUserOpValidationHook_fail() public {
        PackedUserOperation memory uo = _packUO();

        vm.startPrank(address(account));
        // install the wrong paymaster
        module.onInstall(abi.encode(ENTITY_ID, paymaster2));

        vm.expectRevert(abi.encodeWithSelector(PaymasterGuardModule.NotAuthorized.selector));
        module.preUserOpValidationHook(ENTITY_ID, uo, "");
    }

    function test_preRuntimeValidationHook_fail() public {
        vm.startPrank(address(account));
        // install the wrong paymaster
        module.onInstall(abi.encode(ENTITY_ID, paymaster2));

        vm.expectRevert(abi.encodeWithSelector(BaseModule.NotImplemented.selector));
        module.preRuntimeValidationHook(ENTITY_ID, address(0), 0, "", "");
    }

    function _packUO() internal returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: account,
            nonce: 0,
            initCode: "",
            callData: abi.encodePacked(""),
            accountGasLimits: bytes32(bytes16(uint128(200_000))) | bytes32(uint256(200_000)),
            preVerificationGas: 200_000,
            gasFees: bytes32(uint256(uint128(0))),
            paymasterAndData: abi.encodePacked(paymaster1, ""),
            signature: ""
        });
    }
}
