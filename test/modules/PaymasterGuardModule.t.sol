// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {PaymasterGuardModule} from "../../src/modules/PaymasterGuardModule.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract PaymasterGuardModuleTest is AccountTestBase {
    PaymasterGuardModule public module = new PaymasterGuardModule();

    address public account;
    address public paymaster1;
    address public paymaster2;
    uint32 public constant ENTITY_ID = 1;

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
        module.onUninstall(abi.encode(ENTITY_ID));

        assertEq(address(0), module.payamsters(ENTITY_ID, account));
    }

    function test_preUserOpValidationHook_success() public {
        PackedUserOperation memory uo = _packUO(abi.encodePacked(paymaster1, ""));

        vm.startPrank(address(account));
        // install the right paymaster
        module.onInstall(abi.encode(ENTITY_ID, paymaster1));
        uint256 res = module.preUserOpValidationHook(ENTITY_ID, uo, "");

        assertEq(res, 0);
    }

    function test_preUserOpValidationHook_failWithInvalidData() public {
        PackedUserOperation memory uo = _packUO("");

        vm.startPrank(address(account));
        module.onInstall(abi.encode(ENTITY_ID, paymaster1));

        vm.expectRevert();
        module.preUserOpValidationHook(ENTITY_ID, uo, "");
    }

    function test_preUserOpValidationHook_fail() public {
        PackedUserOperation memory uo = _packUO(abi.encodePacked(paymaster1, ""));

        vm.startPrank(address(account));
        // install the wrong paymaster
        module.onInstall(abi.encode(ENTITY_ID, paymaster2));

        vm.expectRevert(abi.encodeWithSelector(PaymasterGuardModule.BadPaymasterSpecified.selector));
        module.preUserOpValidationHook(ENTITY_ID, uo, "");
    }

    function test_preRuntimeValidationHook_success() public {
        vm.startPrank(address(account));

        module.preRuntimeValidationHook(ENTITY_ID, address(0), 0, "", "");
    }

    function _packUO(bytes memory paymasterAndData) internal returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: account,
            nonce: 0,
            initCode: "",
            callData: abi.encodePacked(""),
            accountGasLimits: bytes32(bytes16(uint128(200_000))) | bytes32(uint256(200_000)),
            preVerificationGas: 200_000,
            gasFees: bytes32(uint256(uint128(0))),
            paymasterAndData: paymasterAndData,
            signature: ""
        });
    }
}
