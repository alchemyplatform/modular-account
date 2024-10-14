// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {BaseModule} from "../../src/modules/BaseModule.sol";
import {PaymasterGuardModule} from "../../src/modules/permissions/PaymasterGuardModule.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract PaymasterGuardModuleTest is AccountTestBase {
    PaymasterGuardModule public module = new PaymasterGuardModule();

    address public account;
    address public paymaster1;
    address public paymaster2;
    uint32 public constant ENTITY_ID = 1;

    function setUp() public override {
        account = payable(makeAddr("account"));
        paymaster1 = payable(makeAddr("paymaster1"));
        paymaster2 = payable(makeAddr("paymaster2"));
    }

    function test_onInstall() public withSMATest {
        vm.startPrank(address(account));
        module.onInstall(abi.encode(ENTITY_ID, paymaster1));

        assertEq(paymaster1, module.paymasters(ENTITY_ID, account));
    }

    function test_onUninstall() public withSMATest {
        vm.startPrank(address(account));
        module.onUninstall(abi.encode(ENTITY_ID));

        assertEq(address(0), module.paymasters(ENTITY_ID, account));
    }

    function test_preUserOpValidationHook_success() public withSMATest {
        PackedUserOperation memory uo = _packUO(abi.encodePacked(paymaster1, ""));

        vm.startPrank(address(account));
        // install the right paymaster
        module.onInstall(abi.encode(ENTITY_ID, paymaster1));
        uint256 res = module.preUserOpValidationHook(ENTITY_ID, uo, bytes32(0));

        assertEq(res, 0);
    }

    function test_preUserOpValidationHook_failWithInvalidData() public withSMATest {
        PackedUserOperation memory uo = _packUO("");

        vm.startPrank(address(account));
        module.onInstall(abi.encode(ENTITY_ID, paymaster1));

        vm.expectRevert();
        module.preUserOpValidationHook(ENTITY_ID, uo, bytes32(0));
    }

    function test_preUserOpValidationHook_failWithValidationData() public withSMATest {
        PackedUserOperation memory uo = _packUO(abi.encodePacked(paymaster1, ""));

        vm.startPrank(address(account));
        // install the right paymaster
        module.onInstall(abi.encode(ENTITY_ID, paymaster1));

        // Assert that it would succeed

        uint256 stateSnapshot = vm.snapshot();

        uint256 res = module.preUserOpValidationHook(ENTITY_ID, uo, bytes32(0));

        assertEq(res, 0);

        vm.revertTo(stateSnapshot);

        // Now, test with validation hook data, and expect failure

        uo.signature = hex"1234";

        vm.expectRevert(abi.encodeWithSelector(BaseModule.UnexpectedDataPassed.selector));
        module.preUserOpValidationHook(ENTITY_ID, uo, bytes32(0));
    }

    function test_preUserOpValidationHook_fail() public withSMATest {
        PackedUserOperation memory uo = _packUO(abi.encodePacked(paymaster1, ""));

        vm.startPrank(address(account));
        // install the wrong paymaster
        module.onInstall(abi.encode(ENTITY_ID, paymaster2));

        vm.expectRevert(abi.encodeWithSelector(PaymasterGuardModule.BadPaymasterSpecified.selector));
        module.preUserOpValidationHook(ENTITY_ID, uo, bytes32(0));
    }

    function test_preRuntimeValidationHook_success() public withSMATest {
        vm.startPrank(address(account));

        module.preRuntimeValidationHook(ENTITY_ID, address(0), 0, "", "");
    }

    function _packUO(bytes memory paymasterAndData) internal view returns (PackedUserOperation memory) {
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
