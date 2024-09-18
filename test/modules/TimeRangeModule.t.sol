// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {_packValidationData} from "@eth-infinitism/account-abstraction/core/Helpers.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ValidationDataView} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {HookConfigLib} from "../../src/libraries/HookConfigLib.sol";
import {ModuleEntity, ModuleEntityLib} from "../../src/libraries/ModuleEntityLib.sol";
import {TimeRangeModule} from "../../src/modules/permissions/TimeRangeModule.sol";

import {CustomValidationTestBase} from "../utils/CustomValidationTestBase.sol";

contract TimeRangeModuleTest is CustomValidationTestBase {
    TimeRangeModule public timeRangeModule;

    uint32 public constant HOOK_ENTITY_ID = 0;

    ModuleEntity internal _hookEntity;

    uint48 public validUntil;
    uint48 public validAfter;

    function setUp() public {
        _signerValidation =
            ModuleEntityLib.pack(address(singleSignerValidationModule), TEST_DEFAULT_VALIDATION_ENTITY_ID);

        timeRangeModule = new TimeRangeModule();

        _hookEntity = ModuleEntityLib.pack(address(timeRangeModule), HOOK_ENTITY_ID);
    }

    function test_timeRangeModule_moduleId() public view {
        assertEq(timeRangeModule.moduleId(), "alchemy.timerange-module.0.0.1");
    }

    function test_timeRangeModule_install() public {
        validUntil = 1000;
        validAfter = 100;

        _customValidationSetup();

        // Verify that it is installed
        ValidationDataView memory validationData = account1.getValidationData(_signerValidation);

        assertTrue(validationData.isGlobal);
        assertTrue(validationData.isSignatureValidation);
        assertTrue(validationData.isUserOpValidation);

        assertEq(validationData.preValidationHooks.length, 1);
        assertEq(ModuleEntity.unwrap(validationData.preValidationHooks[0]), ModuleEntity.unwrap(_hookEntity));

        assertEq(validationData.executionHooks.length, 0);
        assertEq(validationData.selectors.length, 0);

        // Verify that the time range is set
        (uint48 retrievedValidUntil, uint48 retrievedValidAfter) =
            timeRangeModule.timeRanges(HOOK_ENTITY_ID, address(account1));
        assertEq(retrievedValidUntil, validUntil);
        assertEq(retrievedValidAfter, validAfter);
    }

    function test_timeRangeModule_uninstall() public {
        test_timeRangeModule_install();

        // Uninstall the module
        bytes[] memory hookUninstallDatas = new bytes[](1);
        hookUninstallDatas[0] = abi.encode(HOOK_ENTITY_ID);

        vm.expectCall({
            callee: address(timeRangeModule),
            data: abi.encodeCall(TimeRangeModule.onUninstall, (hookUninstallDatas[0])),
            count: 1
        });
        vm.prank(address(account1));
        account1.uninstallValidation(_signerValidation, "", hookUninstallDatas);

        // Verify that the time range data is unset
        (uint48 retrievedValidUntil, uint48 retrievedValidAfter) =
            timeRangeModule.timeRanges(HOOK_ENTITY_ID, address(account1));

        assertEq(retrievedValidUntil, 0);
        assertEq(retrievedValidAfter, 0);
    }

    function testFuzz_timeRangeModule_userOp(uint48 _validUntil, uint48 _validAfter) public {
        validUntil = _validUntil;
        validAfter = _validAfter;

        _customValidationSetup();

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: hex"",
            callData: abi.encodeCall(ModularAccount.execute, (makeAddr("recipient"), 0 wei, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));

        userOp.signature = _encodeSignature(_signerValidation, GLOBAL_VALIDATION, abi.encodePacked(r, s, v));

        vm.prank(address(entryPoint));
        uint256 validationData = account1.validateUserOp(userOp, userOpHash, 0);

        uint48 expectedValidUntil = validUntil == 0 ? type(uint48).max : validUntil;

        assertEq(
            validationData,
            _packValidationData({sigFailed: false, validUntil: expectedValidUntil, validAfter: validAfter})
        );
    }

    function testFuzz_timeRangeModule_userOp_fail(uint48 _validUntil, uint48 _validAfter) public {
        validUntil = _validUntil;
        validAfter = _validAfter;

        _customValidationSetup();

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: hex"",
            callData: abi.encodeCall(ModularAccount.execute, (makeAddr("recipient"), 0 wei, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: hex""
        });
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        // Generate a bad signature
        userOp.signature = _encodeSignature(_signerValidation, GLOBAL_VALIDATION, abi.encodePacked("abcd"));

        vm.prank(address(entryPoint));
        uint256 validationData = account1.validateUserOp(userOp, userOpHash, 0);

        uint48 expectedValidUntil = validUntil == 0 ? type(uint48).max : validUntil;

        assertEq(
            validationData,
            _packValidationData({sigFailed: true, validUntil: expectedValidUntil, validAfter: validAfter})
        );
    }

    function test_timeRangeModule_runtime_before() public {
        validUntil = 1000;
        validAfter = 100;

        _customValidationSetup();

        // Attempt from before the valid time range, expect fail
        vm.warp(1);

        vm.expectRevert(
            abi.encodeWithSelector(
                ModularAccount.PreRuntimeValidationHookFailed.selector,
                timeRangeModule,
                HOOK_ENTITY_ID,
                abi.encodeWithSelector(TimeRangeModule.TimeRangeNotValid.selector)
            )
        );
        vm.prank(owner1);
        account1.executeWithAuthorization(
            abi.encodeCall(ModularAccount.execute, (makeAddr("recipient"), 0 wei, "")),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
        );
    }

    function test_timeRangeModule_runtime_during() public {
        validUntil = 1000;
        validAfter = 100;

        _customValidationSetup();

        // Attempt during the valid time range, expect success
        vm.warp(101);

        vm.expectCall({callee: makeAddr("recipient"), msgValue: 0 wei, data: "", count: 1});
        vm.prank(owner1);
        account1.executeWithAuthorization(
            abi.encodeCall(ModularAccount.execute, (makeAddr("recipient"), 0 wei, "")),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
        );
    }

    function test_timeRangeModule_runtime_after() public {
        validUntil = 1000;
        validAfter = 100;

        _customValidationSetup();

        // Attempt after the valid time range, expect fail
        vm.warp(1001);

        vm.expectRevert(
            abi.encodeWithSelector(
                ModularAccount.PreRuntimeValidationHookFailed.selector,
                timeRangeModule,
                HOOK_ENTITY_ID,
                abi.encodeWithSelector(TimeRangeModule.TimeRangeNotValid.selector)
            )
        );
        vm.prank(owner1);
        account1.executeWithAuthorization(
            abi.encodeCall(ModularAccount.execute, (makeAddr("recipient"), 0 wei, "")),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
        );
    }

    function _initialValidationConfig()
        internal
        virtual
        override
        returns (ModuleEntity, bool, bool, bool, bytes4[] memory, bytes memory, bytes[] memory)
    {
        bytes[] memory hooks = new bytes[](1);
        hooks[0] = abi.encodePacked(
            HookConfigLib.packValidationHook(address(timeRangeModule), HOOK_ENTITY_ID),
            abi.encode(HOOK_ENTITY_ID, validUntil, validAfter)
        );
        // patched to also work during SMA tests by differentiating the validation
        _signerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), type(uint32).max - 1);
        return
            (_signerValidation, true, true, true, new bytes4[](0), abi.encode(type(uint32).max - 1, owner1), hooks);
    }
}
