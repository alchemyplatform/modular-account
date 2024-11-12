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

import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {
    Call, IModularAccount, ModuleEntity
} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {Call, IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {ExecutionLib} from "../../src/libraries/ExecutionLib.sol";
import {ModuleBase} from "../../src/modules/ModuleBase.sol";
import {NativeTokenLimitModule} from "../../src/modules/permissions/NativeTokenLimitModule.sol";

import {MockDeployment} from "../mocks/MockDeployment.sol";
import {MockModule} from "../mocks/modules/MockModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract NativeTokenLimitModuleTest is AccountTestBase {
    address public recipient = makeAddr("recipient");
    ExecutionManifest internal _m;
    MockModule public validationModule = new MockModule(_m);
    ModuleEntity public validationFunction;

    NativeTokenLimitModule public module = new NativeTokenLimitModule();
    uint256 public spendLimit = 10 ether;
    uint32 public entityId = 1;

    function setUp() public override {
        _revertSnapshot = vm.snapshotState();
        // Set up a validator with hooks from the gas spend limit module attached

        ModuleEntity[] memory preValidationHooks = new ModuleEntity[](1);
        preValidationHooks[0] = ModuleEntityLib.pack(address(module), entityId);

        bytes[] memory hooks = new bytes[](2);
        hooks[0] =
            abi.encodePacked(HookConfigLib.packValidationHook({_module: address(module), _entityId: entityId}));
        // No init data for pre validation

        hooks[1] = abi.encodePacked(
            HookConfigLib.packExecHook({
                _module: address(module),
                _entityId: entityId,
                _hasPre: true,
                _hasPost: false
            }),
            abi.encode(entityId, spendLimit)
        );

        vm.prank(address(account1));
        account1.installValidation(
            ValidationConfigLib.pack(address(validationModule), entityId, true, true, true),
            new bytes4[](0),
            new bytes(0),
            hooks
        );

        validationFunction = ModuleEntityLib.pack(address(validationModule), entityId);
    }

    function _getExecuteWithValue(uint256 value) internal view returns (bytes memory) {
        return abi.encodeCall(ModularAccountBase.execute, (recipient, value, ""));
    }

    function _getPerformCreateCalldata(uint256 value) internal pure returns (bytes memory) {
        return abi.encodeCall(
            ModularAccountBase.performCreate, (value, type(MockDeployment).creationCode, false, bytes32(0))
        );
    }

    function _getPerformCreate2Calldata(uint256 value, bytes32 salt) internal pure returns (bytes memory) {
        return abi.encodeCall(
            ModularAccountBase.performCreate, (value, type(MockDeployment).creationCode, true, salt)
        );
    }

    function _getPackedUO(uint256 gas1, uint256 gas2, uint256 gas3, uint256 gasPrice, bytes memory callData)
        internal
        view
        returns (PackedUserOperation memory uo)
    {
        uo = PackedUserOperation({
            sender: address(account1),
            nonce: _encodeNonce(ModuleEntityLib.pack(address(validationModule), entityId), GLOBAL_V, 0),
            initCode: "",
            callData: abi.encodePacked(ModularAccountBase.executeUserOp.selector, callData),
            accountGasLimits: bytes32(bytes16(uint128(gas1))) | bytes32(uint256(gas2)),
            preVerificationGas: gas3,
            gasFees: bytes32(uint256(uint128(gasPrice))),
            paymasterAndData: "",
            signature: _encodeSignature("")
        });
    }

    function test_userOp_gasLimit() public withSMATest {
        vm.startPrank(address(entryPoint));

        // uses 10e - 200000 of gas
        assertEq(module.limits(entityId, address(account1)), 10 ether);
        uint256 result = account1.validateUserOp(
            _getPackedUO(100_000, 100_000, 10 ether - 400_000, 1, _getExecuteWithValue(0)), bytes32(0), 0
        );
        assertEq(module.limits(entityId, address(account1)), 200_000);

        uint256 expected = uint256(type(uint48).max) << 160;
        assertEq(result, expected);

        // uses 200k + 1 wei of gas
        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionLib.PreUserOpValidationHookReverted.selector,
                ModuleEntityLib.pack(address(module), entityId),
                abi.encodeWithSelector(NativeTokenLimitModule.ExceededNativeTokenLimit.selector)
            )
        );
        result =
            account1.validateUserOp(_getPackedUO(100_000, 100_000, 1, 1, _getExecuteWithValue(0)), bytes32(0), 0);

        vm.stopPrank();
    }

    function test_userOp_executeLimit() public withSMATest {
        vm.startPrank(address(entryPoint));

        // uses 5e of native tokens
        assertEq(module.limits(entityId, address(account1)), 10 ether);
        account1.executeUserOp(_getPackedUO(0, 0, 0, 0, _getExecuteWithValue(5 ether)), bytes32(0));
        assertEq(module.limits(entityId, address(account1)), 5 ether);

        // uses 5e + 1wei of native tokens
        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionLib.PreExecHookReverted.selector,
                ModuleEntityLib.pack(address(module), entityId),
                abi.encodePacked(NativeTokenLimitModule.ExceededNativeTokenLimit.selector)
            )
        );
        account1.executeUserOp(_getPackedUO(0, 0, 0, 0, _getExecuteWithValue(5 ether + 1)), bytes32(0));

        vm.stopPrank();
    }

    function test_userOp_invalidPaymaster() public withSMATest {
        assertEq(module.limits(entityId, address(account1)), 10 ether);
        PackedUserOperation[] memory uos = new PackedUserOperation[](1);
        uos[0] = _getPackedUO(200_000, 200_000, 200_000, 1, _getExecuteWithValue(5 ether));
        uos[0].paymasterAndData = new bytes(52);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(
                    ExecutionLib.PreUserOpValidationHookReverted.selector,
                    ModuleEntityLib.pack(address(module), entityId),
                    abi.encodeWithSelector(NativeTokenLimitModule.InvalidPaymaster.selector)
                )
            )
        );
        entryPoint.handleOps(uos, beneficiary);
    }

    function test_userOp_executeBatchLimit() public withSMATest {
        Call[] memory calls = new Call[](3);
        calls[0] = Call({target: recipient, value: 1, data: ""});
        calls[1] = Call({target: recipient, value: 1 ether, data: ""});
        calls[2] = Call({target: recipient, value: 5 ether + 100_000, data: ""});

        vm.startPrank(address(entryPoint));
        assertEq(module.limits(entityId, address(account1)), 10 ether);
        account1.executeUserOp(
            _getPackedUO(0, 0, 0, 0, abi.encodeCall(IModularAccount.executeBatch, (calls))), bytes32(0)
        );
        assertEq(module.limits(entityId, address(account1)), 10 ether - 6 ether - 100_001);
        assertEq(recipient.balance, 6 ether + 100_001);

        vm.stopPrank();
    }

    function test_userOp_performCreateLimit() public withSMATest {
        vm.startPrank(address(entryPoint));

        // uses 5e of native tokens
        assertEq(module.limits(entityId, address(account1)), 10 ether);
        account1.executeUserOp(_getPackedUO(0, 0, 0, 0, _getPerformCreateCalldata(5 ether)), bytes32(0));
        assertEq(module.limits(entityId, address(account1)), 5 ether);

        vm.stopPrank();
    }

    function test_userOp_performCreate2Limit() public withSMATest {
        vm.startPrank(address(entryPoint));

        // uses 5e of native tokens
        assertEq(module.limits(entityId, address(account1)), 10 ether);
        account1.executeUserOp(_getPackedUO(0, 0, 0, 0, _getPerformCreate2Calldata(5 ether, 0)), bytes32(0));
        assertEq(module.limits(entityId, address(account1)), 5 ether);

        vm.stopPrank();
    }

    function test_userOp_combinedExecLimit_success() public withSMATest {
        assertEq(module.limits(entityId, address(account1)), 10 ether);
        PackedUserOperation[] memory uos = new PackedUserOperation[](1);
        uos[0] = _getPackedUO(200_000, 200_000, 200_000, 1, _getExecuteWithValue(5 ether));
        entryPoint.handleOps(uos, beneficiary);

        assertEq(module.limits(entityId, address(account1)), 5 ether - 600_000);
        assertEq(recipient.balance, 5 ether);
    }

    function test_userOp_combinedExecBatchLimit_success() public withSMATest {
        Call[] memory calls = new Call[](3);
        calls[0] = Call({target: recipient, value: 1, data: ""});
        calls[1] = Call({target: recipient, value: 1 ether, data: ""});
        calls[2] = Call({target: recipient, value: 5 ether + 100_000, data: ""});

        vm.startPrank(address(entryPoint));
        assertEq(module.limits(entityId, address(account1)), 10 ether);
        PackedUserOperation[] memory uos = new PackedUserOperation[](1);
        uos[0] = _getPackedUO(200_000, 200_000, 200_000, 1, abi.encodeCall(IModularAccount.executeBatch, (calls)));
        entryPoint.handleOps(uos, beneficiary);

        assertEq(module.limits(entityId, address(account1)), 10 ether - 6 ether - 700_001);
        assertEq(recipient.balance, 6 ether + 100_001);

        vm.stopPrank();
    }

    function test_userOp_combinedExecLimit_failExec() public withSMATest {
        assertEq(module.limits(entityId, address(account1)), 10 ether);
        PackedUserOperation[] memory uos = new PackedUserOperation[](1);
        uos[0] = _getPackedUO(200_000, 200_000, 200_000, 1, _getExecuteWithValue(10 ether));
        entryPoint.handleOps(uos, beneficiary);

        assertEq(module.limits(entityId, address(account1)), 10 ether - 600_000);
        assertEq(recipient.balance, 0);
    }

    function test_userOp_paymaster() public withSMATest {
        vm.startPrank(address(entryPoint));

        assertEq(module.limits(entityId, address(account1)), 10 ether);
        PackedUserOperation memory uo = _getPackedUO(200_000, 200_000, 200_000, 1, _getExecuteWithValue(10 ether));
        uo.paymasterAndData =
            abi.encodePacked(address(account1), uint128(uint256(1_000_000)), uint128(uint256(1_000_000)));
        uint256 validationData = account1.validateUserOp(uo, bytes32(0), 0);

        assertEq(validationData & 0x1, 0); // check for success
        assertEq(module.limits(entityId, address(account1)), 10 ether); // limit should not decrease
        assertEq(recipient.balance, 0);
        vm.stopPrank();
    }

    function test_userOp_specialPaymaster() public withSMATest {
        vm.prank(address(account1));
        module.updateSpecialPaymaster(address(account1), true);

        vm.startPrank(address(entryPoint));

        assertEq(module.limits(entityId, address(account1)), 10 ether);
        PackedUserOperation memory uo = _getPackedUO(200_000, 200_000, 200_000, 1, _getExecuteWithValue(5 ether));
        uo.paymasterAndData =
            abi.encodePacked(address(account1), uint128(uint256(200_000)), uint128(uint256(200_000)));
        uint256 validationData = account1.validateUserOp(uo, bytes32(0), 0);

        assertEq(validationData & 0x1, 0); // check for success
        assertEq(module.limits(entityId, address(account1)), 10 ether - 200_000 * 5); // limit should not decrease
        assertEq(recipient.balance, 0);
        vm.stopPrank();
    }

    function test_runtime_executeLimit() public withSMATest {
        assertEq(module.limits(entityId, address(account1)), 10 ether);
        account1.executeWithRuntimeValidation(
            _getExecuteWithValue(5 ether), _encodeSignature(validationFunction, 1, "")
        );
        assertEq(module.limits(entityId, address(account1)), 5 ether);
    }

    function test_runtime_executeBatchLimit() public withSMATest {
        Call[] memory calls = new Call[](3);
        calls[0] = Call({target: recipient, value: 1, data: ""});
        calls[1] = Call({target: recipient, value: 1 ether, data: ""});
        calls[2] = Call({target: recipient, value: 5 ether + 100_000, data: ""});

        assertEq(module.limits(entityId, address(account1)), 10 ether);
        account1.executeWithRuntimeValidation(
            abi.encodeCall(IModularAccount.executeBatch, (calls)), _encodeSignature(validationFunction, 1, "")
        );
        assertEq(module.limits(entityId, address(account1)), 4 ether - 100_001);
    }

    function test_runtime_performCreateLimit() public withSMATest {
        assertEq(module.limits(entityId, address(account1)), 10 ether);
        bytes memory b = account1.executeWithRuntimeValidation(
            _getPerformCreateCalldata(5 ether), _encodeSignature(validationFunction, 1, "")
        );
        assertEq(module.limits(entityId, address(account1)), 5 ether);

        address deployed = abi.decode(b, (address));
        assertEq(deployed.balance, 5 ether);
    }

    function test_runtime_performCreate2Limit() public withSMATest {
        assertEq(module.limits(entityId, address(account1)), 10 ether);
        bytes memory b = account1.executeWithRuntimeValidation(
            _getPerformCreate2Calldata({value: 5 ether, salt: bytes32(0)}),
            _encodeSignature(validationFunction, 1, "")
        );
        assertEq(module.limits(entityId, address(account1)), 5 ether);

        address deployed = abi.decode(b, (address));
        assertEq(deployed.balance, 5 ether);
    }

    function test_userOp_failsWithValidationData() public withSMATest {
        PackedUserOperation[] memory uos = new PackedUserOperation[](1);
        uos[0] = _getPackedUO(200_000, 200_000, 200_000, 1, _getExecuteWithValue(5 ether));

        // Assert that this would pass
        uint256 stateSnapshot = vm.snapshotState();
        vm.prank(beneficiary);
        entryPoint.handleOps(uos, beneficiary);

        vm.revertToState(stateSnapshot);

        // Now, assert it fails with >0 validation data.

        // Pass the module validation hook data.
        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({index: uint8(0), validationData: "abcd"});

        uos[0].signature = _encodeSignature(preValidationHookData, "");

        vm.prank(beneficiary);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(
                    ExecutionLib.PreUserOpValidationHookReverted.selector,
                    ModuleEntityLib.pack(address(module), entityId),
                    abi.encodeWithSelector(ModuleBase.UnexpectedDataPassed.selector)
                )
            )
        );
        entryPoint.handleOps(uos, beneficiary);
    }

    function test_deleteSingleSessionKey() public withSMATest {
        uint32 newEntityId = 2;

        // Add new entity, delete latest entity, old limit should still work
        ModuleEntity[] memory preValidationHooks = new ModuleEntity[](1);
        preValidationHooks[0] = ModuleEntityLib.pack(address(module), newEntityId);

        bytes[] memory hooks = new bytes[](2);
        hooks[0] =
            abi.encodePacked(HookConfigLib.packValidationHook({_module: address(module), _entityId: newEntityId}));

        hooks[1] = abi.encodePacked(
            HookConfigLib.packExecHook({
                _module: address(module),
                _entityId: entityId,
                _hasPre: true,
                _hasPost: false
            }),
            abi.encode(newEntityId, spendLimit)
        );

        vm.startPrank(address(account1));
        account1.installValidation(
            ValidationConfigLib.pack(address(validationModule), newEntityId, true, true, true),
            new bytes4[](0),
            new bytes(0),
            hooks
        );

        account1.uninstallValidation(
            ModuleEntityLib.pack(address(module), newEntityId), abi.encode(newEntityId), new bytes[](0)
        );

        // prev test passes, implying that the previously allocated limit still exists
        test_userOp_executeLimit();

        vm.stopPrank();
    }
}
