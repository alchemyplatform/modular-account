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

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {HookConfig, HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntity, ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {IAccountExecute} from "@eth-infinitism/account-abstraction/interfaces/IAccountExecute.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {MockModule} from "../mocks/modules/MockModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract PostHookDataTest is AccountTestBase {
    struct FuzzConfig {
        uint8 execHookCount;
        bytes[256] preHookReturnData;
        uint8[256] hookOptions; // includes whether to set to a pre hook, post hook, or both
    }

    // installed entity id is their index
    MockModule[] public execHooks;

    uint32 public constant NEW_VALIDATION_ENTITY_ID = 1;
    // installed with entity id 1
    MockModule public validationModule;

    ModuleEntity internal _validationFunction;

    event ReceivedCall(bytes msgData, uint256 msgValue);

    function setUp() public override {
        _allowTestDirectCalls();
    }

    function testFuzz_randomizedValAssocExecHooks_passDataCorrectly_userOp(FuzzConfig memory fuzzConfig) public {
        fuzzConfig.execHookCount = uint8(bound(fuzzConfig.execHookCount, 0, 256));

        _installValidationAndAssocHooks(fuzzConfig);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: _encodeNonce(_validationFunction, GLOBAL_V, 0),
            initCode: hex"",
            callData: abi.encodePacked(
                IAccountExecute.executeUserOp.selector, abi.encodeCall(account1.execute, (beneficiary, 0, hex""))
            ),
            accountGasLimits: _encodeGas(type(uint40).max, type(uint24).max),
            preVerificationGas: 0,
            gasFees: _encodeGas(0, 1),
            paymasterAndData: hex"",
            signature: _encodeSignature("")
        });
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        _expectAndMockExecHooks(
            fuzzConfig, address(entryPoint), 0, abi.encodeCall(IAccountExecute.executeUserOp, (userOp, userOpHash))
        );
        vm.prank(beneficiary);
        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_valAssocExecHooks_passDataCorrectly_userOp_example() public {
        FuzzConfig memory fuzzConfig;

        fuzzConfig.execHookCount = 3;
        fuzzConfig.hookOptions[0] = 1;
        fuzzConfig.hookOptions[1] = 2;
        fuzzConfig.hookOptions[2] = 3;

        fuzzConfig.preHookReturnData[2] = hex"1234";

        testFuzz_randomizedValAssocExecHooks_passDataCorrectly_userOp(fuzzConfig);
    }

    function testFuzz_randomizedValAssocExecHooks_passDataCorrectly_runtime(FuzzConfig memory fuzzConfig) public {
        fuzzConfig.execHookCount = uint8(bound(fuzzConfig.execHookCount, 0, 256));

        _installValidationAndAssocHooks(fuzzConfig);

        bytes memory callData = abi.encodeCall(account1.execute, (beneficiary, 0, hex""));
        bytes memory authorization = _encodeSignature(_validationFunction, GLOBAL_VALIDATION, "");

        _expectAndMockExecHooks(fuzzConfig, address(beneficiary), 0, callData);
        vm.prank(beneficiary);
        account1.executeWithRuntimeValidation(callData, authorization);
    }

    // todo: direct call validation testing

    function test_randomizedValAssocExecHooks_passDataCorrectly_runtime_example() public {
        FuzzConfig memory fuzzConfig;

        fuzzConfig.execHookCount = 3;
        fuzzConfig.hookOptions[0] = 1;
        fuzzConfig.hookOptions[1] = 2;
        fuzzConfig.hookOptions[2] = 3;

        fuzzConfig.preHookReturnData[2] = hex"1234";

        testFuzz_randomizedValAssocExecHooks_passDataCorrectly_runtime(fuzzConfig);
    }

    // todo: do the same with selector-assoc, and both types of hooks

    function _expectAndMockExecHooks(
        FuzzConfig memory fuzzConfig,
        address sender,
        uint256 value,
        bytes memory callData
    ) internal {
        // We must use two passes, as the order in which we call expectEmit matters.
        for (uint256 i = 0; i < fuzzConfig.execHookCount; i++) {
            bool hasPre = fuzzConfig.hookOptions[i] & 1 != 0;
            bool hasPost = fuzzConfig.hookOptions[i] & 2 != 0;

            if (hasPre && hasPost) {
                // Both a pre and post hook.
                // Mock the pre hook, expect the post hook call
                vm.mockCall(
                    address(execHooks[i]),
                    abi.encodeWithSelector(IExecutionHookModule.preExecutionHook.selector),
                    // If the module receives a call to preExecutionHook, it should return the fuzz-generated data
                    // abi-encode this data to match the return type of the function
                    abi.encode(fuzzConfig.preHookReturnData[i])
                );

                // The corresponding post hook expect emit is handled later
            } else if (hasPre) {
                // Only a pre hook.
                // expect the pre hook call
                vm.expectEmit(address(execHooks[i]));
                emit ReceivedCall(
                    abi.encodeCall(IExecutionHookModule.preExecutionHook, (uint32(i), sender, value, callData)), 0
                );
            }
        }

        // Iterate in reverse order for post-exec hooks
        for (uint256 i = fuzzConfig.execHookCount; i > 0;) {
            --i;

            bool hasPre = fuzzConfig.hookOptions[i] & 1 != 0;
            bool hasPost = fuzzConfig.hookOptions[i] & 2 != 0;

            if (hasPre && hasPost) {
                // Both a pre and post hook.
                // Call was previously mocked, expect the post hook call here

                vm.expectEmit(address(execHooks[i]));
                emit ReceivedCall(
                    abi.encodeCall(
                        IExecutionHookModule.postExecutionHook, (uint32(i), fuzzConfig.preHookReturnData[i])
                    ),
                    0
                );
            } else if (hasPost) {
                // Only a post hook.
                // Expect the post hook call with empty data
                vm.expectEmit(address(execHooks[i]));
                emit ReceivedCall(abi.encodeCall(IExecutionHookModule.postExecutionHook, (uint32(i), "")), 0);
            }
        }
    }

    function _installValidationAndAssocHooks(FuzzConfig memory fuzzConfig) internal {
        HookConfig[] memory hooks = new HookConfig[](fuzzConfig.execHookCount);
        bytes[] memory hookInstalls = new bytes[](fuzzConfig.execHookCount);

        ExecutionManifest memory m; // empty manifest
        execHooks = new MockModule[](fuzzConfig.execHookCount);

        for (uint256 i = 0; i < fuzzConfig.execHookCount; i++) {
            execHooks[i] = new MockModule(m);

            hooks[i] = HookConfigLib.packExecHook({
                _module: address(execHooks[i]),
                _entityId: uint32(i),
                _hasPre: fuzzConfig.hookOptions[i] & 1 != 0,
                _hasPost: fuzzConfig.hookOptions[i] & 2 != 0
            });

            hookInstalls[i] = abi.encodePacked(hooks[i]);
        }

        validationModule = new MockModule(m);

        account1.installValidation(
            ValidationConfigLib.pack({
                _module: address(validationModule),
                _entityId: NEW_VALIDATION_ENTITY_ID,
                _isGlobal: true,
                _isSignatureValidation: true,
                _isUserOpValidation: true
            }),
            new bytes4[](0),
            "",
            hookInstalls
        );

        _validationFunction = ModuleEntityLib.pack(address(validationModule), NEW_VALIDATION_ENTITY_ID);
    }
}
