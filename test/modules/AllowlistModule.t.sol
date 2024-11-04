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

import {ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {Call} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {ExecutionLib} from "../../src/libraries/ExecutionLib.sol";
import {ModuleBase} from "../../src/modules/ModuleBase.sol";
import {AllowlistModule} from "../../src/modules/permissions/AllowlistModule.sol";

import {Counter} from "../mocks/Counter.sol";
import {CustomValidationTestBase} from "../utils/CustomValidationTestBase.sol";

contract AllowlistModuleTest is CustomValidationTestBase {
    AllowlistModule public allowlistModule;

    AllowlistModule.AllowlistInput[] public allowlistInputs;

    Counter[] public counters;

    uint32 public constant HOOK_ENTITY_ID = 0;

    event AddressAllowlistUpdated(
        uint32 indexed entityId,
        address indexed account,
        address indexed target,
        AllowlistModule.AddressAllowlistEntry entry
    );
    event SelectorAllowlistUpdated(
        uint32 indexed entityId, address indexed account, bytes24 indexed targetAndSelector, bool allowed
    );

    function setUp() public override {
        _signerValidation =
            ModuleEntityLib.pack(address(singleSignerValidationModule), TEST_DEFAULT_VALIDATION_ENTITY_ID);

        allowlistModule = new AllowlistModule();

        counters = new Counter[](10);

        for (uint256 i = 0; i < counters.length; i++) {
            counters[i] = new Counter();
        }

        // Don't call `_customValidationSetup` here, as we want to test various configurations of install data.
    }

    function test_onInstall() public {
        // install inputs, see comments for case details
        vm.prank(address(account1));
        allowlistModule.onInstall(abi.encode(HOOK_ENTITY_ID, _getInputsForTests()));

        // verify case 1 - a selector (Counter.setNumber) + address (counters[0]) should match
        (bool allowed, bool hasSelectorAllowlist,) =
            allowlistModule.addressAllowlist(HOOK_ENTITY_ID, address(counters[0]), address(account1));
        assertTrue(allowed);
        assertTrue(hasSelectorAllowlist);
        assertTrue(
            allowlistModule.selectorAllowlist(
                HOOK_ENTITY_ID, Counter.setNumber.selector, address(counters[0]), address(account1)
            )
        );

        // verify case 2 - wildcard selector (Counter.increment), any address works
        assertTrue(
            allowlistModule.selectorAllowlist(
                HOOK_ENTITY_ID, Counter.increment.selector, address(0), address(account1)
            )
        );

        // verify case 3 - wildcard address (counters[1]), any selector works
        (bool allowed3, bool hasSelectorAllowlist3,) =
            allowlistModule.addressAllowlist(HOOK_ENTITY_ID, address(counters[1]), address(account1));
        assertTrue(allowed3);
        assertFalse(hasSelectorAllowlist3);
    }

    function test_onUninstall() public {
        // install inputs, see comments for case details
        AllowlistModule.AllowlistInput[] memory inputs = _getInputsForTests();
        vm.startPrank(address(account1));
        allowlistModule.onInstall(abi.encode(HOOK_ENTITY_ID, inputs));
        allowlistModule.onUninstall(abi.encode(HOOK_ENTITY_ID, inputs));
        vm.stopPrank();

        // verify case 1 - a selector (Counter.setNumber) + address (counters[0]) should match
        (bool allowed, bool hasSelectorAllowlist,) =
            allowlistModule.addressAllowlist(HOOK_ENTITY_ID, address(counters[0]), address(account1));
        assertFalse(allowed);
        assertFalse(hasSelectorAllowlist);
        assertFalse(
            allowlistModule.selectorAllowlist(
                HOOK_ENTITY_ID, Counter.setNumber.selector, address(counters[0]), address(account1)
            )
        );

        // verify case 2 - wildcard selector (Counter.increment), any address works
        assertFalse(
            allowlistModule.selectorAllowlist(
                HOOK_ENTITY_ID, Counter.increment.selector, address(0), address(account1)
            )
        );

        // verify case 3 - wildcard address (counters[1]), any selector works
        (bool allowed3, bool hasSelectorAllowlist3,) =
            allowlistModule.addressAllowlist(HOOK_ENTITY_ID, address(counters[1]), address(account1));
        assertFalse(allowed3);
        assertFalse(hasSelectorAllowlist3);
    }

    function test_nativeTokenTransfer_success() public {
        // install inputs, see comments for case details
        vm.startPrank(address(account1));
        allowlistModule.onInstall(abi.encode(HOOK_ENTITY_ID, _getInputsForTests()));

        allowlistModule.preRuntimeValidationHook(
            HOOK_ENTITY_ID,
            address(0),
            0,
            abi.encodeCall(ModularAccountBase.execute, (address(counters[1]), 1 wei, "")),
            ""
        );
    }

    function test_checkAllowlistCalldata_execute() public {
        // install inputs, see comments for case details
        vm.startPrank(address(account1));
        allowlistModule.onInstall(abi.encode(HOOK_ENTITY_ID, _getInputsForTests()));

        // verify case 1 - a selector (Counter.setNumber) + address (counters[0]) should match
        bytes memory data1 = abi.encodeCall(
            ModularAccountBase.execute, (address(counters[0]), 0, abi.encodeCall(Counter.setNumber, (10)))
        );
        allowlistModule.preRuntimeValidationHook(HOOK_ENTITY_ID, address(0), 0, data1, "");
        vm.expectRevert(abi.encodeWithSelector(AllowlistModule.AddressNotAllowed.selector));
        // wrong address
        allowlistModule.preRuntimeValidationHook(
            HOOK_ENTITY_ID,
            address(0),
            0,
            abi.encodeCall(
                ModularAccountBase.execute, (address(counters[5]), 0, abi.encodeCall(Counter.setNumber, (10)))
            ),
            ""
        );
        vm.expectRevert(abi.encodeWithSelector(AllowlistModule.SelectorNotAllowed.selector));
        // wrong selector
        allowlistModule.preRuntimeValidationHook(
            HOOK_ENTITY_ID,
            address(0),
            0,
            abi.encodeCall(
                ModularAccountBase.execute, (address(counters[0]), 0, abi.encodeCall(Counter.decrement, ()))
            ),
            ""
        );

        // verify case 2 - wildcard selector (Counter.increment), any address works
        bytes memory data2 = abi.encodeCall(
            ModularAccountBase.execute, (address(allowlistModule), 0, abi.encodeCall(Counter.increment, ()))
        );
        allowlistModule.preRuntimeValidationHook(HOOK_ENTITY_ID, address(0), 0, data2, "");

        // verify case 3 - wildcard address (counters[1]), any selector works
        bytes memory data3 = abi.encodeCall(
            ModularAccountBase.execute,
            (
                address(counters[1]),
                0,
                abi.encodeCall(AllowlistModule.setSelectorAllowlist, (0, address(1), "", false))
            )
        );
        allowlistModule.preRuntimeValidationHook(HOOK_ENTITY_ID, address(0), 0, data3, "");

        vm.stopPrank();
    }

    function testFuzz_allowlistHook_userOp_single(uint256 seed) public {
        AllowlistModule.AllowlistInput[] memory inputs;
        (inputs, seed) = _generateRandomizedAllowlistInput(seed);

        _copyInputsToStorage(inputs);
        _customValidationSetup();

        Call[] memory calls = new Call[](1);
        (calls[0], seed) = _generateRandomCall(seed);
        bytes memory expectedError = _getExpectedUserOpError(calls);

        _runExecUserOp(calls[0].target, calls[0].data, expectedError);
    }

    function testFuzz_allowlistHook_userOp_batch(uint256 seed) public {
        AllowlistModule.AllowlistInput[] memory inputs;
        (inputs, seed) = _generateRandomizedAllowlistInput(seed);

        _copyInputsToStorage(inputs);
        _customValidationSetup();

        Call[] memory calls;
        (calls, seed) = _generateRandomCalls(seed);
        bytes memory expectedError = _getExpectedUserOpError(calls);

        _runExecBatchUserOp(calls, expectedError);
    }

    function testFuzz_allowlistHook_runtime_single(uint256 seed) public {
        AllowlistModule.AllowlistInput[] memory inputs;
        (inputs, seed) = _generateRandomizedAllowlistInput(seed);

        _copyInputsToStorage(inputs);
        _customValidationSetup();

        Call[] memory calls = new Call[](1);
        (calls[0], seed) = _generateRandomCall(seed);
        bytes memory expectedError = _getExpectedRuntimeError(calls);

        if (keccak256(expectedError) == keccak256("emptyrevert")) {
            _runtimeExecExpFail(calls[0].target, calls[0].data, "");
        } else {
            _runtimeExec(calls[0].target, calls[0].data, expectedError);
        }
    }

    function testFuzz_allowlistHook_runtime_batch(uint256 seed) public {
        AllowlistModule.AllowlistInput[] memory inputs;
        (inputs, seed) = _generateRandomizedAllowlistInput(seed);

        _copyInputsToStorage(inputs);
        _customValidationSetup();

        Call[] memory calls;
        (calls, seed) = _generateRandomCalls(seed);
        bytes memory expectedError = _getExpectedRuntimeError(calls);

        if (keccak256(expectedError) == keccak256("emptyrevert")) {
            _runtimeExecBatchExpFail(calls, "");
        } else {
            _runtimeExecBatch(calls, expectedError);
        }
    }

    function test_revertsOnUnnecessaryValidationData() public {
        allowlistInputs.push(
            AllowlistModule.AllowlistInput({
                target: address(counters[0]),
                hasSelectorAllowlist: false,
                hasERC20SpendLimit: false,
                erc20SpendLimit: 0,
                selectors: new bytes4[](0)
            })
        );

        _customValidationSetup();

        uint256 nonce = entryPoint.getNonce(address(account1), 0);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: nonce,
            initCode: hex"",
            callData: abi.encodeCall(
                account1.execute, (address(counters[0]), 0, abi.encodeCall(Counter.increment, ()))
            ),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));

        userOp.signature =
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // assert that the user op would succeed

        uint256 stateSnapshot = vm.snapshotState();

        vm.prank(beneficiary);
        entryPoint.handleOps(userOps, beneficiary);

        assertEq(counters[0].number(), 1);

        vm.revertToState(stateSnapshot);

        // Now, assert it fails with >0 validation data.

        // Pass the module validation hook data.
        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({index: uint8(0), validationData: "abcd"});

        userOp.signature = _encodeSignature(
            _signerValidation,
            GLOBAL_VALIDATION,
            preValidationHookData,
            abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v)
        );

        userOps[0] = userOp;

        vm.prank(beneficiary);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(
                    ExecutionLib.PreUserOpValidationHookReverted.selector,
                    ModuleEntityLib.pack(address(allowlistModule), HOOK_ENTITY_ID),
                    abi.encodeWithSelector(ModuleBase.UnexpectedDataPassed.selector)
                )
            )
        );
        entryPoint.handleOps(userOps, beneficiary);
    }

    function _beforeInstallStep(address accountImpl) internal override {
        // Expect events to be emitted from onInstall
        for (uint256 i = 0; i < allowlistInputs.length; i++) {
            vm.expectEmit(address(allowlistModule));
            emit AddressAllowlistUpdated(
                HOOK_ENTITY_ID,
                accountImpl,
                allowlistInputs[i].target,
                AllowlistModule.AddressAllowlistEntry({
                    allowed: true,
                    hasSelectorAllowlist: allowlistInputs[i].hasSelectorAllowlist,
                    hasERC20SpendLimit: false
                })
            );

            if (!allowlistInputs[i].hasSelectorAllowlist) {
                continue;
            }

            for (uint256 j = 0; j < allowlistInputs[i].selectors.length; j++) {
                bytes24 targetAndSelector = bytes24(
                    bytes24(bytes20(allowlistInputs[i].target)) | (bytes24(allowlistInputs[i].selectors[j]) >> 160)
                );
                vm.expectEmit(address(allowlistModule));
                emit SelectorAllowlistUpdated(HOOK_ENTITY_ID, accountImpl, targetAndSelector, true);
            }
        }
    }

    function _generateRandomCalls(uint256 seed) internal view returns (Call[] memory, uint256) {
        uint256 length = seed % 10;
        seed = _next(seed);

        Call[] memory calls = new Call[](length);

        for (uint256 i = 0; i < length; i++) {
            (calls[i], seed) = _generateRandomCall(seed);
        }

        return (calls, seed);
    }

    function _generateRandomCall(uint256 seed) internal view returns (Call memory call, uint256 newSeed) {
        // Half of the time, the target is a random counter, the other half, it's a random address.
        bool isCounter = seed % 2 == 0;
        seed = _next(seed);

        call.target = isCounter ? address(counters[seed % counters.length]) : address(uint160(uint256(seed)));
        seed = _next(seed);

        bool validSelector = seed % 2 == 0;
        seed = _next(seed);

        if (validSelector) {
            uint256 selectorIndex = seed % 3;
            seed = _next(seed);

            if (selectorIndex == 0) {
                call.data = abi.encodeCall(Counter.setNumber, (seed % 100));
            } else if (selectorIndex == 1) {
                call.data = abi.encodeCall(Counter.increment, ());
            } else {
                call.data = abi.encodeWithSignature("number()");
            }

            seed = _next(seed);
        } else {
            call.data = abi.encodePacked(bytes4(uint32(uint256(seed))));
            seed = _next(seed);
        }

        return (call, seed);
    }

    function _getExpectedUserOpError(Call[] memory calls) internal view returns (bytes memory) {
        for (uint256 i = 0; i < calls.length; i++) {
            Call memory call = calls[i];

            (bool allowed, bool hasSelectorAllowlist,) =
                allowlistModule.addressAllowlist(HOOK_ENTITY_ID, call.target, address(account1));
            if (allowed) {
                if (
                    hasSelectorAllowlist
                        && !allowlistModule.selectorAllowlist(
                            HOOK_ENTITY_ID, bytes4(call.data), call.target, address(account1)
                        )
                ) {
                    return abi.encodeWithSelector(
                        IEntryPoint.FailedOpWithRevert.selector,
                        0,
                        "AA23 reverted",
                        abi.encodeWithSelector(
                            ExecutionLib.PreUserOpValidationHookReverted.selector,
                            ModuleEntityLib.pack(address(allowlistModule), HOOK_ENTITY_ID),
                            abi.encodeWithSelector(AllowlistModule.SelectorNotAllowed.selector)
                        )
                    );
                }
            } else {
                return abi.encodeWithSelector(
                    IEntryPoint.FailedOpWithRevert.selector,
                    0,
                    "AA23 reverted",
                    abi.encodeWithSelector(
                        ExecutionLib.PreUserOpValidationHookReverted.selector,
                        ModuleEntityLib.pack(address(allowlistModule), HOOK_ENTITY_ID),
                        abi.encodeWithSelector(AllowlistModule.AddressNotAllowed.selector)
                    )
                );
            }
        }

        return "";
    }

    function _getExpectedRuntimeError(Call[] memory calls) internal view returns (bytes memory) {
        for (uint256 i = 0; i < calls.length; i++) {
            Call memory call = calls[i];

            (bool allowed, bool hasSelectorAllowlist,) =
                allowlistModule.addressAllowlist(HOOK_ENTITY_ID, call.target, address(account1));
            if (allowed) {
                if (
                    hasSelectorAllowlist
                        && !allowlistModule.selectorAllowlist(
                            HOOK_ENTITY_ID, bytes4(call.data), call.target, address(account1)
                        )
                ) {
                    return abi.encodeWithSelector(
                        ExecutionLib.PreRuntimeValidationHookReverted.selector,
                        ModuleEntityLib.pack(address(allowlistModule), HOOK_ENTITY_ID),
                        abi.encodeWithSelector(AllowlistModule.SelectorNotAllowed.selector)
                    );
                }
            } else {
                return abi.encodeWithSelector(
                    ExecutionLib.PreRuntimeValidationHookReverted.selector,
                    ModuleEntityLib.pack(address(allowlistModule), HOOK_ENTITY_ID),
                    abi.encodeWithSelector(AllowlistModule.AddressNotAllowed.selector)
                );
            }
        }

        // At this point, we have returned any error that would come from the AllowlistModule.
        // But, because this is in the runtime path, the Counter itself may throw if it is not a valid selector.

        for (uint256 i = 0; i < calls.length; i++) {
            Call memory call = calls[i];
            bytes4 selector = bytes4(call.data);

            if (
                selector != Counter.setNumber.selector && selector != Counter.increment.selector
                    && selector != bytes4(abi.encodeWithSignature("number()"))
            ) {
                //todo: better define a way to handle empty reverts.
                return "emptyrevert";
            }
        }

        return "";
    }

    function _generateRandomizedAllowlistInput(uint256 seed)
        internal
        view
        returns (AllowlistModule.AllowlistInput[] memory, uint256)
    {
        uint256 length = seed % 10;
        seed = _next(seed);

        AllowlistModule.AllowlistInput[] memory inputs = new AllowlistModule.AllowlistInput[](length);

        for (uint256 i = 0; i < length; i++) {
            // Half the time, the target is a random counter, the other half, it's a random address.
            bool isCounter = seed % 2 == 0;
            seed = _next(seed);

            address target =
                isCounter ? address(counters[seed % counters.length]) : address(uint160(uint256(seed)));

            bool hasSelectorAllowlist = seed % 2 == 0;
            seed = _next(seed);

            uint256 selectorLength = seed % 10;
            seed = _next(seed);

            bytes4[] memory selectors = new bytes4[](selectorLength);

            for (uint256 j = 0; j < selectorLength; j++) {
                // half of the time, the selector is a valid selector on counter, the other half it's a random
                // selector

                bool isCounterSelector = seed % 2 == 0;
                seed = _next(seed);

                if (isCounterSelector) {
                    uint256 selectorIndex = seed % 3;
                    seed = _next(seed);

                    if (selectorIndex == 0) {
                        selectors[j] = Counter.setNumber.selector;
                    } else if (selectorIndex == 1) {
                        selectors[j] = Counter.increment.selector;
                    } else {
                        selectors[j] = bytes4(abi.encodeWithSignature("number()"));
                    }
                } else {
                    selectors[j] = bytes4(uint32(uint256(seed)));
                    seed = _next(seed);
                }

                selectors[j] = bytes4(uint32(uint256(keccak256(abi.encodePacked(seed, j)))));
                seed = _next(seed);
            }

            inputs[i] = AllowlistModule.AllowlistInput(target, hasSelectorAllowlist, false, 0, selectors);
        }

        return (inputs, seed);
    }

    function _next(uint256 seed) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(seed)));
    }

    function _initialValidationConfig()
        internal
        virtual
        override
        returns (ModuleEntity, bool, bool, bool, bytes4[] memory, bytes memory, bytes[] memory)
    {
        bytes[] memory hooks = new bytes[](1);
        hooks[0] = abi.encodePacked(
            HookConfigLib.packValidationHook(address(allowlistModule), HOOK_ENTITY_ID),
            abi.encode(HOOK_ENTITY_ID, allowlistInputs)
        );
        // patched to also work during SMA tests by differentiating the validation
        _signerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), type(uint32).max - 1);
        return
            (_signerValidation, true, true, true, new bytes4[](0), abi.encode(type(uint32).max - 1, owner1), hooks);
    }

    // Unfortunately, this is a feature that solidity has only implemented in via-ir, so we need to do it manually
    // to be able to run the tests in lite mode.
    function _copyInputsToStorage(AllowlistModule.AllowlistInput[] memory inputs) internal {
        for (uint256 i = 0; i < inputs.length; i++) {
            allowlistInputs.push(inputs[i]);
        }
    }

    /// Return three inputs:
    ///   - case 1 - a selector (Counter.setNumber) + address (counters[0]) should match
    ///   - case 2 - wildcard selector (Counter.increment), any address works
    ///   - case 3 - wildcard address (counters[1]), any selector works
    function _getInputsForTests() internal view returns (AllowlistModule.AllowlistInput[] memory) {
        AllowlistModule.AllowlistInput[] memory inputs = new AllowlistModule.AllowlistInput[](3);
        // case 1 - a selector (Counter.setNumber) + address (counters[0]) should match
        bytes4[] memory selectors1 = new bytes4[](1);
        selectors1[0] = Counter.setNumber.selector;
        inputs[0] = AllowlistModule.AllowlistInput({
            target: address(counters[0]),
            hasSelectorAllowlist: true,
            hasERC20SpendLimit: false,
            erc20SpendLimit: 0,
            selectors: selectors1
        });
        // case 2 - wildcard selector (Counter.increment), any address works
        bytes4[] memory selectors2 = new bytes4[](1);
        selectors2[0] = Counter.increment.selector;
        inputs[1] = AllowlistModule.AllowlistInput({
            target: address(0),
            hasSelectorAllowlist: true,
            hasERC20SpendLimit: false,
            erc20SpendLimit: 0,
            selectors: selectors2
        });
        // case 3 - wildcard address (counters[1]), any selector works
        inputs[2] = AllowlistModule.AllowlistInput({
            target: address(counters[1]),
            hasSelectorAllowlist: false,
            hasERC20SpendLimit: false,
            erc20SpendLimit: 0,
            selectors: new bytes4[](0)
        });
        return inputs;
    }
}
