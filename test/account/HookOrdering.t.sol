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

import {DIRECT_CALL_VALIDATION_ENTITYID} from "@erc6900/reference-implementation/helpers/Constants.sol";
import {
    ExecutionManifest,
    ManifestExecutionHook
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {ModuleEntity, ValidationConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {HookOrderCheckerModule} from "../mocks/modules/HookOrderCheckerModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

// Asserts that all hooks and account functions are executed in the correct order:
// All pre-validation hooks (in forward order)
// The validation function
// All pre-exec hooks associated w/ validation (in forward order)
// All pre-exec hooks associated w/ selector (in forward order)
// The exec function
// All post-exec hooks associated w/ selector (in reverse order)
// All post-exec hooks associated w/ validation (in reverse order)
//
// To do this, it installs a special module called HookOrderCheckerModule that is a module of every type, and each
// implementation reports it's order (from it's entityId) to a storage list. At the end of each execution flow, the
// list is asserted to be of the right length and contain the elements in the correct order.
//
// This test does not assert hook ordering after the removal of any hooks, or the addition of hooks after the first
// install. That case will need an invariant test + harness to handle the addition and removal of hooks.
contract HookOrderingTest is AccountTestBase {
    HookOrderCheckerModule public hookOrderChecker;

    ModuleEntity public orderCheckerValidationEntity;

    function setUp() public override {
        _revertSnapshot = vm.snapshotState();
        hookOrderChecker = new HookOrderCheckerModule();
    }

    // Test cases:
    // User op: module exec function
    // User op: module exec function, without validation-associated exec hooks, no executeUserOp
    // User op: module exec function, without validation-associated exec hooks, yes executeUserOp
    // Runtime: module exec function
    // Runtime: module exec function, without validation-associated exec hooks
    // Direct call: module exec function
    // Direct call: module exec function, without validation-associated exec hooks
    // User op: account native function
    // User op: account native function, without validation-associated exec hooks, no executeUserOp
    // User op: account native function, without validation-associated exec hooks, yes executeUserOp
    // Runtime: account native function
    // Runtime: account native function, without validation-associated exec hooks
    // Direct call: account native function
    // Direct call: account native function, without validation-associated exec hooks
    // Signature validation

    // Hook and function setup for all cases except signature validation:
    //  1. pre validation hook 1
    //  2. pre validation hook 2
    //  3. pre validation hook 3
    //  4. validation
    //  5. pre exec (validation-assoc) hook 1: pre only
    //  6. pre exec (validation-assoc) hook 2: post only (skipped)
    //  7. pre exec (validation-assoc) hook 3: pre and post
    //  8. pre exec (validation-assoc) hook 4: pre and post
    //  9. pre exec (validation-assoc) hook 5: pre only
    // 10. pre exec (validation-assoc) hook 6: post only (skipped)
    // 11. pre exec (selector-assoc) hook 1: pre only
    // 12. pre exec (selector-assoc) hook 2: post only (skipped)
    // 13. pre exec (selector-assoc) hook 3: pre and post
    // 14. pre exec (selector-assoc) hook 4: pre and post
    // 15. pre exec (selector-assoc) hook 5: pre only
    // 16. pre exec (selector-assoc) hook 6: post only (skipped)
    // 17. exec
    // 16. post exec (selector-assoc) hook 6: post only
    // 15. post exec (selector-assoc) hook 5: pre only (skipped)
    // 14. post exec (selector-assoc) hook 4: pre and post
    // 13. post exec (selector-assoc) hook 3: pre and post
    // 12. post exec (selector-assoc) hook 2: post only)
    // 11. post exec (selector-assoc) hook 1: pre only (skipped)
    // 10. post exec (validation-assoc) hook 6: post only
    //  9. post exec (validation-assoc) hook 5: pre only (skipped)
    //  8. post exec (validation-assoc) hook 4: pre and post
    //  7. post exec (validation-assoc) hook 3: pre and post
    //  6. post exec (validation-assoc) hook 2: post only
    //  5. post exec (validation-assoc) hook 1: pre only (skipped)

    function test_hookOrder_userOp_moduleExecFunction_withAssoc() public withSMATest {
        _installOrderCheckerModuleWithValidationAssocExec(4);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: _encodeNonce(orderCheckerValidationEntity, SELECTOR_ASSOCIATED_V, 0),
            initCode: hex"",
            callData: abi.encodePacked(
                account1.executeUserOp.selector, abi.encodeCall(HookOrderCheckerModule.foo, (17))
            ),
            accountGasLimits: _encodeGas(1_000_000, 1_000_000),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: _encodeSignature(hex"")
        });

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        _checkInvokeOrderWithValidationAssocExec();
    }

    function test_hookOrder_userOp_moduleExecFunction_noAssoc_regular() public withSMATest {
        _installOrderCheckerModuleNoValidationAssocExec(4);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: _encodeNonce(orderCheckerValidationEntity, SELECTOR_ASSOCIATED_V, 0),
            initCode: hex"",
            callData: abi.encodeCall(HookOrderCheckerModule.foo, (17)),
            accountGasLimits: _encodeGas(1_000_000, 1_000_000),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: _encodeSignature(hex"")
        });

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        _checkInvokeOrderNoValidationAssocExec();
    }

    function test_hookOrder_userOp_moduleExecFunction_noAssoc_execUO() public withSMATest {
        _installOrderCheckerModuleNoValidationAssocExec(4);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: _encodeNonce(orderCheckerValidationEntity, SELECTOR_ASSOCIATED_V, 0),
            initCode: hex"",
            callData: abi.encodePacked(
                account1.executeUserOp.selector, abi.encodeCall(HookOrderCheckerModule.foo, (17))
            ),
            accountGasLimits: _encodeGas(1_000_000, 1_000_000),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: _encodeSignature(hex"")
        });

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        _checkInvokeOrderNoValidationAssocExec();
    }

    function test_hookOrder_runtime_moduleExecFunction() public withSMATest {
        _installOrderCheckerModuleWithValidationAssocExec(4);

        account1.executeWithRuntimeValidation(
            abi.encodeCall(HookOrderCheckerModule.foo, (17)),
            _encodeSignature(orderCheckerValidationEntity, SELECTOR_ASSOCIATED_VALIDATION, "")
        );

        _checkInvokeOrderWithValidationAssocExec();
    }

    function test_hookOrder_runtime_moduleExecFunction_noAssoc() public withSMATest {
        _installOrderCheckerModuleNoValidationAssocExec(4);

        account1.executeWithRuntimeValidation(
            abi.encodeCall(HookOrderCheckerModule.foo, (17)),
            _encodeSignature(orderCheckerValidationEntity, SELECTOR_ASSOCIATED_VALIDATION, "")
        );

        _checkInvokeOrderNoValidationAssocExec();
    }

    function test_hookOrder_directCall_moduleExecFunction() public withSMATest {
        _installOrderCheckerModuleWithValidationAssocExec(DIRECT_CALL_VALIDATION_ENTITYID);

        vm.prank(address(hookOrderChecker));
        HookOrderCheckerModule(address(account1)).foo(17);

        _checkInvokeOrderDirectCallWithValidationAssocExec();
    }

    function test_hookOrder_directCall_moduleExecFunction_noAssoc() public withSMATest {
        _installOrderCheckerModuleNoValidationAssocExec(DIRECT_CALL_VALIDATION_ENTITYID);

        vm.prank(address(hookOrderChecker));
        HookOrderCheckerModule(address(account1)).foo(17);

        _checkInvokeOrderDirectCallNoValidationAssocExec();
    }

    function test_hookOrder_userOp_accountNativeFunction_withAssoc() public withSMATest {
        _installOrderCheckerModuleWithValidationAssocExec(4);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: _encodeNonce(orderCheckerValidationEntity, SELECTOR_ASSOCIATED_V, 0),
            initCode: hex"",
            callData: abi.encodePacked(
                account1.executeUserOp.selector,
                abi.encodeCall(
                    account1.execute,
                    (address(hookOrderChecker), 0 wei, abi.encodeCall(HookOrderCheckerModule.foo, (17)))
                )
            ),
            accountGasLimits: _encodeGas(1_000_000, 1_000_000),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: _encodeSignature(hex"")
        });

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        _checkInvokeOrderWithValidationAssocExec();
    }

    function test_hookOrder_userOp_accountNativeFunction_noAssoc_regular() public withSMATest {
        _installOrderCheckerModuleNoValidationAssocExec(4);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: _encodeNonce(orderCheckerValidationEntity, SELECTOR_ASSOCIATED_V, 0),
            initCode: hex"",
            callData: abi.encodeCall(
                account1.execute, (address(hookOrderChecker), 0 wei, abi.encodeCall(HookOrderCheckerModule.foo, (17)))
            ),
            accountGasLimits: _encodeGas(1_000_000, 1_000_000),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: _encodeSignature(hex"")
        });

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        _checkInvokeOrderNoValidationAssocExec();
    }

    function test_hookOrder_userOp_accountNativeFunction_noAssoc_execUO() public withSMATest {
        _installOrderCheckerModuleNoValidationAssocExec(4);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: _encodeNonce(orderCheckerValidationEntity, SELECTOR_ASSOCIATED_V, 0),
            initCode: hex"",
            callData: abi.encodePacked(
                account1.executeUserOp.selector,
                abi.encodeCall(
                    account1.execute,
                    (address(hookOrderChecker), 0 wei, abi.encodeCall(HookOrderCheckerModule.foo, (17)))
                )
            ),
            accountGasLimits: _encodeGas(1_000_000, 1_000_000),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: _encodeSignature(hex"")
        });

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        _checkInvokeOrderNoValidationAssocExec();
    }

    function test_hookOrder_runtime_accountNativeFunction_regular() public withSMATest {
        _installOrderCheckerModuleWithValidationAssocExec(4);

        account1.executeWithRuntimeValidation(
            abi.encodeCall(
                account1.execute,
                (address(hookOrderChecker), 0 wei, abi.encodeCall(HookOrderCheckerModule.foo, (17)))
            ),
            _encodeSignature(orderCheckerValidationEntity, SELECTOR_ASSOCIATED_VALIDATION, "")
        );

        _checkInvokeOrderWithValidationAssocExec();
    }

    function test_hookOrder_runtime_accountNativeFunction_noAssoc() public withSMATest {
        _installOrderCheckerModuleNoValidationAssocExec(4);

        account1.executeWithRuntimeValidation(
            abi.encodeCall(
                account1.execute,
                (address(hookOrderChecker), 0 wei, abi.encodeCall(HookOrderCheckerModule.foo, (17)))
            ),
            _encodeSignature(orderCheckerValidationEntity, SELECTOR_ASSOCIATED_VALIDATION, "")
        );

        _checkInvokeOrderNoValidationAssocExec();
    }

    function test_hookOrder_directCall_accountNativeFunction_withAssoc() public withSMATest {
        _installOrderCheckerModuleWithValidationAssocExec(DIRECT_CALL_VALIDATION_ENTITYID);

        vm.prank(address(hookOrderChecker));
        HookOrderCheckerModule(address(account1)).foo(17);

        _checkInvokeOrderDirectCallWithValidationAssocExec();
    }

    function test_hookOrder_directCall_accountNativeFunction_noAssoc() public withSMATest {
        _installOrderCheckerModuleNoValidationAssocExec(DIRECT_CALL_VALIDATION_ENTITYID);

        vm.prank(address(hookOrderChecker));
        HookOrderCheckerModule(address(account1)).foo(17);

        _checkInvokeOrderDirectCallNoValidationAssocExec();
    }

    function test_hookOrder_signatureValidation() public withSMATest {
        _installOrderCheckerModuleWithValidationAssocExec(4);

        // Technically, the hooks aren't supposed to make state changes during the signature validation flow
        // because it will be invoked with `staticcall`, so we call `isValidSignature` directly with `call`.

        bytes memory callData = abi.encodeCall(
            account1.isValidSignature, (bytes32(0), _encode1271Signature(orderCheckerValidationEntity, hex""))
        );

        (bool success,) = address(account1).call(callData);

        require(success, "HookOrderingTest: signature validation failed");

        _checkInvokeOrderSignatureValidation();
    }

    function _installOrderCheckerModuleWithValidationAssocExec(uint32 validationEntityId) internal {
        // Must be done in two steps:
        // - validation and validation-associated functions
        // - execution function and selector-associated functions

        (ValidationConfig validationConfig, bytes4[] memory selectors, bytes[] memory startingHooks) =
            _getValidationInstallDataNoExecHooks(validationEntityId);

        bytes[] memory hooks = new bytes[](9);

        // Pre-validation hooks
        hooks[0] = startingHooks[0];
        hooks[1] = startingHooks[1];
        hooks[2] = startingHooks[2];

        // Validation-associated exec hooks
        hooks[3] = abi.encodePacked(
            HookConfigLib.packExecHook({
                _module: address(hookOrderChecker),
                _entityId: 5,
                _hasPre: true,
                _hasPost: false
            })
        );
        hooks[4] = abi.encodePacked(
            HookConfigLib.packExecHook({
                _module: address(hookOrderChecker),
                _entityId: 6,
                _hasPre: false,
                _hasPost: true
            })
        );
        hooks[5] = abi.encodePacked(
            HookConfigLib.packExecHook({
                _module: address(hookOrderChecker),
                _entityId: 7,
                _hasPre: true,
                _hasPost: true
            })
        );
        hooks[6] = abi.encodePacked(
            HookConfigLib.packExecHook({
                _module: address(hookOrderChecker),
                _entityId: 8,
                _hasPre: true,
                _hasPost: true
            })
        );
        hooks[7] = abi.encodePacked(
            HookConfigLib.packExecHook({
                _module: address(hookOrderChecker),
                _entityId: 9,
                _hasPre: true,
                _hasPost: false
            })
        );
        hooks[8] = abi.encodePacked(
            HookConfigLib.packExecHook({
                _module: address(hookOrderChecker),
                _entityId: 10,
                _hasPre: false,
                _hasPost: true
            })
        );

        vm.prank(address(entryPoint));
        account1.installValidation(validationConfig, selectors, "", hooks);

        _installExecFunctionWithHooks();
    }

    function _installOrderCheckerModuleNoValidationAssocExec(uint32 validationEntityId) internal {
        (ValidationConfig validationConfig, bytes4[] memory selectors, bytes[] memory hooks) =
            _getValidationInstallDataNoExecHooks(validationEntityId);

        vm.prank(address(entryPoint));
        account1.installValidation(validationConfig, selectors, "", hooks);

        _installExecFunctionWithHooks();
    }

    function _installExecFunctionWithHooks() internal {
        // Install the execution function and selector-associated hooks

        // The executionManifest only contains the execution function, we need to insert the selector-associated
        // hooks
        ExecutionManifest memory manifest = hookOrderChecker.executionManifest();

        ManifestExecutionHook[] memory execHooks = new ManifestExecutionHook[](12);

        // Apply hooks to the `foo` function
        execHooks[0] = ManifestExecutionHook({
            executionSelector: HookOrderCheckerModule.foo.selector,
            entityId: 11,
            isPreHook: true,
            isPostHook: false
        });
        execHooks[1] = ManifestExecutionHook({
            executionSelector: HookOrderCheckerModule.foo.selector,
            entityId: 12,
            isPreHook: false,
            isPostHook: true
        });
        execHooks[2] = ManifestExecutionHook({
            executionSelector: HookOrderCheckerModule.foo.selector,
            entityId: 13,
            isPreHook: true,
            isPostHook: true
        });
        execHooks[3] = ManifestExecutionHook({
            executionSelector: HookOrderCheckerModule.foo.selector,
            entityId: 14,
            isPreHook: true,
            isPostHook: true
        });
        execHooks[4] = ManifestExecutionHook({
            executionSelector: HookOrderCheckerModule.foo.selector,
            entityId: 15,
            isPreHook: true,
            isPostHook: false
        });
        execHooks[5] = ManifestExecutionHook({
            executionSelector: HookOrderCheckerModule.foo.selector,
            entityId: 16,
            isPreHook: false,
            isPostHook: true
        });

        // Apply hooks to the `execute` function
        execHooks[6] = ManifestExecutionHook({
            executionSelector: account1.execute.selector,
            entityId: 11,
            isPreHook: true,
            isPostHook: false
        });
        execHooks[7] = ManifestExecutionHook({
            executionSelector: account1.execute.selector,
            entityId: 12,
            isPreHook: false,
            isPostHook: true
        });
        execHooks[8] = ManifestExecutionHook({
            executionSelector: account1.execute.selector,
            entityId: 13,
            isPreHook: true,
            isPostHook: true
        });
        execHooks[9] = ManifestExecutionHook({
            executionSelector: account1.execute.selector,
            entityId: 14,
            isPreHook: true,
            isPostHook: true
        });
        execHooks[10] = ManifestExecutionHook({
            executionSelector: account1.execute.selector,
            entityId: 15,
            isPreHook: true,
            isPostHook: false
        });
        execHooks[11] = ManifestExecutionHook({
            executionSelector: account1.execute.selector,
            entityId: 16,
            isPreHook: false,
            isPostHook: true
        });

        manifest.executionHooks = execHooks;

        vm.prank(address(entryPoint));
        account1.installExecution(address(hookOrderChecker), manifest, "");
    }

    function _getValidationInstallDataNoExecHooks(uint32 validationEntityId)
        internal
        returns (ValidationConfig, bytes4[] memory, bytes[] memory)
    {
        ValidationConfig validationConfig = ValidationConfigLib.pack({
            _module: address(hookOrderChecker),
            _entityId: validationEntityId,
            _isGlobal: false,
            _isSignatureValidation: true,
            _isUserOpValidation: true
        });

        orderCheckerValidationEntity = ModuleEntityLib.pack(address(hookOrderChecker), validationEntityId);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = HookOrderCheckerModule.foo.selector;
        selectors[1] = account1.execute.selector;

        bytes[] memory hooks = new bytes[](3);

        // Pre-validation hooks
        hooks[0] =
            abi.encodePacked(HookConfigLib.packValidationHook({_module: address(hookOrderChecker), _entityId: 1}));
        hooks[1] =
            abi.encodePacked(HookConfigLib.packValidationHook({_module: address(hookOrderChecker), _entityId: 2}));
        hooks[2] =
            abi.encodePacked(HookConfigLib.packValidationHook({_module: address(hookOrderChecker), _entityId: 3}));

        return (validationConfig, selectors, hooks);
    }

    function _checkInvokeOrderWithValidationAssocExec() internal view {
        uint32[] memory expectedOrder = new uint32[](21);
        uint32[21] memory expectedOrderValues =
            [uint32(1), 2, 3, 4, 5, 7, 8, 9, 11, 13, 14, 15, 17, 16, 14, 13, 12, 10, 8, 7, 6];

        for (uint256 i = 0; i < expectedOrder.length; i++) {
            expectedOrder[i] = expectedOrderValues[i];
        }

        uint256[] memory actualOrder = hookOrderChecker.getRecordedFunctionCalls();

        _assertArrsEqual(expectedOrder, actualOrder);
    }

    function _checkInvokeOrderDirectCallWithValidationAssocExec() internal view {
        uint32[] memory expectedOrder = new uint32[](20);
        uint32[20] memory expectedOrderValues =
            [uint32(1), 2, 3, 5, 7, 8, 9, 11, 13, 14, 15, 17, 16, 14, 13, 12, 10, 8, 7, 6];

        for (uint256 i = 0; i < expectedOrder.length; i++) {
            expectedOrder[i] = expectedOrderValues[i];
        }

        uint256[] memory actualOrder = hookOrderChecker.getRecordedFunctionCalls();

        _assertArrsEqual(expectedOrder, actualOrder);
    }

    function _checkInvokeOrderNoValidationAssocExec() internal view {
        uint32[] memory expectedOrder = new uint32[](13);
        uint32[13] memory expectedOrderValues = [uint32(1), 2, 3, 4, 11, 13, 14, 15, 17, 16, 14, 13, 12];

        for (uint256 i = 0; i < expectedOrder.length; i++) {
            expectedOrder[i] = expectedOrderValues[i];
        }

        uint256[] memory actualOrder = hookOrderChecker.getRecordedFunctionCalls();

        _assertArrsEqual(expectedOrder, actualOrder);
    }

    function _checkInvokeOrderDirectCallNoValidationAssocExec() internal view {
        uint32[] memory expectedOrder = new uint32[](12);
        uint32[12] memory expectedOrderValues = [uint32(1), 2, 3, 11, 13, 14, 15, 17, 16, 14, 13, 12];

        for (uint256 i = 0; i < expectedOrder.length; i++) {
            expectedOrder[i] = expectedOrderValues[i];
        }

        uint256[] memory actualOrder = hookOrderChecker.getRecordedFunctionCalls();

        _assertArrsEqual(expectedOrder, actualOrder);
    }

    function _checkInvokeOrderSignatureValidation() internal view {
        uint32[] memory expectedOrder = new uint32[](4);
        uint32[4] memory expectedOrderValues = [uint32(1), 2, 3, 4];

        for (uint256 i = 0; i < expectedOrder.length; i++) {
            expectedOrder[i] = expectedOrderValues[i];
        }

        uint256[] memory actualOrder = hookOrderChecker.getRecordedFunctionCalls();

        _assertArrsEqual(expectedOrder, actualOrder);
    }

    function _assertArrsEqual(uint32[] memory expected, uint256[] memory actual) internal pure {
        assertEq(expected.length, actual.length);

        for (uint256 i = 0; i < expected.length; i++) {
            assertEq(expected[i], actual[i]);
        }
    }
}
