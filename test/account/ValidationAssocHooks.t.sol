// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";

import {ModuleManagerInternals} from "../../src/account/ModuleManagerInternals.sol";

import {MockModule} from "../mocks/modules/MockModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract ValidationAssocHooksTest is AccountTestBase {
    MockModule[] public hooks;

    function setUp() public override {
        _allowTestDirectCalls();

        ExecutionManifest memory m; // empty manifest

        for (uint256 i = 0; i < 257; i++) {
            hooks.push(new MockModule(m));
        }
    }

    function test_validationAssocHooks_maxValidationHooks() public {
        // Attempt to install 257 validation hooks, expect a revert.

        bytes[] memory hookInstalls = new bytes[](257);

        for (uint256 i = 0; i < 257; i++) {
            hookInstalls[i] = abi.encodePacked(
                HookConfigLib.packValidationHook({_module: address(hooks[i]), _entityId: uint32(i)})
            );
        }

        vm.expectRevert(abi.encodeWithSelector(ModuleManagerInternals.ValidationAssocHookLimitExceeded.selector));
        account1.installValidation(
            ValidationConfigLib.pack({
                _validationFunction: _signerValidation,
                _isGlobal: true,
                _isSignatureValidation: true,
                _isUserOpValidation: true
            }),
            new bytes4[](0),
            "",
            hookInstalls
        );
    }

    function test_validationAssocHooks_maxExecHooks() public {
        // Attempt to install 257 exec hooks, expect a revert.

        bytes[] memory hookInstalls = new bytes[](257);

        for (uint256 i = 0; i < 257; i++) {
            hookInstalls[i] = abi.encodePacked(
                HookConfigLib.packExecHook({
                    _module: address(hooks[i]),
                    _entityId: uint32(i),
                    _hasPre: false,
                    _hasPost: false
                })
            );
        }

        vm.expectRevert(abi.encodeWithSelector(ModuleManagerInternals.ValidationAssocHookLimitExceeded.selector));
        account1.installValidation(
            ValidationConfigLib.pack({
                _validationFunction: _signerValidation,
                _isGlobal: true,
                _isSignatureValidation: true,
                _isUserOpValidation: true
            }),
            new bytes4[](0),
            "",
            hookInstalls
        );
    }
}
