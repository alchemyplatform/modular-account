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
import {ModuleEntity, ValidationConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {SemiModularAccountBase} from "../../src/account/SemiModularAccountBase.sol";

import {MockSMADirectFallbackModule} from "../mocks/modules/MockSMADirectFallbackModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract SemiModularAccountDirectCallTest is AccountTestBase {
    address internal _target;
    MockSMADirectFallbackModule internal _module;
    ModuleEntity internal _directCallModuleEntity;
    ModuleEntity internal _fallbackDirectCallModuleEntity;

    function setUp() public override {
        _revertSnapshot = vm.snapshotState();
        _module = new MockSMADirectFallbackModule();
        _directCallModuleEntity = ModuleEntityLib.pack(address(_module), DIRECT_CALL_VALIDATION_ENTITYID);

        _fallbackDirectCallModuleEntity = ModuleEntityLib.pack(address(owner1), DIRECT_CALL_VALIDATION_ENTITYID);

        // enforces that this test runs with an SMA.
        account1 = ModularAccount(payable(factory.createSemiModularAccount(owner1, 0)));
        _target = makeAddr("4546b");
    }

    // Negatives

    function test_fail_smaDirectCall_disabledFallbackSigner() external {
        vm.prank(owner1);
        SemiModularAccountBase(payable(account1)).updateFallbackSignerData(address(0), true);

        bytes memory expectedRevertData = abi.encodeWithSelector(
            ModularAccountBase.ValidationFunctionMissing.selector, ModularAccountBase.execute.selector
        );

        vm.prank(owner1);
        vm.expectRevert(expectedRevertData);
        account1.execute(_target, 0, "");
    }

    function test_fail_smaDirectCall_notFallbackSigner() external {
        bytes memory expectedRevertData = abi.encodeWithSelector(
            ModularAccountBase.ValidationFunctionMissing.selector, ModularAccountBase.execute.selector
        );

        vm.prank(makeAddr("4546b"));
        vm.expectRevert(expectedRevertData);
        account1.execute(_target, 0, "");
    }

    // Positives

    function test_Flow_smaDirectCall_installedHooksUninstalled() external {
        // We install the validation as if it were a direct call validation, but we pass hooks from the
        // DirectCallModule, and while the validation remains the fallback signer + direct call entityId.
        bytes[] memory hooks = new bytes[](2);
        hooks[0] = abi.encodePacked(
            HookConfigLib.packExecHook({_hookFunction: _directCallModuleEntity, _hasPre: true, _hasPost: true}),
            hex"00" // onInstall data
        );
        hooks[1] = abi.encodePacked(
            HookConfigLib.packValidationHook({_hookFunction: _directCallModuleEntity}),
            hex"00" // onInstall data
        );

        ValidationConfig validationConfig =
            ValidationConfigLib.pack(_fallbackDirectCallModuleEntity, false, false, false);

        vm.prank(owner1);
        account1.installValidation(validationConfig, new bytes4[](0), "", hooks);

        // First, run with installed validation and validation-associated execution hooks.
        vm.prank(owner1);
        account1.execute(_target, 0, "");

        assertTrue(_module.preHookRan());
        assertTrue(_module.postHookRan());
        assertTrue(_module.validationHookRan());

        // We pass hook uninstall data to ensure onUninstall is called.
        bytes[] memory hookUninstallDatas = new bytes[](2);
        hookUninstallDatas[0] = new bytes(1);

        // If we pass a non-empty bytes parameter (second param), the tx reverts because we try to call an empty
        // contract, since the hooks are on a different entity, we have to include uninstall data there.
        vm.prank(owner1);
        account1.uninstallValidation(_fallbackDirectCallModuleEntity, new bytes(0), hookUninstallDatas);

        // Only the post exec hook should be true, as we used the validation we're uninstalling to uninstall.
        assertFalse(_module.preHookRan());
        assertTrue(_module.postHookRan());
        assertFalse(_module.validationHookRan());

        // Execute with the fallback validation again, since it should not be uninstall-able.
        vm.prank(owner1);
        account1.execute(_target, 0, "");

        // Ensure the hooks were properly uninstalled by checking to make sure they haven't run.
        assertFalse(_module.preHookRan());
        assertTrue(_module.postHookRan());
        assertFalse(_module.validationHookRan());
    }

    function test_smaDirectCall() external {
        vm.prank(owner1);
        account1.execute(_target, 0, "");
    }
}
