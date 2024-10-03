// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {HookConfig, IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {
    ExecutionDataView,
    ValidationDataView
} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";

import {HookConfigLib} from "../../src/libraries/HookConfigLib.sol";
import {ModuleEntity, ModuleEntityLib} from "../../src/libraries/ModuleEntityLib.sol";

import {ComprehensiveModule} from "../mocks/modules/ComprehensiveModule.sol";
import {CustomValidationTestBase} from "../utils/CustomValidationTestBase.sol";

contract ModularAccountViewTest is CustomValidationTestBase {
    ComprehensiveModule public comprehensiveModule;

    event ReceivedCall(bytes msgData, uint256 msgValue);

    ModuleEntity public comprehensiveModuleValidation;

    function setUp() public override {
        comprehensiveModule = new ComprehensiveModule();
        comprehensiveModuleValidation =
            ModuleEntityLib.pack(address(comprehensiveModule), uint32(ComprehensiveModule.EntityId.VALIDATION));

        _customValidationSetup();

        vm.startPrank(address(entryPoint));
        account1.installExecution(address(comprehensiveModule), comprehensiveModule.executionManifest(), "");
        vm.stopPrank();
    }

    function test_moduleView_getExecutionData_native() public withSMATest {
        bytes4[] memory selectorsToCheck = new bytes4[](5);

        selectorsToCheck[0] = IModularAccount.execute.selector;

        selectorsToCheck[1] = IModularAccount.executeBatch.selector;

        selectorsToCheck[2] = UUPSUpgradeable.upgradeToAndCall.selector;

        selectorsToCheck[3] = IModularAccount.installExecution.selector;

        selectorsToCheck[4] = IModularAccount.uninstallExecution.selector;

        for (uint256 i = 0; i < selectorsToCheck.length; i++) {
            ExecutionDataView memory data = account1.getExecutionData(selectorsToCheck[i]);
            assertEq(data.module, address(account1));
            assertTrue(data.allowGlobalValidation);
            assertFalse(data.skipRuntimeValidation);
        }
    }

    function test_moduleView_getExecutionData_module() public withSMATest {
        bytes4[] memory selectorsToCheck = new bytes4[](1);
        address[] memory expectedModuleAddress = new address[](1);

        selectorsToCheck[0] = comprehensiveModule.foo.selector;
        expectedModuleAddress[0] = address(comprehensiveModule);

        for (uint256 i = 0; i < selectorsToCheck.length; i++) {
            ExecutionDataView memory data = account1.getExecutionData(selectorsToCheck[i]);
            assertEq(data.module, expectedModuleAddress[i]);
            assertFalse(data.allowGlobalValidation);
            assertFalse(data.skipRuntimeValidation);

            HookConfig[3] memory expectedHooks = [
                HookConfigLib.packExecHook(
                    ModuleEntityLib.pack(
                        address(comprehensiveModule), uint32(ComprehensiveModule.EntityId.BOTH_EXECUTION_HOOKS)
                    ),
                    true,
                    true
                ),
                HookConfigLib.packExecHook(
                    ModuleEntityLib.pack(
                        address(comprehensiveModule), uint32(ComprehensiveModule.EntityId.PRE_EXECUTION_HOOK)
                    ),
                    true,
                    false
                ),
                HookConfigLib.packExecHook(
                    ModuleEntityLib.pack(
                        address(comprehensiveModule), uint32(ComprehensiveModule.EntityId.POST_EXECUTION_HOOK)
                    ),
                    false,
                    true
                )
            ];

            assertEq(data.executionHooks.length, 3);
            for (uint256 j = 0; j < data.executionHooks.length; j++) {
                assertEq(HookConfig.unwrap(data.executionHooks[j]), HookConfig.unwrap(expectedHooks[j]));
            }
        }
    }

    function test_moduleView_getValidationData() public withSMATest {
        ValidationDataView memory data = account1.getValidationData(comprehensiveModuleValidation);
        bytes4[] memory selectors = data.selectors;

        assertTrue(data.isGlobal);
        assertTrue(data.isSignatureValidation);
        assertTrue(data.isUserOpValidation);
        assertEq(data.validationHooks.length, 2);
        assertEq(
            HookConfig.unwrap(data.validationHooks[0]),
            HookConfig.unwrap(
                HookConfigLib.packValidationHook(
                    address(comprehensiveModule), uint32(ComprehensiveModule.EntityId.PRE_VALIDATION_HOOK_1)
                )
            )
        );
        assertEq(
            HookConfig.unwrap(data.validationHooks[1]),
            HookConfig.unwrap(
                HookConfigLib.packValidationHook(
                    address(comprehensiveModule), uint32(ComprehensiveModule.EntityId.PRE_VALIDATION_HOOK_2)
                )
            )
        );

        assertEq(data.executionHooks.length, 0);
        assertEq(selectors.length, 1);
        assertEq(selectors[0], comprehensiveModule.foo.selector);
    }

    // Test config

    function _initialValidationConfig()
        internal
        virtual
        override
        returns (ModuleEntity, bool, bool, bool, bytes4[] memory, bytes memory, bytes[] memory)
    {
        bytes[] memory hooks = new bytes[](2);
        hooks[0] = abi.encodePacked(
            HookConfigLib.packValidationHook(
                address(comprehensiveModule), uint32(ComprehensiveModule.EntityId.PRE_VALIDATION_HOOK_1)
            )
        );
        hooks[1] = abi.encodePacked(
            HookConfigLib.packValidationHook(
                address(comprehensiveModule), uint32(ComprehensiveModule.EntityId.PRE_VALIDATION_HOOK_2)
            )
        );

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = comprehensiveModule.foo.selector;

        return (comprehensiveModuleValidation, true, true, true, selectors, bytes(""), hooks);
    }
}
