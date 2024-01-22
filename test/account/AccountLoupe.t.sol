// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {Test} from "forge-std/Test.sol";

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {IMultiOwnerPlugin} from "../../src/plugins/owner/IMultiOwnerPlugin.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";
import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";
import {
    ManifestAssociatedFunctionType,
    ManifestExecutionHook,
    ManifestFunction,
    PluginManifest
} from "../../src/interfaces/IPlugin.sol";
import {IAccountLoupe} from "../../src/interfaces/IAccountLoupe.sol";
import {IPluginManager} from "../../src/interfaces/IPluginManager.sol";
import {IStandardExecutor} from "../../src/interfaces/IStandardExecutor.sol";
import {FunctionReference, FunctionReferenceLib} from "../../src/libraries/FunctionReferenceLib.sol";

import {MultiOwnerMSCAFactory} from "../../src/factory/MultiOwnerMSCAFactory.sol";
import {ComprehensivePlugin} from "../mocks/plugins/ComprehensivePlugin.sol";
import {MockPlugin} from "../mocks/MockPlugin.sol";

contract AccountLoupeTest is Test {
    IEntryPoint public entryPoint;
    MultiOwnerPlugin public multiOwnerPlugin;
    MultiOwnerMSCAFactory public factory;
    ComprehensivePlugin public comprehensivePlugin;

    UpgradeableModularAccount public account1;

    FunctionReference public ownerUserOpValidation;
    FunctionReference public ownerRuntimeValidation;

    event ReceivedCall(bytes msgData, uint256 msgValue);

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));

        multiOwnerPlugin = new MultiOwnerPlugin();
        address impl = address(new UpgradeableModularAccount(entryPoint));
        factory = new MultiOwnerMSCAFactory(
            address(this),
            address(multiOwnerPlugin),
            impl,
            keccak256(abi.encode(multiOwnerPlugin.pluginManifest())),
            entryPoint
        );
        comprehensivePlugin = new ComprehensivePlugin();

        address[] memory owners = new address[](1);
        owners[0] = address(this);
        account1 = UpgradeableModularAccount(payable(factory.createAccount(0, owners)));

        bytes32 manifestHash = keccak256(abi.encode(comprehensivePlugin.pluginManifest()));
        account1.installPlugin(address(comprehensivePlugin), manifestHash, "", new FunctionReference[](0));

        ownerUserOpValidation = FunctionReferenceLib.pack(
            address(multiOwnerPlugin), uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER)
        );
        ownerRuntimeValidation = FunctionReferenceLib.pack(
            address(multiOwnerPlugin), uint8(IMultiOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
    }

    function test_pluginLoupe_getInstalledPlugins_initial() public {
        address[] memory plugins = account1.getInstalledPlugins();

        assertEq(plugins.length, 2);

        assertEq(plugins[1], address(multiOwnerPlugin));
        assertEq(plugins[0], address(comprehensivePlugin));
    }

    function test_pluginLoupe_getExecutionFunctionConfig_native() public {
        bytes4[] memory selectorsToCheck = new bytes4[](5);
        FunctionReference[] memory expectedUserOpValidations = new FunctionReference[](5);
        FunctionReference[] memory expectedRuntimeValidations = new FunctionReference[](5);

        selectorsToCheck[0] = IStandardExecutor.execute.selector;
        expectedUserOpValidations[0] = ownerUserOpValidation;
        expectedRuntimeValidations[0] = ownerRuntimeValidation;

        selectorsToCheck[1] = IStandardExecutor.executeBatch.selector;
        expectedUserOpValidations[1] = ownerUserOpValidation;
        expectedRuntimeValidations[1] = ownerRuntimeValidation;

        selectorsToCheck[2] = UUPSUpgradeable.upgradeToAndCall.selector;
        expectedUserOpValidations[2] = ownerUserOpValidation;
        expectedRuntimeValidations[2] = ownerRuntimeValidation;

        selectorsToCheck[3] = IPluginManager.installPlugin.selector;
        expectedUserOpValidations[3] = ownerUserOpValidation;
        expectedRuntimeValidations[3] = ownerRuntimeValidation;

        selectorsToCheck[4] = IPluginManager.uninstallPlugin.selector;
        expectedUserOpValidations[4] = ownerUserOpValidation;
        expectedRuntimeValidations[4] = ownerRuntimeValidation;

        for (uint256 i = 0; i < selectorsToCheck.length; i++) {
            IAccountLoupe.ExecutionFunctionConfig memory config =
                account1.getExecutionFunctionConfig(selectorsToCheck[i]);

            assertEq(config.plugin, address(account1));
            assertEq(
                FunctionReference.unwrap(config.userOpValidationFunction),
                FunctionReference.unwrap(expectedUserOpValidations[i])
            );
            assertEq(
                FunctionReference.unwrap(config.runtimeValidationFunction),
                FunctionReference.unwrap(expectedRuntimeValidations[i])
            );
        }
    }

    function test_pluginLoupe_getExecutionFunctionConfig_plugin() public {
        bytes4[] memory selectorsToCheck = new bytes4[](2);
        address[] memory expectedPluginAddress = new address[](2);
        FunctionReference[] memory expectedUserOpValidations = new FunctionReference[](2);
        FunctionReference[] memory expectedRuntimeValidations = new FunctionReference[](2);

        selectorsToCheck[0] = comprehensivePlugin.foo.selector;
        expectedPluginAddress[0] = address(comprehensivePlugin);
        expectedUserOpValidations[0] = FunctionReferenceLib.pack(
            address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.USER_OP_VALIDATION)
        );
        expectedRuntimeValidations[0] = FunctionReferenceLib.pack(
            address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.RUNTIME_VALIDATION)
        );

        selectorsToCheck[1] = multiOwnerPlugin.updateOwners.selector;
        expectedPluginAddress[1] = address(multiOwnerPlugin);
        expectedUserOpValidations[1] = ownerUserOpValidation;
        expectedRuntimeValidations[1] = ownerRuntimeValidation;

        for (uint256 i = 0; i < selectorsToCheck.length; i++) {
            IAccountLoupe.ExecutionFunctionConfig memory config =
                account1.getExecutionFunctionConfig(selectorsToCheck[i]);

            assertEq(config.plugin, expectedPluginAddress[i]);
            assertEq(
                FunctionReference.unwrap(config.userOpValidationFunction),
                FunctionReference.unwrap(expectedUserOpValidations[i])
            );
            assertEq(
                FunctionReference.unwrap(config.runtimeValidationFunction),
                FunctionReference.unwrap(expectedRuntimeValidations[i])
            );
        }
    }

    function test_pluginLoupe_getExecutionHooks() public {
        IAccountLoupe.ExecutionHooks[] memory hooks = account1.getExecutionHooks(comprehensivePlugin.foo.selector);

        assertEq(hooks.length, 2);

        _assertHookEq(
            hooks[0],
            FunctionReferenceLib.pack(
                address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.PRE_EXECUTION_HOOK)
            ),
            FunctionReferenceLib.pack(
                address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.POST_EXECUTION_HOOK)
            )
        );

        _assertHookEq(
            hooks[1],
            FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE,
            FunctionReferenceLib.pack(
                address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.POST_EXECUTION_HOOK)
            )
        );
    }

    function test_pluginLoupe_getHooks_multiple() public {
        // Add a third set of execution hooks to the account, and validate that it can return all hooks applied
        // over the function.

        PluginManifest memory mockPluginManifest;

        mockPluginManifest.executionHooks = new ManifestExecutionHook[](1);
        mockPluginManifest.executionHooks[0] = ManifestExecutionHook({
            executionSelector: ComprehensivePlugin.foo.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 0,
                dependencyIndex: 0
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        MockPlugin mockPlugin = new MockPlugin(mockPluginManifest);
        bytes32 manifestHash = keccak256(abi.encode(mockPlugin.pluginManifest()));

        account1.installPlugin(address(mockPlugin), manifestHash, "", new FunctionReference[](0));

        // Assert that the returned execution hooks are what is expected

        IAccountLoupe.ExecutionHooks[] memory hooks = account1.getExecutionHooks(comprehensivePlugin.foo.selector);

        assertEq(hooks.length, 3);

        _assertHookEq(
            hooks[0],
            FunctionReferenceLib.pack(address(mockPlugin), uint8(0)),
            FunctionReferenceLib.pack(address(mockPlugin), uint8(0))
        );

        _assertHookEq(
            hooks[1],
            FunctionReferenceLib.pack(
                address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.PRE_EXECUTION_HOOK)
            ),
            FunctionReferenceLib.pack(
                address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.POST_EXECUTION_HOOK)
            )
        );

        _assertHookEq(
            hooks[2],
            FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE,
            FunctionReferenceLib.pack(
                address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.POST_EXECUTION_HOOK)
            )
        );
    }

    function test_pluginLoupe_getPreValidationHooks() public {
        (FunctionReference[] memory preUoHooks, FunctionReference[] memory preRuntimeHooks) =
            account1.getPreValidationHooks(comprehensivePlugin.foo.selector);

        // veriry pre UO hooks
        assertEq(preUoHooks.length, 2);
        assertEq(
            FunctionReference.unwrap(preUoHooks[0]),
            FunctionReference.unwrap(
                FunctionReferenceLib.pack(
                    address(comprehensivePlugin),
                    uint8(ComprehensivePlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK_2)
                )
            )
        );
        assertEq(
            FunctionReference.unwrap(preUoHooks[1]),
            FunctionReference.unwrap(
                FunctionReferenceLib.pack(
                    address(comprehensivePlugin),
                    uint8(ComprehensivePlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK_1)
                )
            )
        );

        // veriry pre runtime hooks
        assertEq(preRuntimeHooks.length, 2);
        assertEq(
            FunctionReference.unwrap(preRuntimeHooks[0]),
            FunctionReference.unwrap(
                FunctionReferenceLib.pack(
                    address(comprehensivePlugin),
                    uint8(ComprehensivePlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK_2)
                )
            )
        );
        assertEq(
            FunctionReference.unwrap(preRuntimeHooks[1]),
            FunctionReference.unwrap(
                FunctionReferenceLib.pack(
                    address(comprehensivePlugin),
                    uint8(ComprehensivePlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK_1)
                )
            )
        );
    }

    function test_pluginLoupe_getExecutionHooks_overlapping() public {
        PluginManifest memory mockPluginManifest;

        mockPluginManifest.executionHooks = new ManifestExecutionHook[](9);

        // [0, null]
        mockPluginManifest.executionHooks[0] = ManifestExecutionHook({
            executionSelector: ComprehensivePlugin.foo.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 0,
                dependencyIndex: 0
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.NONE,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        // [0, null]
        mockPluginManifest.executionHooks[1] = ManifestExecutionHook({
            executionSelector: ComprehensivePlugin.foo.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 0,
                dependencyIndex: 0
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.NONE,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        // [1, 2]
        mockPluginManifest.executionHooks[2] = ManifestExecutionHook({
            executionSelector: ComprehensivePlugin.foo.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 1,
                dependencyIndex: 0
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 2,
                dependencyIndex: 0
            })
        });

        // [1, 2]
        mockPluginManifest.executionHooks[3] = ManifestExecutionHook({
            executionSelector: ComprehensivePlugin.foo.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 1,
                dependencyIndex: 0
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 2,
                dependencyIndex: 0
            })
        });

        // [3, 2]
        mockPluginManifest.executionHooks[4] = ManifestExecutionHook({
            executionSelector: ComprehensivePlugin.foo.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 3,
                dependencyIndex: 0
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 2,
                dependencyIndex: 0
            })
        });

        // [1, 4]
        mockPluginManifest.executionHooks[5] = ManifestExecutionHook({
            executionSelector: ComprehensivePlugin.foo.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 1,
                dependencyIndex: 0
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 4,
                dependencyIndex: 0
            })
        });

        // [1, null]
        mockPluginManifest.executionHooks[6] = ManifestExecutionHook({
            executionSelector: ComprehensivePlugin.foo.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 1,
                dependencyIndex: 0
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.NONE,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        // [null, 2]
        mockPluginManifest.executionHooks[7] = ManifestExecutionHook({
            executionSelector: ComprehensivePlugin.foo.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.NONE,
                functionId: 0,
                dependencyIndex: 0
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 2,
                dependencyIndex: 0
            })
        });

        // [null, 2]
        mockPluginManifest.executionHooks[8] = ManifestExecutionHook({
            executionSelector: ComprehensivePlugin.foo.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.NONE,
                functionId: 0,
                dependencyIndex: 0
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 2,
                dependencyIndex: 0
            })
        });

        MockPlugin mockPlugin = new MockPlugin(mockPluginManifest);
        bytes32 manifestHash = keccak256(abi.encode(mockPlugin.pluginManifest()));

        account1.installPlugin(address(mockPlugin), manifestHash, "", new FunctionReference[](0));

        // Assert that the returned execution hooks are what is expected

        IAccountLoupe.ExecutionHooks[] memory hooks = account1.getExecutionHooks(comprehensivePlugin.foo.selector);

        assertEq(hooks.length, 7);

        // [3, 2]
        _assertHookEq(
            hooks[0],
            FunctionReferenceLib.pack(address(mockPlugin), uint8(3)),
            FunctionReferenceLib.pack(address(mockPlugin), uint8(2))
        );

        // [1, 4]
        _assertHookEq(
            hooks[1],
            FunctionReferenceLib.pack(address(mockPlugin), uint8(1)),
            FunctionReferenceLib.pack(address(mockPlugin), uint8(4))
        );

        // [1, 2]
        _assertHookEq(
            hooks[2],
            FunctionReferenceLib.pack(address(mockPlugin), uint8(1)),
            FunctionReferenceLib.pack(address(mockPlugin), uint8(2))
        );

        // [0, null]
        _assertHookEq(
            hooks[3],
            FunctionReferenceLib.pack(address(mockPlugin), uint8(0)),
            FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE
        );

        _assertHookEq(
            hooks[4],
            FunctionReferenceLib.pack(
                address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.PRE_EXECUTION_HOOK)
            ),
            FunctionReferenceLib.pack(
                address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.POST_EXECUTION_HOOK)
            )
        );

        // [null, 2]
        _assertHookEq(
            hooks[5],
            FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE,
            FunctionReferenceLib.pack(address(mockPlugin), uint8(2))
        );

        _assertHookEq(
            hooks[6],
            FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE,
            FunctionReferenceLib.pack(
                address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.POST_EXECUTION_HOOK)
            )
        );
    }

    function _assertHookEq(
        IAccountLoupe.ExecutionHooks memory hook,
        FunctionReference preHook,
        FunctionReference postHook
    ) internal {
        assertEq(FunctionReference.unwrap(hook.preExecHook), FunctionReference.unwrap(preHook));
        assertEq(FunctionReference.unwrap(hook.postExecHook), FunctionReference.unwrap(postHook));
    }

    function test_trace_comprehensivePlugin() public {
        vm.prank(address(comprehensivePlugin));
        account1.executeFromPlugin(abi.encodeCall(comprehensivePlugin.foo, ()));
    }
}
