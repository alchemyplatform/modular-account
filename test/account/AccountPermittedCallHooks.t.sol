// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";
import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";
import {IPluginManager} from "../../src/interfaces/IPluginManager.sol";
import {FunctionReference} from "../../src/libraries/FunctionReferenceLib.sol";
import {
    IPlugin,
    ManifestExecutionHook,
    PluginManifest,
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction
} from "../../src/interfaces/IPlugin.sol";

import {MultiOwnerMSCAFactory} from "../../src/factory/MultiOwnerMSCAFactory.sol";
import {MockPlugin} from "../mocks/MockPlugin.sol";

/// @dev Unlike execution hooks, permitted call hooks are scoped to the plugin that is executing the call
/// through `executeFromPlugin`. Therefore, different plugins cannot apply overlapping hooks to the same
/// plugin + selector combination. Overlapping hooks in this case can only originate from the same plugin,
/// which is unrealistic but possible. That's what we test here.
contract UpgradeableModularAccountPermittedCallHooksTest is Test {
    using ECDSA for bytes32;

    IEntryPoint public entryPoint;
    MultiOwnerPlugin public multiOwnerPlugin;
    MultiOwnerMSCAFactory public factory;
    MockPlugin public mockPlugin1;
    bytes32 public manifestHash1;

    address public owner1;
    uint256 public owner1Key;
    UpgradeableModularAccount public account1;

    bytes4 internal constant _EXEC_SELECTOR = bytes4(uint32(1));
    uint8 internal constant _PRE_HOOK_FUNCTION_ID_1 = 1;
    uint8 internal constant _POST_HOOK_FUNCTION_ID_2 = 2;
    uint8 internal constant _PRE_HOOK_FUNCTION_ID_3 = 3;
    uint8 internal constant _POST_HOOK_FUNCTION_ID_4 = 4;

    PluginManifest public m1;

    event PluginInstalled(
        address indexed plugin,
        bytes32 manifestHash,
        FunctionReference[] dependencies,
        IPluginManager.InjectedHook[] injectedHooks
    );
    event PluginUninstalled(address indexed plugin, bool indexed callbacksSucceeded);
    // emitted by MockPlugin
    event ReceivedCall(bytes msgData, uint256 msgValue);

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));
        multiOwnerPlugin = new MultiOwnerPlugin();

        (owner1, owner1Key) = makeAddrAndKey("owner1");
        address impl = address(new UpgradeableModularAccount(IEntryPoint(address(entryPoint))));

        factory = new MultiOwnerMSCAFactory(
            address(this),
            address(multiOwnerPlugin),
            impl,
            keccak256(abi.encode(multiOwnerPlugin.pluginManifest())),
            entryPoint
        );

        address[] memory owners = new address[](1);
        owners[0] = owner1;
        account1 = UpgradeableModularAccount(payable(factory.createAccount(0, owners)));
        vm.deal(address(account1), 100 ether);

        entryPoint.depositTo{value: 1 wei}(address(account1));

        m1.executionFunctions.push(_EXEC_SELECTOR);

        m1.runtimeValidationFunctions.push(
            ManifestAssociatedFunction({
                executionSelector: _EXEC_SELECTOR,
                associatedFunction: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
                    functionId: 0,
                    dependencyIndex: 0
                })
            })
        );

        m1.permittedExecutionSelectors.push(_EXEC_SELECTOR);
    }

    /// @dev Plugin hook pair(s): [1, null]
    ///      Expected execution: [1, null]
    function test_prePermittedCallHook_install() public {
        vm.startPrank(owner1);

        _installPlugin1WithHooks(
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0})
        );

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, null]
    ///      Expected execution: [1, null]
    function test_prePermittedCallHook_run() public {
        test_prePermittedCallHook_install();

        vm.startPrank(address(mockPlugin1));

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                address(mockPlugin1), // caller
                0, // msg.value in call to account
                abi.encodePacked(_EXEC_SELECTOR)
            ),
            0 // msg value in call to plugin
        );

        account1.executeFromPlugin(abi.encodePacked(_EXEC_SELECTOR));

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, null]
    ///      Expected execution: [1, null]
    function test_prePermittedCallHook_uninstall() public {
        test_prePermittedCallHook_install();

        vm.startPrank(owner1);

        _uninstallPlugin(mockPlugin1);

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, 2]
    ///      Expected execution: [1, 2]
    function test_permittedCallHookPair_install() public {
        vm.startPrank(owner1);

        _installPlugin1WithHooks(
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            })
        );

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, 2]
    ///      Expected execution: [1, 2]
    function test_permittedCallHookPair_run() public {
        test_permittedCallHookPair_install();

        vm.startPrank(address(mockPlugin1));

        vm.expectEmit(true, true, true, true);
        // pre hook call
        emit ReceivedCall(
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                address(mockPlugin1), // caller
                0, // msg.value in call to account
                abi.encodePacked(_EXEC_SELECTOR)
            ),
            0 // msg value in call to plugin
        );
        vm.expectEmit(true, true, true, true);
        // exec call
        emit ReceivedCall(abi.encodePacked(_EXEC_SELECTOR), 0);
        vm.expectEmit(true, true, true, true);
        // post hook call
        emit ReceivedCall(
            abi.encodeCall(
                IPlugin.postExecutionHook, (_POST_HOOK_FUNCTION_ID_2, abi.encode(_PRE_HOOK_FUNCTION_ID_1))
            ),
            0 // msg value in call to plugin
        );

        account1.executeFromPlugin(abi.encodePacked(_EXEC_SELECTOR));

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, 2]
    ///      Expected execution: [1, 2]
    function test_permittedCallHookPair_uninstall() public {
        test_permittedCallHookPair_install();

        vm.startPrank(owner1);

        _uninstallPlugin(mockPlugin1);

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [null, 2]
    ///      Expected execution: [null, 2]
    function test_postOnlyPermittedCallHook_install() public {
        vm.startPrank(owner1);

        _installPlugin1WithHooks(
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0}),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            })
        );

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [null, 2]
    ///      Expected execution: [null, 2]
    function test_postOnlyPermittedCallHook_run() public {
        test_postOnlyPermittedCallHook_install();

        vm.startPrank(address(mockPlugin1));

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(
            abi.encodeCall(IPlugin.postExecutionHook, (_POST_HOOK_FUNCTION_ID_2, "")),
            0 // msg value in call to plugin
        );

        account1.executeFromPlugin(abi.encodePacked(_EXEC_SELECTOR));

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [null, 2]
    ///      Expected execution: [null, 2]
    function test_postOnlyPermittedCallHook_uninstall() public {
        test_postOnlyPermittedCallHook_install();

        vm.startPrank(owner1);

        _uninstallPlugin(mockPlugin1);

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, null], [1, null]
    ///      Expected execution: [1, null]
    function test_overlappingPrePermittedCallHooks_install() public {
        vm.startPrank(owner1);

        _installPlugin1WithHooks(
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0}),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0})
        );

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, null], [1, null]
    ///      Expected execution: [1, null]
    function test_overlappingPrePermittedCallHooks_run() public {
        test_overlappingPrePermittedCallHooks_install();

        vm.startPrank(address(mockPlugin1));

        // Expect the pre hook to be called just once.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                address(mockPlugin1), // caller
                0, // msg.value in call to account
                abi.encodePacked(_EXEC_SELECTOR)
            ),
            1
        );

        account1.executeFromPlugin(abi.encodePacked(_EXEC_SELECTOR));

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, null], [1, null]
    ///      Expected execution: [1, null]
    function test_overlappingPrePermittedCallHooks_uninstall() public {
        test_overlappingPrePermittedCallHooks_install();

        vm.startPrank(owner1);

        _uninstallPlugin(mockPlugin1);

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, 2], [1, 2]
    ///      Expected execution: [1, 2]
    function test_overlappingPermittedCallHookPairs_install() public {
        vm.startPrank(owner1);

        _installPlugin1WithHooks(
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            })
        );

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, 2], [1, 2]
    ///      Expected execution: [1, 2]
    function test_overlappingPermittedCallHookPairs_run() public {
        test_overlappingPermittedCallHookPairs_install();

        vm.startPrank(address(mockPlugin1));

        // Expect the pre hook to be called just once.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                address(mockPlugin1), // caller
                0, // msg.value in call to account
                abi.encodePacked(_EXEC_SELECTOR)
            ),
            1
        );

        // Expect the post hook to be called just once, with the expected data.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                abi.encode(_PRE_HOOK_FUNCTION_ID_1) // preExecHookData
            ),
            1
        );

        account1.executeFromPlugin(abi.encodePacked(_EXEC_SELECTOR));

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, 2], [1, 2]
    ///      Expected execution: [1, 2]
    function test_overlappingPermittedCallHookPairs_uninstall() public {
        test_overlappingPermittedCallHookPairs_install();

        vm.startPrank(owner1);

        _uninstallPlugin(mockPlugin1);

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, 2], [3, 2]
    ///      Expected execution: [1, 2], [3, 2]
    function test_overlappingPermittedCallHookPairsOnPost_install() public {
        vm.startPrank(owner1);

        _installPlugin1WithHooks(
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_3,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            })
        );

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, 2], [3, 2]
    ///      Expected execution: [1, 2], [3, 2]
    function test_overlappingPermittedCallHookPairsOnPost_run() public {
        test_overlappingPermittedCallHookPairsOnPost_install();

        vm.startPrank(address(mockPlugin1));

        // Expect each pre hook to be called once.

        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_3,
                address(mockPlugin1), // caller
                0, // msg.value in call to account
                abi.encodePacked(_EXEC_SELECTOR)
            ),
            1
        );

        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                address(mockPlugin1), // caller
                0, // msg.value in call to account
                abi.encodePacked(_EXEC_SELECTOR)
            ),
            1
        );

        // Expect the post hook to be called twice, with the expected data.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                abi.encode(_PRE_HOOK_FUNCTION_ID_1) // preExecHookData
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                abi.encode(_PRE_HOOK_FUNCTION_ID_3) // preExecHookData
            ),
            1
        );

        account1.executeFromPlugin(abi.encodePacked(_EXEC_SELECTOR));

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, 2], [3, 2]
    ///      Expected execution: [1, 2], [3, 2]
    function test_overlappingPermittedCallHookPairsOnPost_uninstall() public {
        test_overlappingPermittedCallHookPairsOnPost_install();

        vm.startPrank(owner1);

        _uninstallPlugin(mockPlugin1);

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, 2], [1, 4]
    ///      Expected execution: [1, 2], [1, 4]
    function test_overlappingPermittedCallHookPairsOnPre_install() public {
        vm.startPrank(owner1);

        _installPlugin1WithHooks(
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_4,
                dependencyIndex: 0
            })
        );

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, 2], [1, 4]
    ///      Expected execution: [1, 2], [1, 4]
    function test_overlappingPermittedCallHookPairsOnPre_run() public {
        test_overlappingPermittedCallHookPairsOnPre_install();

        vm.startPrank(address(mockPlugin1));

        // Expect the pre hook to be called twice, each passing data over to their respective post hooks.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                address(mockPlugin1), // caller
                0, // msg.value in call to account
                abi.encodePacked(_EXEC_SELECTOR)
            ),
            2
        );

        // Expect each post hook to be called once, with the expected data.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                abi.encode(_PRE_HOOK_FUNCTION_ID_1) // preExecHookData
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_4,
                abi.encode(_PRE_HOOK_FUNCTION_ID_1) // preExecHookData
            ),
            1
        );

        account1.executeFromPlugin(abi.encodePacked(_EXEC_SELECTOR));

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, 2], [1, 4]
    ///      Expected execution: [1, 2], [1, 4]
    function test_overlappingPermittedCallHookPairsOnPre_uninstall() public {
        test_overlappingPermittedCallHookPairsOnPre_install();

        vm.startPrank(owner1);

        _uninstallPlugin(mockPlugin1);

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, 2], [1, null]
    ///      Expected execution: [1, 2]
    function test_overlappingPermittedCallHookPairsOnPreWithNullPost_install() public {
        vm.startPrank(owner1);

        _installPlugin1WithHooks(
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0})
        );

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, 2], [1, null]
    ///      Expected execution: [1, 2]
    function test_overlappingPermittedCallHookPairsOnPreWithNullPost_run() public {
        test_overlappingPermittedCallHookPairsOnPreWithNullPost_install();

        vm.startPrank(address(mockPlugin1));

        // Expect the pre hook to be called just once.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                address(mockPlugin1), // caller
                0, // msg.value in call to account
                abi.encodePacked(_EXEC_SELECTOR)
            ),
            1
        );

        // Expect the post hook to be called just once, with the expected data.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                abi.encode(_PRE_HOOK_FUNCTION_ID_1) // preExecHookData
            ),
            1
        );

        account1.executeFromPlugin(abi.encodePacked(_EXEC_SELECTOR));

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, 2], [1, null]
    ///      Expected execution: [1, 2]
    function test_overlappingPermittedCallHookPairsOnPreWithNullPost_uninstall() public {
        test_overlappingPermittedCallHookPairsOnPreWithNullPost_install();

        vm.startPrank(owner1);

        _uninstallPlugin(mockPlugin1);

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, 2], [null, 2]
    ///      Expected execution: [1, 2], [null, 2]
    function test_overlappingPermittedCallHookPairsOnPreWithNullPre_install() public {
        vm.startPrank(owner1);

        _installPlugin1WithHooks(
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            }),
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0}),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            })
        );

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, 2], [null, 2]
    ///      Expected execution: [1, 2], [null, 2]
    function test_overlappingPermittedCallHookPairsOnPreWithNullPre_run() public {
        test_overlappingPermittedCallHookPairsOnPreWithNullPre_install();

        vm.startPrank(address(mockPlugin1));

        // Expect the pre hook to be called just once.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                address(mockPlugin1), // caller
                0, // msg.value in call to account
                abi.encodePacked(_EXEC_SELECTOR)
            ),
            1
        );

        // Expect the post hook to be called twice, with the expected data.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                abi.encode(_PRE_HOOK_FUNCTION_ID_1) // preExecHookData
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                "" // preExecHookData
            ),
            1
        );

        account1.executeFromPlugin(abi.encodePacked(_EXEC_SELECTOR));

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [1, 2], [null, 2]
    ///      Expected execution: [1, 2], [null, 2]
    function test_overlappingPermittedCallHookPairsOnPreWithNullPre_uninstall() public {
        test_overlappingPermittedCallHookPairsOnPreWithNullPre_install();

        vm.startPrank(owner1);

        _uninstallPlugin(mockPlugin1);

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [null, 2], [null, 2]
    ///      Expected execution: [null, 2]
    function test_overlappingPostPermittedCallHooks_install() public {
        vm.startPrank(owner1);

        _installPlugin1WithHooks(
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0}),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            }),
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0}),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            })
        );

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [null, 2], [null, 2]
    ///      Expected execution: [null, 2]
    function test_overlappingPostPermittedCallHooks_run() public {
        test_overlappingPostPermittedCallHooks_install();

        vm.startPrank(address(mockPlugin1));

        // Expect the post hook to be called just once.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.postExecutionHook.selector,
                _POST_HOOK_FUNCTION_ID_2,
                "" // preExecHookData
            ),
            1
        );

        account1.executeFromPlugin(abi.encodePacked(_EXEC_SELECTOR));

        vm.stopPrank();
    }

    /// @dev Plugin hook pair(s): [null, 2], [null, 2]
    ///      Expected execution: [null, 2]
    function test_overlappingPostPermittedCallHooks_uninstall() public {
        test_overlappingPostPermittedCallHooks_install();

        vm.startPrank(owner1);

        _uninstallPlugin(mockPlugin1);

        vm.stopPrank();
    }

    function _installPlugin1WithHooks(ManifestFunction memory preHook1, ManifestFunction memory postHook1)
        internal
    {
        m1.permittedCallHooks.push(ManifestExecutionHook(_EXEC_SELECTOR, preHook1, postHook1));
        mockPlugin1 = new MockPlugin(m1);
        manifestHash1 = keccak256(abi.encode(mockPlugin1.pluginManifest()));

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onInstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(
            address(mockPlugin1), manifestHash1, new FunctionReference[](0), new IPluginManager.InjectedHook[](0)
        );

        account1.installPlugin({
            plugin: address(mockPlugin1),
            manifestHash: manifestHash1,
            pluginInitData: bytes(""),
            dependencies: new FunctionReference[](0),
            injectedHooks: new IPluginManager.InjectedHook[](0)
        });
    }

    function _installPlugin1WithHooks(
        ManifestFunction memory preHook1,
        ManifestFunction memory postHook1,
        ManifestFunction memory preHook2,
        ManifestFunction memory postHook2
    ) internal {
        m1.permittedCallHooks.push(ManifestExecutionHook(_EXEC_SELECTOR, preHook1, postHook1));
        m1.permittedCallHooks.push(ManifestExecutionHook(_EXEC_SELECTOR, preHook2, postHook2));
        mockPlugin1 = new MockPlugin(m1);
        manifestHash1 = keccak256(abi.encode(mockPlugin1.pluginManifest()));

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onInstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(
            address(mockPlugin1), manifestHash1, new FunctionReference[](0), new IPluginManager.InjectedHook[](0)
        );

        account1.installPlugin({
            plugin: address(mockPlugin1),
            manifestHash: manifestHash1,
            pluginInitData: bytes(""),
            dependencies: new FunctionReference[](0),
            injectedHooks: new IPluginManager.InjectedHook[](0)
        });
    }

    function _uninstallPlugin(MockPlugin plugin) internal {
        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onUninstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginUninstalled(address(plugin), true);

        account1.uninstallPlugin(address(plugin), bytes(""), bytes(""), new bytes[](0));
    }
}
