// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";
import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";
import {IPluginManager} from "../../src/interfaces/IPluginManager.sol";
import {FunctionReference, FunctionReferenceLib} from "../../src/libraries/FunctionReferenceLib.sol";

import {MultiOwnerMSCAFactory} from "../../src/factory/MultiOwnerMSCAFactory.sol";

// A test that verifies how the account caches the state of plugins. This is intended to ensure consistency of
// execution flow when either hooks or plugins change installation state within a single call to the account.
// Test cases included here:
// - UO validation → install / uninstall hook → hook execution
//    - Add pre exec hook
//    - Add post-only exec hook
//    - Add pre/post hook pair
// - UO validation → install execution function → hook execution → execution function
// - UO validation → uninstall execution function → hook execution → execution function *reverts*
// - Runtime validation → install / uninstall hook → hook executionp
// - Runtime validation → install execution function → hook execution → execution function
// - Runtime validation → uninstall execution function → hook execution → execution function *reverts*
// Test cases covered by other tests:
// - UO validation → hook execution
// - Runtime validation → hook execution
contract AccountStatePhasesTest is Test {
    using ECDSA for bytes32;

    IEntryPoint public entryPoint;
    MultiOwnerPlugin public multiOwnerPlugin;
    MultiOwnerMSCAFactory public factory;

    address public owner1;
    uint256 public owner1Key;
    UpgradeableModularAccount public account1;

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
    }

    // Planning out how to do this:
    // - Create a custom plugin that can perform install / uninstall during hooks, validation, or execution.
    // - This can be done by pushing the call encoding responsibilitiy to this test, and just exposing a "side"
    // method that specifies what it should do in a given phase back toward the calling account.
    // - Authorization can be granted by making the plugin itself an owner in multi-owner plugin, which will
    // authorize runtime calls.
    // - The contents of what is called can be a set of mock plugins like the exec hooks test.

    function test_UOValidation_installExecHook_isExecuted_firstHook() public {}

    function test_UOValidation_installExecHook_isExecuted_secondHook() public {}

    // Helper functions
}
