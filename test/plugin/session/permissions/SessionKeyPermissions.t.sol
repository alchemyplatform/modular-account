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

pragma solidity ^0.8.22;

import {Test} from "forge-std/Test.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {UserOperation} from "modular-account-libs/interfaces/UserOperation.sol";
import {FunctionReference} from "modular-account-libs/interfaces/IPluginManager.sol";
import {Call} from "modular-account-libs/interfaces/IStandardExecutor.sol";
import {FunctionReferenceLib} from "modular-account-libs/libraries/FunctionReferenceLib.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {ISessionKeyPermissionsUpdates} from
    "../../../../src/plugins/session/permissions/ISessionKeyPermissionsUpdates.sol";
import {UpgradeableModularAccount} from "../../../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerModularAccountFactory} from "../../../../src/factory/MultiOwnerModularAccountFactory.sol";
import {IEntryPoint} from "../../../../src/interfaces/erc4337/IEntryPoint.sol";
import {IMultiOwnerPlugin} from "../../../../src/plugins/owner/IMultiOwnerPlugin.sol";
import {MultiOwnerPlugin} from "../../../../src/plugins/owner/MultiOwnerPlugin.sol";
import {ISessionKeyPlugin} from "../../../../src/plugins/session/ISessionKeyPlugin.sol";
import {SessionKeyPlugin} from "../../../../src/plugins/session/SessionKeyPlugin.sol";
import {Counter} from "../../../mocks/Counter.sol";

contract SessionKeyPermissionsTest is Test {
    using ECDSA for bytes32;

    IEntryPoint entryPoint;
    address payable beneficiary;
    MultiOwnerPlugin multiOwnerPlugin;
    MultiOwnerModularAccountFactory factory;
    SessionKeyPlugin sessionKeyPlugin;
    FunctionReference[] dependencies;

    address owner1;
    uint256 owner1Key;
    UpgradeableModularAccount account1;

    address sessionKey1;
    uint256 sessionKey1Private;

    uint256 constant CALL_GAS_LIMIT = 70000;
    uint256 constant VERIFICATION_GAS_LIMIT = 1000000;

    address payable recipient;

    Counter counter1;

    Counter counter2;

    event PermissionsUpdated(address indexed account, address indexed sessionKey, bytes[] updates);

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));
        (owner1, owner1Key) = makeAddrAndKey("owner1");
        beneficiary = payable(makeAddr("beneficiary"));
        recipient = payable(makeAddr("recipient"));

        vm.deal(beneficiary, 1 wei);
        vm.deal(recipient, 1 wei);

        multiOwnerPlugin = new MultiOwnerPlugin();
        address impl = address(new UpgradeableModularAccount(entryPoint));

        factory = new MultiOwnerModularAccountFactory(
            address(this),
            address(multiOwnerPlugin),
            impl,
            keccak256(abi.encode(multiOwnerPlugin.pluginManifest())),
            entryPoint
        );

        sessionKeyPlugin = new SessionKeyPlugin();

        address[] memory owners1 = new address[](1);
        owners1[0] = owner1;
        account1 = UpgradeableModularAccount(payable(factory.createAccount(0, owners1)));
        vm.deal(address(account1), 100 ether);

        bytes32 manifestHash = keccak256(abi.encode(sessionKeyPlugin.pluginManifest()));
        dependencies.push(
            FunctionReferenceLib.pack(
                address(multiOwnerPlugin), uint8(IMultiOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
            )
        );
        dependencies.push(
            FunctionReferenceLib.pack(
                address(multiOwnerPlugin), uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER)
            )
        );
        vm.prank(owner1);
        account1.installPlugin({
            plugin: address(sessionKeyPlugin),
            manifestHash: manifestHash,
            pluginInstallData: abi.encode(new address[](0), new bytes32[](0), new bytes[][](0)),
            dependencies: dependencies
        });

        // Create and add a session key
        (sessionKey1, sessionKey1Private) = makeAddrAndKey("sessionKey1");

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKey1, bytes32(0), new bytes[](0));

        // Initialize the interaction targets
        counter1 = new Counter();
        counter1.increment();

        counter2 = new Counter();
        counter2.increment();
    }

    function test_sessionPerms_validateSetUp() public {
        assertEq(
            uint8(sessionKeyPlugin.getAccessControlType(address(account1), sessionKey1)),
            uint8(ISessionKeyPlugin.ContractAccessControlType.ALLOWLIST)
        );
    }

    function test_sessionPerms_contractDefaultAllowList() public {
        _runSessionKeyExecUserOp(
            address(counter1),
            sessionKey1,
            sessionKey1Private,
            abi.encodeCall(Counter.increment, ()),
            0 wei,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA23 reverted (or OOG)")
        );

        // Call should fail before removing the allowlist
        assertEq(counter1.number(), 1);

        // Remove the allowlist
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.setAccessListType,
            (ISessionKeyPlugin.ContractAccessControlType.ALLOW_ALL_ACCESS)
        );
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Call should succeed after removing the allowlist
        _runSessionKeyExecUserOp(
            address(counter1), sessionKey1, sessionKey1Private, abi.encodeCall(Counter.increment, ()), 0 wei, ""
        );

        assertEq(counter1.number(), 2);
    }

    function test_sessionPerms_contractAllowList() public {
        // Assert the contracts to be added are not already on the allowlist
        (bool isOnList, bool checkSelectors) =
            sessionKeyPlugin.getAccessControlEntry(address(account1), sessionKey1, address(counter1));

        assertFalse(isOnList, "Address should not start on the list");
        assertFalse(checkSelectors, "Address should not start with selectors checked");

        // Add the allowlist
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.updateAccessListAddressEntry, (address(counter1), true, false)
        );
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Plugin should report the entry as on the list
        (isOnList, checkSelectors) =
            sessionKeyPlugin.getAccessControlEntry(address(account1), sessionKey1, address(counter1));
        assertTrue(isOnList);
        assertFalse(checkSelectors);

        // Call should succeed after adding the allowlist
        _runSessionKeyExecUserOp(
            address(counter1), sessionKey1, sessionKey1Private, abi.encodeCall(Counter.increment, ()), 0 wei, ""
        );

        assertEq(counter1.number(), 2);

        // // Call should fail for contract not on allowlist
        _runSessionKeyExecUserOp(
            address(counter2),
            sessionKey1,
            sessionKey1Private,
            abi.encodeCall(Counter.increment, ()),
            0 wei,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA23 reverted (or OOG)")
        );

        assertEq(counter2.number(), 1);
    }

    function test_sessionPerms_contractDenyList() public {
        // Add the denylist
        bytes[] memory updates = new bytes[](2);
        updates[0] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.setAccessListType, (ISessionKeyPlugin.ContractAccessControlType.DENYLIST)
        );
        updates[1] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.updateAccessListAddressEntry, (address(counter1), true, false)
        );
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Check that the call should fail after adding the denylist
        _runSessionKeyExecUserOp(
            address(counter1),
            sessionKey1,
            sessionKey1Private,
            abi.encodeCall(Counter.increment, ()),
            0 wei,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA23 reverted (or OOG)")
        );

        assertEq(counter1.number(), 1);

        // Call should suceed for contract not on denylist
        _runSessionKeyExecUserOp(
            address(counter2), sessionKey1, sessionKey1Private, abi.encodeCall(Counter.increment, ()), 0 wei, ""
        );

        assertEq(counter2.number(), 2);
    }

    function test_sessionPerms_selectorAllowList() public {
        // Validate that the address and the selector do not start out enabled.
        (bool addressOnList, bool checkSelectors) =
            sessionKeyPlugin.getAccessControlEntry(address(account1), sessionKey1, address(counter1));
        assertFalse(addressOnList);
        assertFalse(checkSelectors);
        bool selectorOnList = sessionKeyPlugin.isSelectorOnAccessControlList(
            address(account1), sessionKey1, address(counter1), Counter.increment.selector
        );
        assertFalse(selectorOnList);

        // Add the allowlist
        bytes[] memory updates = new bytes[](2);
        updates[0] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.updateAccessListAddressEntry, (address(counter1), true, true)
        );
        updates[1] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.updateAccessListFunctionEntry,
            (address(counter1), Counter.increment.selector, true)
        );

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Validate that the address and the selector are now enabled
        (addressOnList, checkSelectors) =
            sessionKeyPlugin.getAccessControlEntry(address(account1), sessionKey1, address(counter1));
        assertTrue(addressOnList);
        assertTrue(checkSelectors);
        selectorOnList = sessionKeyPlugin.isSelectorOnAccessControlList(
            address(account1), sessionKey1, address(counter1), Counter.increment.selector
        );
        assertTrue(selectorOnList);

        // Call should succeed after adding the allowlist
        _runSessionKeyExecUserOp(
            address(counter1), sessionKey1, sessionKey1Private, abi.encodeCall(Counter.increment, ()), 0 wei, ""
        );

        assertEq(counter1.number(), 2);

        // Call should fail for function not on allowlist
        _runSessionKeyExecUserOp(
            address(counter1),
            sessionKey1,
            sessionKey1Private,
            abi.encodeCall(Counter.setNumber, (5)),
            0 wei,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA23 reverted (or OOG)")
        );

        assertEq(counter1.number(), 2);
    }

    function test_sessionPerms_selectorDenyList() public {
        // Add the denylist
        bytes[] memory updates = new bytes[](3);
        updates[0] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.setAccessListType, (ISessionKeyPlugin.ContractAccessControlType.DENYLIST)
        );
        updates[1] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.updateAccessListAddressEntry, (address(counter1), true, true)
        );
        updates[2] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.updateAccessListFunctionEntry,
            (address(counter1), Counter.increment.selector, true)
        );

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Call should fail after adding the denylist
        _runSessionKeyExecUserOp(
            address(counter1),
            sessionKey1,
            sessionKey1Private,
            abi.encodeCall(Counter.increment, ()),
            0 wei,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA23 reverted (or OOG)")
        );

        assertEq(counter1.number(), 1);

        // Call should succeed for function not on denylist
        _runSessionKeyExecUserOp(
            address(counter1), sessionKey1, sessionKey1Private, abi.encodeCall(Counter.setNumber, (5)), 0 wei, ""
        );

        assertEq(counter1.number(), 5);
    }

    function testFuzz_sessionKeyTimeRange(uint48 startTime, uint48 endTime) public {
        bytes[] memory updates = new bytes[](2);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.updateTimeRange, (startTime, endTime));
        updates[1] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.setAccessListType,
            (ISessionKeyPlugin.ContractAccessControlType.ALLOW_ALL_ACCESS)
        );

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(0), value: 0, data: ""});

        UserOperation memory userOp = UserOperation({
            sender: address(account1),
            nonce: entryPoint.getNonce(address(account1), 0),
            initCode: "",
            callData: abi.encodeCall(ISessionKeyPlugin.executeWithSessionKey, (calls, sessionKey1)),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKey1Private, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        vm.prank(address(entryPoint));
        uint256 validationData = account1.validateUserOp(userOp, userOpHash, 0);

        // Assert the correct time range fields are returned
        // Only check the end time field if it wasn't zero, which is interpretted as a max value by 4337.
        if (endTime != 0) {
            assertEq(uint48(validationData >> 160), endTime);
        }
        assertEq(uint48(validationData >> 208), startTime);
    }

    function test_rotateKey_basic() public {
        // Remove the default allowlist
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.setAccessListType,
            (ISessionKeyPlugin.ContractAccessControlType.ALLOW_ALL_ACCESS)
        );
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        (address sessionKey2, uint256 sessionKey2Private) = makeAddrAndKey("sessionKey2");

        // Add the session key to the account
        address[] memory keysToAdd = new address[](1);
        keysToAdd[0] = sessionKey2;

        vm.startPrank(owner1);
        SessionKeyPlugin(address(account1)).rotateSessionKey(
            sessionKey1, sessionKeyPlugin.findPredecessor(address(account1), sessionKey1), sessionKey2
        );
        vm.stopPrank();

        // Attempting to use the previous key should fail during the signature check
        _runSessionKeyExecUserOp(
            address(counter1),
            sessionKey1,
            sessionKey1Private,
            abi.encodeCall(Counter.increment, ()),
            0 wei,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA23 reverted (or OOG)")
        );

        // Attempting to use the new key should succeed
        _runSessionKeyExecUserOp(
            address(counter1), sessionKey2, sessionKey2Private, abi.encodeCall(Counter.increment, ()), 0 wei, ""
        );
    }

    function test_rotateKey_permissionsTransfer() public {
        // Set a time range on the key
        uint48 startTime = uint48(block.timestamp);
        uint48 endTime = uint48(block.timestamp + 1000);

        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.updateTimeRange, (startTime, endTime));

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Rotate the key
        address sessionKey2 = makeAddr("sessionKey2");

        vm.startPrank(owner1);
        SessionKeyPlugin(address(account1)).rotateSessionKey(
            sessionKey1, sessionKeyPlugin.findPredecessor(address(account1), sessionKey1), sessionKey2
        );
        vm.stopPrank();

        // Check the rotated key's time range
        (uint48 returnedStartTime, uint48 returnedEndTime) =
            sessionKeyPlugin.getKeyTimeRange(address(account1), sessionKey2);

        assertEq(returnedStartTime, startTime);
        assertEq(returnedEndTime, endTime);
    }

    function testFuzz_sessionKeyPermissions_setRequiredPaymaster(address requiredPaymaster) public {
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setRequiredPaymaster, (requiredPaymaster));

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Check the required paymaster
        address returnedRequiredPaymaster = sessionKeyPlugin.getRequiredPaymaster(address(account1), sessionKey1);
        assertEq(returnedRequiredPaymaster, requiredPaymaster);

        // Set the required paymaster to zero
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setRequiredPaymaster, (address(0)));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Check the required paymaster
        returnedRequiredPaymaster = sessionKeyPlugin.getRequiredPaymaster(address(account1), sessionKey1);
        assertEq(returnedRequiredPaymaster, address(0));
    }

    function testFuzz_sessionKeyPermissions_checkRequiredPaymaster(
        address requiredPaymaster,
        address providedPaymaster
    ) public {
        // Disable the allowlist and disable native token spend checking.
        bytes[] memory updates = new bytes[](2);
        updates[0] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.setAccessListType,
            (ISessionKeyPlugin.ContractAccessControlType.ALLOW_ALL_ACCESS)
        );
        updates[1] = abi.encodeCall(ISessionKeyPermissionsUpdates.setNativeTokenSpendLimit, (type(uint256).max, 0));

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        vm.assume(providedPaymaster != address(0));

        // First validate a user op with the paymaster set, without the required paymaster rule.

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: recipient, value: 1 wei, data: ""});
        UserOperation memory userOp = UserOperation({
            sender: address(account1),
            nonce: entryPoint.getNonce(address(account1), 0),
            initCode: "",
            callData: abi.encodeCall(ISessionKeyPlugin.executeWithSessionKey, (calls, sessionKey1)),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: abi.encodePacked(providedPaymaster),
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKey1Private, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        vm.prank(address(entryPoint));
        uint256 validationData = account1.validateUserOp(userOp, userOpHash, 0);

        // Assert that validation passes
        assertEq(uint160(validationData), 0);

        // Now set the required paymaster rule and validate again.
        bytes[] memory updates2 = new bytes[](1);
        updates2[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setRequiredPaymaster, (requiredPaymaster));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates2);

        vm.startPrank(address(entryPoint));

        if (requiredPaymaster == providedPaymaster || requiredPaymaster == address(0)) {
            // Assert that validation passes
            validationData = account1.validateUserOp(userOp, userOpHash, 0);
            assertEq(uint160(validationData), 0);
        } else {
            // Assert that validation fails
            vm.expectRevert(ISessionKeyPlugin.PermissionsCheckFailed.selector);
            validationData = account1.validateUserOp(userOp, userOpHash, 0);
        }
    }

    function test_sessionKeyPerms_requiredPaymaster_partialAddressFails() public {
        // Disable the allowlist
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.setAccessListType,
            (ISessionKeyPlugin.ContractAccessControlType.ALLOW_ALL_ACCESS)
        );
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // create a paymaster address that would match, if right-padded with zeroes
        address paymasterAddr = 0x1234123412341234000000000000000000000000;
        // Add it
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setRequiredPaymaster, (paymasterAddr));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: recipient, value: 1 wei, data: ""});

        UserOperation memory userOp = UserOperation({
            sender: address(account1),
            nonce: entryPoint.getNonce(address(account1), 0),
            initCode: "",
            callData: abi.encodeCall(ISessionKeyPlugin.executeWithSessionKey, (calls, sessionKey1)),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: abi.encodePacked(uint64(0x1234123412341234)),
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKey1Private, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        vm.expectRevert("AA93 invalid paymasterAndData");
        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_sessionKeyPerms_updatePermissions_invalidUpdates() public {
        vm.startPrank(owner1);
        bytes[] memory updates = new bytes[](1);
        updates[0] = hex"112233"; // < 4 byte update
        vm.expectRevert(
            abi.encodeWithSelector(ISessionKeyPlugin.InvalidPermissionsUpdate.selector, bytes4(updates[0]))
        );
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        updates[0] = hex"11223344"; // Invalid selector
        vm.expectRevert(
            abi.encodeWithSelector(ISessionKeyPlugin.InvalidPermissionsUpdate.selector, bytes4(updates[0]))
        );
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);
    }

    function test_sessionKeyPerms_independentKeyStorage() public {
        address sessionKey2 = makeAddr("sessionKey2");

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKey2, bytes32(0), new bytes[](0));

        ISessionKeyPlugin.ContractAccessControlType accessControlType1;
        ISessionKeyPlugin.ContractAccessControlType accessControlType2;

        accessControlType1 = sessionKeyPlugin.getAccessControlType(address(account1), sessionKey1);
        accessControlType2 = sessionKeyPlugin.getAccessControlType(address(account1), sessionKey2);

        assertEq(
            uint8(accessControlType1),
            uint8(ISessionKeyPlugin.ContractAccessControlType.ALLOWLIST),
            "sessionKey1 should start with an allowlist"
        );
        assertEq(
            uint8(accessControlType2),
            uint8(ISessionKeyPlugin.ContractAccessControlType.ALLOWLIST),
            "sessionKey2 should start with an allowlist"
        );

        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.setAccessListType,
            (ISessionKeyPlugin.ContractAccessControlType.ALLOW_ALL_ACCESS)
        );
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        accessControlType1 = sessionKeyPlugin.getAccessControlType(address(account1), sessionKey1);
        accessControlType2 = sessionKeyPlugin.getAccessControlType(address(account1), sessionKey2);

        assertEq(
            uint8(accessControlType1),
            uint8(ISessionKeyPlugin.ContractAccessControlType.ALLOW_ALL_ACCESS),
            "sessionKey1 should now have no allowlist"
        );
        assertEq(
            uint8(accessControlType2),
            uint8(ISessionKeyPlugin.ContractAccessControlType.ALLOWLIST),
            "sessionKey2 should still have an allowlist"
        );
    }

    function test_sessionKeyPerms_reinstallResets() public {
        // Tests that reinstalling the plugin resets the permissions.

        uint48 time1 = uint48(2000);
        uint48 time2 = uint48(3000);
        // Set the time range on the key
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.updateTimeRange, (time1, time2));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Assert that the time range is set
        (uint48 returnedStartTime, uint48 returnedEndTime) =
            sessionKeyPlugin.getKeyTimeRange(address(account1), sessionKey1);
        assertEq(returnedStartTime, time1);
        assertEq(returnedEndTime, time2);

        // Uninstall the session key plugin
        vm.prank(owner1);
        account1.uninstallPlugin(address(sessionKeyPlugin), "", "");

        // Reinstall the session key plugin.
        vm.startPrank(owner1);
        account1.installPlugin({
            plugin: address(sessionKeyPlugin),
            manifestHash: keccak256(abi.encode(sessionKeyPlugin.pluginManifest())),
            pluginInstallData: abi.encode(new address[](0), new bytes32[](0), new bytes[][](0)),
            dependencies: dependencies
        });
        vm.stopPrank();

        // Re-add the session key
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKey1, bytes32(0), new bytes[](0));

        // Assert that the time range is reset
        (returnedStartTime, returnedEndTime) = sessionKeyPlugin.getKeyTimeRange(address(account1), sessionKey1);
        assertEq(returnedStartTime, uint48(0));
        assertEq(returnedEndTime, uint48(0));
    }

    function testFuzz_initialSessionKeysWithPermissions(uint256 seed) public {
        // Uninstall the plugin
        vm.prank(owner1);
        account1.uninstallPlugin(address(sessionKeyPlugin), "", "");

        address[] memory sessionKeys = _generateRandomAddresses(seed);
        bytes32[] memory tags = new bytes32[](sessionKeys.length);
        bytes[][] memory sessionKeyPermissions = new bytes[][](sessionKeys.length);
        for (uint256 i = 0; i < sessionKeys.length; i++) {
            uint256 modifiedSeed;
            unchecked {
                modifiedSeed = seed + i;
            }
            sessionKeyPermissions[i] = _generateRandomPermissionUpdates(modifiedSeed);
        }

        // Reinstall the plugin with the session keys
        for (uint256 i = 0; i < sessionKeys.length; i++) {
            vm.expectEmit(true, true, true, true);
            emit PermissionsUpdated(address(account1), sessionKeys[i], sessionKeyPermissions[i]);
        }
        bytes32 manifestHash = keccak256(abi.encode(sessionKeyPlugin.pluginManifest()));
        vm.prank(owner1);
        account1.installPlugin({
            plugin: address(sessionKeyPlugin),
            manifestHash: manifestHash,
            pluginInstallData: abi.encode(sessionKeys, tags, sessionKeyPermissions),
            dependencies: dependencies
        });
    }

    function _runSessionKeyExecUserOp(
        address target,
        address sessionKey,
        uint256 privateKey,
        bytes memory callData,
        uint256 value,
        bytes memory revertReason
    ) internal {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: target, value: value, data: callData});

        UserOperation memory userOp = UserOperation({
            sender: address(account1),
            nonce: entryPoint.getNonce(address(account1), 0),
            initCode: "",
            callData: abi.encodeCall(ISessionKeyPlugin.executeWithSessionKey, (calls, sessionKey)),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        if (revertReason.length > 0) {
            vm.expectRevert(revertReason);
        }
        entryPoint.handleOps(userOps, beneficiary);
    }

    function _generateRandomAddresses(uint256 seed) internal returns (address[] memory keys) {
        uint256 addressCount = (seed % 5) + 1;

        keys = new address[](addressCount);
        for (uint256 i = 0; i < addressCount; i++) {
            keys[i] = makeAddr(string.concat(vm.toString(seed), "sessionKey", vm.toString(i)));
        }
    }

    function _generateRandomPermissionUpdates(uint256 seed) internal returns (bytes[] memory updates) {
        uint256 updateCount = (seed % 5) + 1;

        updates = new bytes[](updateCount);

        for (uint256 i = 0; i < updateCount; i++) {
            uint256 updateType = (seed % 6) + 1;
            if (updateType == 1) {
                // Set access list type
                uint256 accessListType = (seed % 3);
                updates[i] = abi.encodeCall(
                    ISessionKeyPermissionsUpdates.setAccessListType,
                    ISessionKeyPlugin.ContractAccessControlType(accessListType)
                );
            } else if (updateType == 2) {
                // Update access list address entry
                address addr = makeAddr(string.concat(vm.toString(seed), "addr", vm.toString(i)));
                bool isOnList = (seed % 2) == 0;
                bool checkSelectors = (seed % 3) == 0;
                updates[i] = abi.encodeCall(
                    ISessionKeyPermissionsUpdates.updateAccessListAddressEntry, (addr, isOnList, checkSelectors)
                );
            } else if (updateType == 3) {
                // Update access list function entry
                address addr = makeAddr(string.concat(vm.toString(seed), "addr", vm.toString(i)));
                bytes4 selector = bytes4(uint32(seed));
                bool isOnList = (seed % 2) == 0;
                updates[i] = abi.encodeCall(
                    ISessionKeyPermissionsUpdates.updateAccessListFunctionEntry, (addr, selector, isOnList)
                );
            } else if (updateType == 4) {
                // Set time range
                uint48 startTime = uint48(seed);
                uint48 endTime = uint48(seed << 2);
                updates[i] = abi.encodeCall(ISessionKeyPermissionsUpdates.updateTimeRange, (startTime, endTime));
            } else if (updateType == 5) {
                // Set required paymaster
                address paymaster = makeAddr(string.concat(vm.toString(seed), "paymaster", vm.toString(i)));
                updates[i] = abi.encodeCall(ISessionKeyPermissionsUpdates.setRequiredPaymaster, (paymaster));
            } else if (updateType == 6) {
                // Set native token spend limit
                uint256 limit = seed;
                updates[i] = abi.encodeCall(ISessionKeyPermissionsUpdates.setNativeTokenSpendLimit, (limit, 0));
            }
        }
    }
}
