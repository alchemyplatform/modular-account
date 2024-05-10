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
import {FunctionReferenceLib} from "modular-account-libs/libraries/FunctionReferenceLib.sol";
import {UserOperation} from "modular-account-libs/interfaces/UserOperation.sol";
import {FunctionReference} from "modular-account-libs/interfaces/IPluginManager.sol";
import {Call} from "modular-account-libs/interfaces/IStandardExecutor.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {ISessionKeyPermissionsUpdates} from
    "../../../src/plugins/session/permissions/ISessionKeyPermissionsUpdates.sol";
import {UpgradeableModularAccount} from "../../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerModularAccountFactory} from "../../../src/factory/MultiOwnerModularAccountFactory.sol";
import {IEntryPoint} from "../../../src/interfaces/erc4337/IEntryPoint.sol";
import {BasePlugin} from "../../../src/plugins/BasePlugin.sol";
import {IMultiOwnerPlugin} from "../../../src/plugins/owner/IMultiOwnerPlugin.sol";
import {MultiOwnerPlugin} from "../../../src/plugins/owner/MultiOwnerPlugin.sol";
import {ISessionKeyPlugin} from "../../../src/plugins/session/ISessionKeyPlugin.sol";
import {SessionKeyPlugin} from "../../../src/plugins/session/SessionKeyPlugin.sol";

contract SessionKeyPluginWithMultiOwnerTest is Test {
    using ECDSA for bytes32;

    IEntryPoint entryPoint;
    address payable beneficiary;
    MultiOwnerPlugin multiOwnerPlugin;
    MultiOwnerModularAccountFactory factory;
    SessionKeyPlugin sessionKeyPlugin;

    address owner1;
    uint256 owner1Key;
    address[] public owners;
    UpgradeableModularAccount account1;

    uint256 constant CALL_GAS_LIMIT = 70000;
    uint256 constant VERIFICATION_GAS_LIMIT = 1000000;

    address payable recipient;

    // Event re-declarations for use with `vm.expectEmit()`
    event SessionKeyAdded(address indexed account, address indexed sessionKey, bytes32 indexed tag);
    event SessionKeyRemoved(address indexed account, address indexed sessionKey);
    event SessionKeyRotated(address indexed account, address indexed oldSessionKey, address indexed newSessionKey);

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

        owners = new address[](1);
        owners[0] = owner1;
        account1 = UpgradeableModularAccount(payable(factory.createAccount(0, owners)));
        vm.deal(address(account1), 100 ether);

        bytes32 manifestHash = keccak256(abi.encode(sessionKeyPlugin.pluginManifest()));
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReferenceLib.pack(
            address(multiOwnerPlugin), uint8(IMultiOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] = FunctionReferenceLib.pack(
            address(multiOwnerPlugin), uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER)
        );
        vm.prank(owner1);
        account1.installPlugin({
            plugin: address(sessionKeyPlugin),
            manifestHash: manifestHash,
            pluginInstallData: abi.encode(new address[](0), new bytes32[](0), new bytes[][](0)),
            dependencies: dependencies
        });
    }

    function test_sessionKey_addKeySuccess() public {
        address sessionKeyToAdd = makeAddr("sessionKey1");

        vm.expectEmit(true, true, true, true);
        emit SessionKeyAdded(address(account1), sessionKeyToAdd, bytes32(0));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKeyToAdd, bytes32(0), new bytes[](0));

        // Check using all view methods
        address[] memory sessionKeys = sessionKeyPlugin.sessionKeysOf(address(account1));
        assertEq(sessionKeys.length, 1);
        assertEq(sessionKeys[0], sessionKeyToAdd);
        assertTrue(sessionKeyPlugin.isSessionKeyOf(address(account1), sessionKeyToAdd));
    }

    function test_sessionKey_addKeyFailure() public {
        vm.startPrank(owner1);

        // Zero address session key
        address sessionKeyToAdd = address(0);
        vm.expectRevert(abi.encodeWithSelector(ISessionKeyPlugin.InvalidSessionKey.selector, address(0)));
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKeyToAdd, bytes32(0), new bytes[](0));

        // Duplicate session key
        sessionKeyToAdd = makeAddr("sessionKey1");
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKeyToAdd, bytes32(0), new bytes[](0));
        vm.expectRevert(abi.encodeWithSelector(ISessionKeyPlugin.InvalidSessionKey.selector, sessionKeyToAdd));
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKeyToAdd, bytes32(0), new bytes[](0));

        // Check using all view methods
        address[] memory sessionKeys = sessionKeyPlugin.sessionKeysOf(address(account1));
        assertEq(sessionKeys.length, 1);
        assertEq(sessionKeys[0], sessionKeyToAdd);
        assertTrue(sessionKeyPlugin.isSessionKeyOf(address(account1), sessionKeyToAdd));
    }

    function test_sessionKey_addAndRemoveKeys() public {
        address sessionKey1 = makeAddr("sessionKey1");
        address sessionKey2 = makeAddr("sessionKey2");

        vm.startPrank(owner1);
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKey1, bytes32(0), new bytes[](0));
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKey2, bytes32(0), new bytes[](0));
        vm.stopPrank();

        // Check using all view methods
        address[] memory sessionKeys = sessionKeyPlugin.sessionKeysOf(address(account1));
        assertEq(sessionKeys.length, 2);
        assertEq(sessionKeys[0], sessionKey2);
        assertEq(sessionKeys[1], sessionKey1);
        assertTrue(sessionKeyPlugin.isSessionKeyOf(address(account1), sessionKey1));
        assertTrue(sessionKeyPlugin.isSessionKeyOf(address(account1), sessionKey2));

        vm.expectEmit(true, true, true, true);
        emit SessionKeyRemoved(address(account1), sessionKey1);
        vm.startPrank(owner1);
        SessionKeyPlugin(address(account1)).removeSessionKey(
            sessionKey1, sessionKeyPlugin.findPredecessor(address(account1), sessionKey1)
        );
        vm.stopPrank();

        // Check using all view methods
        sessionKeys = sessionKeyPlugin.sessionKeysOf(address(account1));
        assertEq(sessionKeys.length, 1);
        assertEq(sessionKeys[0], sessionKey2);
        assertFalse(sessionKeyPlugin.isSessionKeyOf(address(account1), sessionKey1));
        assertTrue(sessionKeyPlugin.isSessionKeyOf(address(account1), sessionKey2));
    }

    function testFuzz_sessionKey_addKeysDuringInstall(uint8 seed) public {
        // First uninstall the plugin
        vm.prank(owner1);
        account1.uninstallPlugin(address(sessionKeyPlugin), "", "");

        // Generate a set of initial session keys
        uint256 addressCount = (seed % 16) + 1;

        address[] memory sessionKeysToAdd = new address[](addressCount);
        bytes32[] memory tags = new bytes32[](addressCount);
        for (uint256 i = 0; i < addressCount; i++) {
            sessionKeysToAdd[i] = makeAddr(string.concat(vm.toString(seed), "sessionKey", vm.toString(i)));
            tags[i] = bytes32(uint256(i) + seed);
        }

        bytes memory onInstallData = abi.encode(sessionKeysToAdd, tags, new bytes[][](addressCount));

        // Re-install the plugin
        bytes32 manifestHash = keccak256(abi.encode(sessionKeyPlugin.pluginManifest()));
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReferenceLib.pack(
            address(multiOwnerPlugin), uint8(IMultiOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        dependencies[1] = FunctionReferenceLib.pack(
            address(multiOwnerPlugin), uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER)
        );

        for (uint256 i = 0; i < addressCount; i++) {
            vm.expectEmit(true, true, true, true);
            emit SessionKeyAdded(address(account1), sessionKeysToAdd[i], tags[i]);
        }
        vm.prank(owner1);
        account1.installPlugin({
            plugin: address(sessionKeyPlugin),
            manifestHash: manifestHash,
            pluginInstallData: onInstallData,
            dependencies: dependencies
        });

        // Check using all view methods
        address[] memory sessionKeys = sessionKeyPlugin.sessionKeysOf(address(account1));
        assertEq(sessionKeys.length, addressCount);
        for (uint256 i = 0; i < addressCount; i++) {
            // Invert the indexing because the view function will return it in reverse order
            assertEq(sessionKeys[sessionKeys.length - 1 - i], sessionKeysToAdd[i]);
            assertTrue(sessionKeyPlugin.isSessionKeyOf(address(account1), sessionKeysToAdd[i]));
        }
    }

    function test_sessionKey_rotate_valid() public {
        // Add the first key
        address sessionKey1 = makeAddr("sessionKey1");
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKey1, bytes32(0), new bytes[](0));

        // Rotate to the second key
        address sessionKey2 = makeAddr("sessionKey2");
        bytes32 predecessor = sessionKeyPlugin.findPredecessor(address(account1), sessionKey1);
        vm.expectEmit(true, true, true, true);
        emit SessionKeyRotated(address(account1), sessionKey1, sessionKey2);
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).rotateSessionKey(sessionKey1, predecessor, sessionKey2);

        // Check using all view methods
        address[] memory sessionKeys = sessionKeyPlugin.sessionKeysOf(address(account1));
        assertEq(sessionKeys.length, 1);
        assertEq(sessionKeys[0], sessionKey2);
        assertFalse(sessionKeyPlugin.isSessionKeyOf(address(account1), sessionKey1));
        assertTrue(sessionKeyPlugin.isSessionKeyOf(address(account1), sessionKey2));
    }

    function test_sessionKey_rotate_existing() public {
        // Add the session keys 1 and 2
        address sessionKey1 = makeAddr("sessionKey1");
        address sessionKey2 = makeAddr("sessionKey2");
        vm.startPrank(owner1);
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKey1, bytes32(0), new bytes[](0));
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKey2, bytes32(0), new bytes[](0));
        vm.stopPrank();

        // Attempt to rotate key 1 to key 2
        bytes32 predecessor = sessionKeyPlugin.findPredecessor(address(account1), sessionKey1);
        vm.expectRevert(abi.encodeWithSelector(ISessionKeyPlugin.InvalidSessionKey.selector, sessionKey2));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).rotateSessionKey(sessionKey1, predecessor, sessionKey2);
    }

    function test_sessionKey_rotate_invalid() public {
        // Add the first key
        address sessionKey1 = makeAddr("sessionKey1");
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKey1, bytes32(0), new bytes[](0));

        // Attempt to rotate to the zero address
        address zeroAddr = address(0);
        bytes32 predecessor = sessionKeyPlugin.findPredecessor(address(account1), sessionKey1);
        vm.expectRevert(abi.encodeWithSelector(ISessionKeyPlugin.InvalidSessionKey.selector, zeroAddr));
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).rotateSessionKey(sessionKey1, predecessor, zeroAddr);
    }

    function test_sessionKey_useSessionKey() public {
        (address sessionKey1, uint256 sessionKeyPrivate) = makeAddrAndKey("sessionKey1");

        vm.startPrank(owner1);
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKey1, bytes32(0), new bytes[](0));
        // Disable the allowlist and native token spend checking
        bytes[] memory permissionUpdates = new bytes[](2);
        permissionUpdates[0] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.setAccessListType,
            (ISessionKeyPlugin.ContractAccessControlType.ALLOW_ALL_ACCESS)
        );
        permissionUpdates[1] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setNativeTokenSpendLimit, (type(uint256).max, 0));
        SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKey1, permissionUpdates);
        vm.stopPrank();

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: recipient, value: 1 wei, data: ""});

        UserOperation memory userOp = UserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(
                ISessionKeyPlugin(address(sessionKeyPlugin)).executeWithSessionKey, (calls, sessionKey1)
            ),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPrivate, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(recipient.balance, 2 wei);
    }

    function test_sessionKey_useSessionKey_failInRuntime() public {
        (address sessionKey1,) = makeAddrAndKey("sessionKey1");

        vm.startPrank(owner1);
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKey1, bytes32(0), new bytes[](0));

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: recipient, value: 1 wei, data: ""});

        vm.expectRevert(abi.encodeWithSelector(UpgradeableModularAccount.AlwaysDenyRule.selector));
        SessionKeyPlugin(address(account1)).executeWithSessionKey(calls, sessionKey1);
    }

    function testFuzz_sessionKey_userOpValidation_valid(uint16 seed) public {
        uint256[] memory privateKeys = _createSessionKeys(uint8(seed));

        // Pick a random signer to use to validate with
        uint256 signerPrivateKey = privateKeys[(seed >> 8) % privateKeys.length];
        address signerAddress = vm.addr(signerPrivateKey);

        // Construct a user op to validate against
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: recipient, value: 1 wei, data: ""});
        UserOperation memory userOp = UserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(
                ISessionKeyPlugin(address(sessionKeyPlugin)).executeWithSessionKey, (calls, signerAddress)
            ),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        vm.prank(address(account1));
        uint256 result = sessionKeyPlugin.userOpValidationFunction(
            uint8(ISessionKeyPlugin.FunctionId.USER_OP_VALIDATION_SESSION_KEY), userOp, userOpHash
        );

        assertEq(result, 0);
    }

    function testFuzz_sessionKey_userOpValidation_mismatchedSig(uint8 sessionKeysSeed, uint64 signerSeed) public {
        _createSessionKeys(sessionKeysSeed);

        (address signer, uint256 signerPrivate) =
            makeAddrAndKey(string.concat("Signer", vm.toString(uint32(signerSeed))));

        // The signer should not be a session key of the plugin - this is exceedingly unlikely but checking
        // anyways.
        vm.assume(!sessionKeyPlugin.isSessionKeyOf(address(account1), signer));

        // Construct a user op to validate against
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: recipient, value: 1 wei, data: ""});
        UserOperation memory userOp = UserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(
                ISessionKeyPlugin(address(sessionKeyPlugin)).executeWithSessionKey, (calls, signer)
            ),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivate, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        vm.startPrank(address(account1));
        vm.expectRevert(ISessionKeyPlugin.PermissionsCheckFailed.selector);
        sessionKeyPlugin.userOpValidationFunction(
            uint8(ISessionKeyPlugin.FunctionId.USER_OP_VALIDATION_SESSION_KEY), userOp, userOpHash
        );
    }

    function testFuzz_sessionKey_userOpValidation_invalidSig(uint8 sessionKeysSeed, uint64 signerSeed) public {
        _createSessionKeys(sessionKeysSeed);

        (address signer,) = makeAddrAndKey(string.concat("Signer", vm.toString(uint32(signerSeed))));

        // The signer should not be a session key of the plugin - this is exceedingly unlikely but checking
        // anyways.
        vm.assume(!sessionKeyPlugin.isSessionKeyOf(address(account1), signer));

        // Construct a user op to validate against
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: recipient, value: 1 wei, data: ""});
        UserOperation memory userOp = UserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(
                ISessionKeyPlugin(address(sessionKeyPlugin)).executeWithSessionKey, (calls, signer)
            ),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        userOp.signature = "";

        vm.prank(address(account1));
        vm.expectRevert(abi.encodeWithSelector(ISessionKeyPlugin.InvalidSignature.selector, signer));
        sessionKeyPlugin.userOpValidationFunction(
            uint8(ISessionKeyPlugin.FunctionId.USER_OP_VALIDATION_SESSION_KEY), userOp, userOpHash
        );
    }

    function testFuzz_sessionKey_invalidFunctionId(uint8 functionId, UserOperation memory userOp) public {
        vm.assume(functionId != uint8(ISessionKeyPlugin.FunctionId.USER_OP_VALIDATION_SESSION_KEY));

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        vm.expectRevert(
            abi.encodeWithSelector(
                BasePlugin.NotImplemented.selector, BasePlugin.userOpValidationFunction.selector, functionId
            )
        );
        sessionKeyPlugin.userOpValidationFunction(functionId, userOp, userOpHash);
    }

    // getPredecessor test case with sentinel value as predecessor
    function test_sessionKey_getPredecessor_sentinel() public {
        address sessionKey1 = makeAddr("sessionKey1");
        address sessionKey2 = makeAddr("sessionKey2");

        vm.startPrank(owner1);
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKey1, bytes32(0), new bytes[](0));
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKey2, bytes32(0), new bytes[](0));

        bytes32 predecessor = sessionKeyPlugin.findPredecessor(address(account1), sessionKey2);
        assertEq(predecessor, bytes32(uint256(1)));

        SessionKeyPlugin(address(account1)).removeSessionKey(sessionKey2, predecessor);
        vm.stopPrank();

        // Check using all view methods
        address[] memory sessionKeys = sessionKeyPlugin.sessionKeysOf(address(account1));
        assertEq(sessionKeys.length, 1);
        assertEq(sessionKeys[0], sessionKey1);
        assertTrue(sessionKeyPlugin.isSessionKeyOf(address(account1), sessionKey1));
        assertFalse(sessionKeyPlugin.isSessionKeyOf(address(account1), sessionKey2));
    }

    // getPredecessor test case with address value as predecessor
    function test_sessionKey_getPredecessor_address() public {
        address sessionKey1 = makeAddr("sessionKey1");
        address sessionKey2 = makeAddr("sessionKey2");

        vm.startPrank(owner1);
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKey1, bytes32(0), new bytes[](0));
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKey2, bytes32(0), new bytes[](0));

        bytes32 predecessor = sessionKeyPlugin.findPredecessor(address(account1), sessionKey1);
        assertEq(predecessor, bytes32(bytes20(sessionKey2)));

        SessionKeyPlugin(address(account1)).removeSessionKey(sessionKey1, predecessor);
        vm.stopPrank();

        // Check using all view methods
        address[] memory sessionKeys = sessionKeyPlugin.sessionKeysOf(address(account1));
        assertEq(sessionKeys.length, 1);
        assertEq(sessionKeys[0], sessionKey2);
        assertTrue(sessionKeyPlugin.isSessionKeyOf(address(account1), sessionKey2));
        assertFalse(sessionKeyPlugin.isSessionKeyOf(address(account1), sessionKey1));
    }

    function test_sessionKey_getPredecessor_missing() public {
        address[] memory sessionKeysToAdd = new address[](1);
        sessionKeysToAdd[0] = makeAddr("sessionKey1");

        vm.startPrank(owner1);
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKeysToAdd[0], bytes32(0), new bytes[](0));

        address key2 = makeAddr("sessionKey2");
        vm.expectRevert(abi.encodeWithSelector(ISessionKeyPlugin.SessionKeyNotFound.selector, key2));
        sessionKeyPlugin.findPredecessor(address(account1), key2);
    }

    function test_sessionKey_doesNotContainSentinelValue() public {
        assertFalse(sessionKeyPlugin.isSessionKeyOf(address(account1), address(1)));

        address[] memory sessionKeysToAdd = new address[](1);
        sessionKeysToAdd[0] = makeAddr("sessionKey1");

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).addSessionKey(sessionKeysToAdd[0], bytes32(0), new bytes[](0));

        assertFalse(sessionKeyPlugin.isSessionKeyOf(address(account1), address(1)));
    }

    function _createSessionKeys(uint8 seed) internal returns (uint256[] memory privateKeys) {
        uint256 addressCount = (seed % 16) + 1;

        address[] memory sessionKeysToAdd = new address[](addressCount);
        privateKeys = new uint256[](addressCount);
        for (uint256 i = 0; i < addressCount; i++) {
            (sessionKeysToAdd[i], privateKeys[i]) = makeAddrAndKey(string.concat("sessionKey", vm.toString(i)));
        }

        // To disable the allowlist and native token spend checking
        bytes[] memory permissionUpdates = new bytes[](2);
        permissionUpdates[0] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.setAccessListType,
            (ISessionKeyPlugin.ContractAccessControlType.ALLOW_ALL_ACCESS)
        );
        permissionUpdates[1] =
            abi.encodeCall(ISessionKeyPermissionsUpdates.setNativeTokenSpendLimit, (type(uint256).max, 0));

        vm.startPrank(owner1);
        for (uint256 i = 0; i < addressCount; i++) {
            SessionKeyPlugin(address(account1)).addSessionKey(sessionKeysToAdd[i], bytes32(0), new bytes[](0));
            SessionKeyPlugin(address(account1)).updateKeyPermissions(sessionKeysToAdd[i], permissionUpdates);
        }
        vm.stopPrank();
    }
}
