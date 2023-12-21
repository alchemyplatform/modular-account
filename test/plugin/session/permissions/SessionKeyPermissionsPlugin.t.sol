// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";

import {UpgradeableModularAccount} from "../../../../src/account/UpgradeableModularAccount.sol";
import {IMultiOwnerPlugin} from "../../../../src/plugins/owner/IMultiOwnerPlugin.sol";
import {MultiOwnerPlugin} from "../../../../src/plugins/owner/MultiOwnerPlugin.sol";
import {ISessionKeyPlugin} from "../../../../src/plugins/session/ISessionKeyPlugin.sol";
import {SessionKeyPlugin} from "../../../../src/plugins/session/SessionKeyPlugin.sol";
import {ISessionKeyPermissionsPlugin} from
    "../../../../src/plugins/session/permissions/ISessionKeyPermissionsPlugin.sol";
import {ISessionKeyPermissionsUpdates} from
    "../../../../src/plugins/session/permissions/ISessionKeyPermissionsUpdates.sol";
import {SessionKeyPermissionsPlugin} from
    "../../../../src/plugins/session/permissions/SessionKeyPermissionsPlugin.sol";
import {IEntryPoint} from "../../../../src/interfaces/erc4337/IEntryPoint.sol";
import {UserOperation} from "../../../../src/interfaces/erc4337/UserOperation.sol";
import {IPluginManager} from "../../../../src/interfaces/IPluginManager.sol";
import {FunctionReference, FunctionReferenceLib} from "../../../../src/libraries/FunctionReferenceLib.sol";
import {Call} from "../../../../src/interfaces/IStandardExecutor.sol";

import {Counter} from "../../../mocks/Counter.sol";
import {MultiOwnerMSCAFactory} from "../../../../src/factory/MultiOwnerMSCAFactory.sol";

contract SessionKeyPermissionsPluginTest is Test {
    using ECDSA for bytes32;

    IEntryPoint entryPoint;
    address payable beneficiary;
    MultiOwnerPlugin multiOwnerPlugin;
    MultiOwnerMSCAFactory factory;
    SessionKeyPlugin sessionKeyPlugin;
    SessionKeyPermissionsPlugin sessionKeyPermissionsPlugin;

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

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));
        (owner1, owner1Key) = makeAddrAndKey("owner1");
        beneficiary = payable(makeAddr("beneficiary"));
        recipient = payable(makeAddr("recipient"));

        vm.deal(beneficiary, 1 wei);
        vm.deal(recipient, 1 wei);

        multiOwnerPlugin = new MultiOwnerPlugin();
        address impl = address(new UpgradeableModularAccount(entryPoint));

        factory = new MultiOwnerMSCAFactory(
            address(this),
            address(multiOwnerPlugin),
            impl,
            keccak256(abi.encode(multiOwnerPlugin.pluginManifest())),
            entryPoint
        );

        sessionKeyPlugin = new SessionKeyPlugin();
        sessionKeyPermissionsPlugin = new SessionKeyPermissionsPlugin();

        address[] memory owners1 = new address[](1);
        owners1[0] = owner1;
        account1 = UpgradeableModularAccount(payable(factory.createAccount(0, owners1)));
        vm.deal(address(account1), 100 ether);

        bytes32 manifestHash = keccak256(abi.encode(sessionKeyPlugin.pluginManifest()));
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReferenceLib.pack(
            address(multiOwnerPlugin), uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER)
        );
        dependencies[1] = FunctionReferenceLib.pack(
            address(multiOwnerPlugin), uint8(IMultiOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );
        vm.prank(owner1);
        account1.installPlugin({
            plugin: address(sessionKeyPlugin),
            manifestHash: manifestHash,
            pluginInitData: abi.encode(new address[](0)),
            dependencies: dependencies,
            injectedHooks: new IPluginManager.InjectedHook[](0)
        });

        manifestHash = keccak256(abi.encode(sessionKeyPermissionsPlugin.pluginManifest()));
        // Can reuse the same dependencies for this installation, because the requirements are the same.
        vm.prank(owner1);
        account1.installPlugin({
            plugin: address(sessionKeyPermissionsPlugin),
            manifestHash: manifestHash,
            pluginInitData: "",
            dependencies: dependencies,
            injectedHooks: new IPluginManager.InjectedHook[](0)
        });

        // Create and add a session key
        (sessionKey1, sessionKey1Private) = makeAddrAndKey("sessionKey1");

        address[] memory sessionKeysToAdd = new address[](1);
        sessionKeysToAdd[0] = sessionKey1;

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateSessionKeys(
            sessionKeysToAdd, new SessionKeyPlugin.SessionKeyToRemove[](0)
        );

        // Register the session key with the permissions plugin
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).registerKey(sessionKey1, 0);

        // Initialize the interaction targets

        counter1 = new Counter();
        counter1.increment();

        counter2 = new Counter();
        counter2.increment();
    }

    function test_sessionPerms_validateSetUp() public {
        assertEq(
            uint8(sessionKeyPermissionsPlugin.getAccessControlType(address(account1), sessionKey1)),
            uint8(ISessionKeyPermissionsPlugin.ContractAccessControlType.ALLOWLIST)
        );
    }

    function test_sessionPerms_duplicateRegister() public {
        vm.prank(owner1);
        vm.expectRevert(
            abi.encodeWithSelector(ISessionKeyPermissionsPlugin.KeyAlreadyRegistered.selector, sessionKey1)
        );
        SessionKeyPermissionsPlugin(address(account1)).registerKey(sessionKey1, 0);
    }

    function test_sessionPerms_contractDefaultAllowList() public {
        _runSessionKeyExecUserOp(
            address(counter1),
            sessionKey1,
            sessionKey1Private,
            abi.encodeCall(Counter.increment, ()),
            0 wei,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error")
        );

        // Call should fail before removing the allowlist
        assertEq(counter1.number(), 1);

        // Remove the allowlist
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.setAccessListType,
            (ISessionKeyPermissionsPlugin.ContractAccessControlType.NONE)
        );
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Call should succeed after removing the allowlist
        _runSessionKeyExecUserOp(
            address(counter1), sessionKey1, sessionKey1Private, abi.encodeCall(Counter.increment, ()), 0 wei, ""
        );

        assertEq(counter1.number(), 2);
    }

    function test_sessionPerms_contractAllowList() public {
        // Assert the contracts to be added are not already on the allowlist
        (bool isOnList, bool checkSelectors) =
            sessionKeyPermissionsPlugin.getAccessControlEntry(address(account1), sessionKey1, address(counter1));

        assertFalse(isOnList, "Address should not start on the list");
        assertFalse(checkSelectors, "Address should not start with selectors checked");

        // Add the allowlist
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.updateAccessListAddressEntry, (address(counter1), true, false)
        );
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Plugin should report the entry as on the list
        (isOnList, checkSelectors) =
            sessionKeyPermissionsPlugin.getAccessControlEntry(address(account1), sessionKey1, address(counter1));
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
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error")
        );

        assertEq(counter2.number(), 1);
    }

    function test_sessionPerms_contractDenyList() public {
        // Add the denylist
        bytes[] memory updates = new bytes[](2);
        updates[0] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.setAccessListType,
            (ISessionKeyPermissionsPlugin.ContractAccessControlType.DENYLIST)
        );
        updates[1] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.updateAccessListAddressEntry, (address(counter1), true, false)
        );
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Check that the call should fail after adding the denylist
        _runSessionKeyExecUserOp(
            address(counter1),
            sessionKey1,
            sessionKey1Private,
            abi.encodeCall(Counter.increment, ()),
            0 wei,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error")
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
            sessionKeyPermissionsPlugin.getAccessControlEntry(address(account1), sessionKey1, address(counter1));
        assertFalse(addressOnList);
        assertFalse(checkSelectors);
        bool selectorOnList = sessionKeyPermissionsPlugin.isSelectorOnAccessControlList(
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
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Validate that the address and the selector are now enabled
        (addressOnList, checkSelectors) =
            sessionKeyPermissionsPlugin.getAccessControlEntry(address(account1), sessionKey1, address(counter1));
        assertTrue(addressOnList);
        assertTrue(checkSelectors);
        selectorOnList = sessionKeyPermissionsPlugin.isSelectorOnAccessControlList(
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
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error")
        );

        assertEq(counter1.number(), 2);
    }

    function test_sessionPerms_selectorDenyList() public {
        // Add the denylist
        bytes[] memory updates = new bytes[](3);
        updates[0] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.setAccessListType,
            (ISessionKeyPermissionsPlugin.ContractAccessControlType.DENYLIST)
        );
        updates[1] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.updateAccessListAddressEntry, (address(counter1), true, true)
        );
        updates[2] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.updateAccessListFunctionEntry,
            (address(counter1), Counter.increment.selector, true)
        );

        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Call should fail after adding the denylist
        _runSessionKeyExecUserOp(
            address(counter1),
            sessionKey1,
            sessionKey1Private,
            abi.encodeCall(Counter.increment, ()),
            0 wei,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error")
        );

        assertEq(counter1.number(), 1);

        // Call should succeed for function not on denylist
        _runSessionKeyExecUserOp(
            address(counter1), sessionKey1, sessionKey1Private, abi.encodeCall(Counter.setNumber, (5)), 0 wei, ""
        );

        assertEq(counter1.number(), 5);
    }

    function testFuzz_sessionKeyTimeRange(uint48 startTime, uint48 endTime) public {
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.updateTimeRange, (startTime, endTime));

        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

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
            (ISessionKeyPermissionsPlugin.ContractAccessControlType.NONE)
        );
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        (address sessionKey2, uint256 sessionKey2Private) = makeAddrAndKey("sessionKey2");

        // Add the session key to the account
        address[] memory keysToAdd = new address[](1);
        keysToAdd[0] = sessionKey2;

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateSessionKeys(
            keysToAdd, new SessionKeyPlugin.SessionKeyToRemove[](0)
        );

        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).rotateKey(sessionKey1, sessionKey2);

        // Attempting to use the previous key should fail
        _runSessionKeyExecUserOp(
            address(counter1),
            sessionKey1,
            sessionKey1Private,
            abi.encodeCall(Counter.increment, ()),
            0 wei,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error")
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
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Rotate the key
        address sessionKey2 = makeAddr("sessionKey2");

        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).rotateKey(sessionKey1, sessionKey2);

        // Check the rotated key's time range
        (uint48 returnedStartTime, uint48 returnedEndTime) =
            sessionKeyPermissionsPlugin.getKeyTimeRange(address(account1), sessionKey2);

        assertEq(returnedStartTime, startTime);
        assertEq(returnedEndTime, endTime);
    }

    function testFuzz_sessionKeyPermissions_setRequiredPaymaster(address requiredPaymaster) public {
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setRequiredPaymaster, (requiredPaymaster));

        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Check the required paymaster
        address returnedRequiredPaymaster =
            sessionKeyPermissionsPlugin.getRequiredPaymaster(address(account1), sessionKey1);
        assertEq(returnedRequiredPaymaster, requiredPaymaster);

        // Set the required paymaster to zero
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setRequiredPaymaster, (address(0)));
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Check the required paymaster
        returnedRequiredPaymaster =
            sessionKeyPermissionsPlugin.getRequiredPaymaster(address(account1), sessionKey1);
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
            (ISessionKeyPermissionsPlugin.ContractAccessControlType.NONE)
        );
        updates[1] = abi.encodeCall(ISessionKeyPermissionsUpdates.setNativeTokenSpendLimit, (type(uint256).max, 0));

        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

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
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates2);

        vm.prank(address(entryPoint));
        validationData = account1.validateUserOp(userOp, userOpHash, 0);

        if (requiredPaymaster == providedPaymaster || requiredPaymaster == address(0)) {
            // Assert that validation passes
            assertEq(uint160(validationData), 0);
        } else {
            // Assert that validation fails
            assertEq(uint160(validationData), 1);
        }
    }

    function test_sessionKeyPerms_requiredPaymaster_partialAddressFails() public {
        // Disable the allowlist
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.setAccessListType,
            (ISessionKeyPermissionsPlugin.ContractAccessControlType.NONE)
        );
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // create a paymaster address that would match, if right-padded with zeroes
        address paymasterAddr = 0x1234123412341234000000000000000000000000;
        // Add it
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setRequiredPaymaster, (paymasterAddr));
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

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
        vm.expectRevert(abi.encodeWithSelector(ISessionKeyPermissionsPlugin.InvalidPermissionsUpdate.selector));
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        updates[0] = hex"11223344"; // Invalid selector
        vm.expectRevert(abi.encodeWithSelector(ISessionKeyPermissionsPlugin.InvalidPermissionsUpdate.selector));
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);
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
}
