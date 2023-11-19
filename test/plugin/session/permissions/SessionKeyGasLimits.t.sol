// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Test, console} from "forge-std/Test.sol";

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
import {Call} from "../../../../src/interfaces/IStandardExecutor.sol";
import {FunctionReference, FunctionReferenceLib} from "../../../../src/libraries/FunctionReferenceLib.sol";

import {MultiOwnerMSCAFactory} from "../../../../src/factory/MultiOwnerMSCAFactory.sol";

contract SessionKeyGasLimitsTest is Test {
    using ECDSA for bytes32;

    IEntryPoint entryPoint;
    address payable beneficiary;

    MultiOwnerPlugin public multiOwnerPlugin;
    MultiOwnerMSCAFactory public factory;
    SessionKeyPlugin sessionKeyPlugin;
    SessionKeyPermissionsPlugin sessionKeyPermissionsPlugin;

    address owner1;
    uint256 owner1Key;
    UpgradeableModularAccount account1;

    address sessionKey1;
    uint256 sessionKey1Private;

    address recipient;

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));
        (owner1, owner1Key) = makeAddrAndKey("owner1");
        beneficiary = payable(makeAddr("beneficiary"));
        recipient = makeAddr("recipient");

        vm.deal(beneficiary, 1 wei);

        multiOwnerPlugin = new MultiOwnerPlugin();
        factory = new MultiOwnerMSCAFactory(
            address(this),
            address(multiOwnerPlugin),
            address(new UpgradeableModularAccount(entryPoint)),
            keccak256(abi.encode(multiOwnerPlugin.pluginManifest())),
            entryPoint
        );
        owner1 = makeAddr("owner");
        address[] memory owners = new address[](1);
        owners[0] = owner1;
        account1 = UpgradeableModularAccount(payable(factory.createAccount(0, owners)));

        vm.deal(address(account1), 100 ether);

        sessionKeyPlugin = new SessionKeyPlugin();
        sessionKeyPermissionsPlugin = new SessionKeyPermissionsPlugin();

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

        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(
            ISessionKeyPermissionsUpdates.setAccessListType,
            (ISessionKeyPermissionsPlugin.ContractAccessControlType.NONE)
        );
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);
    }

    function testFuzz_sessionKeyGasLimits_setLimits(uint256 limit, uint48 interval, uint48 timestamp) public {
        vm.warp(timestamp);

        // Assert that the limit starts out unset
        (ISessionKeyPermissionsPlugin.SpendLimitInfo memory spendLimitInfo,) =
            sessionKeyPermissionsPlugin.getGasSpendLimit(address(account1), sessionKey1);

        assertFalse(spendLimitInfo.hasLimit);
        assertEq(spendLimitInfo.limit, 0);
        assertEq(spendLimitInfo.refreshInterval, 0);
        assertEq(spendLimitInfo.limitUsed, 0);

        // Set the limit
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setGasSpendLimit, (limit, interval));
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Verify that the limit is set
        (spendLimitInfo,) = sessionKeyPermissionsPlugin.getGasSpendLimit(address(account1), sessionKey1);

        if (limit == type(uint256).max) {
            // If the limit is "set" to this value, it is just removed.
            // verify that the values are still as they were before.
            assertEq(spendLimitInfo.limit, 0);
            assertEq(spendLimitInfo.refreshInterval, 0);
            assertEq(spendLimitInfo.limitUsed, 0);
        } else {
            // The limit is actually set, verify that the values are as expected.
            assertTrue(spendLimitInfo.hasLimit);
            assertEq(spendLimitInfo.limit, limit);
            assertEq(spendLimitInfo.refreshInterval, interval);
            assertEq(spendLimitInfo.limitUsed, 0);
            if (interval == 0) {
                assertEq(spendLimitInfo.lastUsedTime, 0);
            } else {
                assertEq(spendLimitInfo.lastUsedTime, timestamp);
            }
        }
    }

    // gas limit zero
    function test_sessionKeyGasLimits_enforceLimit_none() public {
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setGasSpendLimit, (0 ether, 0 days));
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // A user op spending any gas should be rejected at this stage
        _runSessionKeyUserOp(
            50_000,
            150_000,
            1,
            200_000 wei,
            sessionKey1Private,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error")
        );
    }

    function testFuzz_sessionKeyGasLimits_nolimit(uint256 gasPrice) public {
        gasPrice = bound(gasPrice, 1 wei, 1_000_000_000 gwei);

        uint256 ethToSpend = 1_000_000 * gasPrice;

        // Extra padding amount to cover the duplicate requirement gas for validation
        vm.deal(address(account1), ethToSpend);

        _runSessionKeyUserOp(200_000, 800_000, gasPrice, ethToSpend, sessionKey1Private, "");
    }

    function test_sessionKeyGasLimits_enforceLimit_basic_single() public {
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setGasSpendLimit, (1 ether, 0 days));
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // A basic user op using 0.6 ether in gas should succeed
        _runSessionKeyUserOp(100_000, 500_000, 1_000 gwei, 0.6 ether, sessionKey1Private, "");

        // This usage update should be reflected in the limits
        (ISessionKeyPermissionsPlugin.SpendLimitInfo memory spendLimitInfo,) =
            sessionKeyPermissionsPlugin.getGasSpendLimit(address(account1), sessionKey1);
        assertTrue(spendLimitInfo.hasLimit);
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 0.6 ether);
        assertEq(spendLimitInfo.refreshInterval, 0);
        assertEq(spendLimitInfo.lastUsedTime, 0);

        // A basic user op using 0.6 ether in gas should now fail
        _runSessionKeyUserOp(
            100_000,
            500_000,
            1_000 gwei,
            0.6 ether,
            sessionKey1Private,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error")
        );
    }

    function test_sessionKeyGasLimits_exceedLimit_single() public {
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setGasSpendLimit, (1 ether, 0 days));
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // A basic user op using 1.2 ether in gas should fail
        _runSessionKeyUserOp(
            100_000,
            500_000,
            2_000 gwei,
            1.2 ether,
            sessionKey1Private,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error")
        );
    }

    function test_sessionKeyGasLimits_enforceLimit_basic_multipleInBundle() public {
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setGasSpendLimit, (1 ether, 0 days));
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Construct two user ops that, when bundled together, spend 0.8 ether
        UserOperation[] memory userOps = new UserOperation[](2);
        userOps[0] = _generateAndSignUserOp(
            100_000, 300_000, 1_000 gwei, 0.4 ether, sessionKey1Private, _wrapNonceWithAddr(0, sessionKey1)
        );
        userOps[1] = _generateAndSignUserOp(
            100_000, 300_000, 1_000 gwei, 0.4 ether, sessionKey1Private, _wrapNonceWithAddr(1, sessionKey1)
        );

        // Run the user ops
        entryPoint.handleOps(userOps, beneficiary);

        // This usage update should be reflected in the limits
        (ISessionKeyPermissionsPlugin.SpendLimitInfo memory spendLimitInfo,) =
            sessionKeyPermissionsPlugin.getGasSpendLimit(address(account1), sessionKey1);
        assertTrue(spendLimitInfo.hasLimit);
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 0.8 ether);
        assertEq(spendLimitInfo.refreshInterval, 0);
        assertEq(spendLimitInfo.lastUsedTime, 0);
    }

    function test_sessionKeyGasLimits_exceedLimit_multipleInBundle() public {
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setGasSpendLimit, (1 ether, 0 days));
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Construct two user ops that, when bundled together, spend 1.6 ether
        UserOperation[] memory userOps = new UserOperation[](2);
        userOps[0] = _generateAndSignUserOp(
            100_000, 300_000, 2_000 gwei, 0.8 ether, sessionKey1Private, _wrapNonceWithAddr(0, sessionKey1)
        );
        userOps[1] = _generateAndSignUserOp(
            100_000, 300_000, 2_000 gwei, 0.8 ether, sessionKey1Private, _wrapNonceWithAddr(1, sessionKey1)
        );

        // Run the user ops
        // The second op (index 1) should be the one that fails signature validation.
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 1, "AA24 signature error"));
        entryPoint.handleOps(userOps, beneficiary);

        // The lack of usage update should be reflected in the limits
        (ISessionKeyPermissionsPlugin.SpendLimitInfo memory spendLimitInfo,) =
            sessionKeyPermissionsPlugin.getGasSpendLimit(address(account1), sessionKey1);
        assertTrue(spendLimitInfo.hasLimit);
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 0 ether);
        assertEq(spendLimitInfo.refreshInterval, 0);
        assertEq(spendLimitInfo.lastUsedTime, 0);
    }

    function test_sessionKeyGasLimits_refreshInterval_inspectValidationData() public {
        // Pick a start time
        uint256 time0 = 1698708080;
        vm.warp(time0);

        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setGasSpendLimit, (1 ether, 1 days));
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // A basic user op using 0.6 ether in gas should succeed
        _runSessionKeyUserOp(100_000, 500_000, 1_000 gwei, 0.6 ether, sessionKey1Private, "");

        // This usage update should be reflected in the limits
        (ISessionKeyPermissionsPlugin.SpendLimitInfo memory spendLimitInfo,) =
            sessionKeyPermissionsPlugin.getGasSpendLimit(address(account1), sessionKey1);
        assertTrue(spendLimitInfo.hasLimit);
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 0.6 ether);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0);

        // Inspect the returned time range from validateUserOp to see the higher start time for the next interval.
        UserOperation memory userOp = _generateAndSignUserOp(
            100_000, 500_000, 1_000 gwei, 0.6 ether, sessionKey1Private, _wrapNonceWithAddr(0, sessionKey1)
        );
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        // NOTE: this causes the last used to advance, which is an intentional side effect of validation. Under
        // normal circumstances, if it is not yet due, the validation will revert by the EntryPoint. The account
        // protects from stray state updates by asserting that these calls only come from the entrypoint, but we
        // mock it here with vm.prank.
        uint256 validationData = account1.validateUserOp(userOp, userOpHash, 0);

        uint48 expectedStartTime = uint48(time0 + 1 days);
        uint48 actualStartTime = uint48(validationData >> 208);
        assertEq(actualStartTime, expectedStartTime);
    }

    function test_sessionKeyGasLimits_refreshInterval_single() public {
        // Pick a start time
        uint256 time0 = 1698708080;
        vm.warp(time0);

        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setGasSpendLimit, (1 ether, 1 days));
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // A basic user op using 0.6 ether in gas should succeed
        _runSessionKeyUserOp(100_000, 500_000, 1_000 gwei, 0.6 ether, sessionKey1Private, "");

        // This usage update should be reflected in the limits
        (ISessionKeyPermissionsPlugin.SpendLimitInfo memory spendLimitInfo,) =
            sessionKeyPermissionsPlugin.getGasSpendLimit(address(account1), sessionKey1);
        assertTrue(spendLimitInfo.hasLimit);
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 0.6 ether);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0);

        // Attempting to use another 0.6 ether now should fail

        _runSessionKeyUserOp(
            100_000,
            500_000,
            1_000 gwei,
            0.6 ether,
            sessionKey1Private,
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA22 expired or not due")
        );

        // Skip forward and run the user op

        skip(1 days + 1 minutes);
        _runSessionKeyUserOp(100_000, 500_000, 1_000 gwei, 0.6 ether, sessionKey1Private, "");

        // This usage update should be reflected in the limits
        (spendLimitInfo,) = sessionKeyPermissionsPlugin.getGasSpendLimit(address(account1), sessionKey1);

        assertTrue(spendLimitInfo.hasLimit);
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 0.6 ether);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        // The last used time SHOULD increment by the actual time passed, not just the interval, if the call
        // succeeded.
        assertEq(spendLimitInfo.lastUsedTime, time0 + 1 days + 1 minutes);
    }

    function test_sessionKeyGasLimits_refreshInterval_multipleInBundle() public {
        // Pick a start time
        uint256 time0 = 1698708080;
        vm.warp(time0);

        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setGasSpendLimit, (1 ether, 1 days));
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Use up 0.6 ether
        _runSessionKeyUserOp(100_000, 500_000, 1_000 gwei, 0.6 ether, sessionKey1Private, "");

        // Construct two user ops that, when bundled together, spend 0.8 ether

        UserOperation[] memory userOps = new UserOperation[](2);
        userOps[0] = _generateAndSignUserOp(
            100_000, 300_000, 1_000 gwei, 0.4 ether, sessionKey1Private, _wrapNonceWithAddr(1, sessionKey1)
        );
        userOps[1] = _generateAndSignUserOp(
            100_000, 300_000, 1_000 gwei, 0.4 ether, sessionKey1Private, _wrapNonceWithAddr(2, sessionKey1)
        );

        // Run the user ops. This should fail now, with the second one's start time being later.
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 1, "AA22 expired or not due"));
        entryPoint.handleOps(userOps, beneficiary);

        // Usage should still be at 0.6
        (ISessionKeyPermissionsPlugin.SpendLimitInfo memory spendLimitInfo,) =
            sessionKeyPermissionsPlugin.getGasSpendLimit(address(account1), sessionKey1);
        assertTrue(spendLimitInfo.hasLimit);
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 0.6 ether);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0);

        // Skip forward and run the user ops again. This should succeed now.
        skip(1 days + 1 minutes);

        entryPoint.handleOps(userOps, beneficiary);

        // Usage should now be at 0.4 (odd case, since the first one fits in the old interval, but the second one
        // doesn't.

        (spendLimitInfo,) = sessionKeyPermissionsPlugin.getGasSpendLimit(address(account1), sessionKey1);
        assertTrue(spendLimitInfo.hasLimit);
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 0.4 ether);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        // The last used time SHOULD increment by the actual time passed, not just the interval, if the call
        // succeeded.
        assertEq(spendLimitInfo.lastUsedTime, time0 + 1 days + 1 minutes);
    }

    function test_sessionKeyGasLimits_refreshInterval_multipleInBundle_tryExceedFails() public {
        // Pick a start time
        uint256 time0 = 1698708080;
        vm.warp(time0);

        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setGasSpendLimit, (1 ether, 1 days));
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Use up 0.8 ether
        _runSessionKeyUserOp(100_000, 700_000, 1_000 gwei, 0.8 ether, sessionKey1Private, "");

        // Construct three user ops that each cost 0.4 ether, and when bundled together, spend 1.2 ether

        UserOperation[] memory userOps = new UserOperation[](3);
        userOps[0] = _generateAndSignUserOp(
            100_000, 300_000, 1_000 gwei, 0.4 ether, sessionKey1Private, _wrapNonceWithAddr(1, sessionKey1)
        );
        userOps[1] = _generateAndSignUserOp(
            100_000, 300_000, 1_000 gwei, 0.4 ether, sessionKey1Private, _wrapNonceWithAddr(2, sessionKey1)
        );
        userOps[2] = _generateAndSignUserOp(
            100_000, 300_000, 1_000 gwei, 0.4 ether, sessionKey1Private, _wrapNonceWithAddr(3, sessionKey1)
        );

        // Run the user ops. This should fail now, since even the first one exceeds the spend limit
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA22 expired or not due"));
        entryPoint.handleOps(userOps, beneficiary);

        // Usage should still be at 0.8
        (ISessionKeyPermissionsPlugin.SpendLimitInfo memory spendLimitInfo,) =
            sessionKeyPermissionsPlugin.getGasSpendLimit(address(account1), sessionKey1);
        assertTrue(spendLimitInfo.hasLimit);
        assertEq(spendLimitInfo.limit, 1 ether);
        assertEq(spendLimitInfo.limitUsed, 0.8 ether);
        assertEq(spendLimitInfo.refreshInterval, 1 days);
        assertEq(spendLimitInfo.lastUsedTime, time0);

        // Skip forward and try to run the user ops again. This should still fail, since the third one
        // would exceed the next spend limit window. This is somewhat counterintuitive, since it would seem like
        // 0.8 + 1.2 ether should fit in two 1 ether intervals. However, the first user op in the 1.2 ether bundler
        // starts a new interval and sets the usage to 0.4, meaning the remainder from the previous interval is not
        // actually usable.
        skip(1 days + 1 minutes);

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 2, "AA24 signature error"));
        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_sessionKeyGasLimits_refreshInterval_resetFlagTracking() public {
        // Pick a start time
        uint256 time0 = 1698708080;
        vm.warp(time0);

        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setGasSpendLimit, (1 ether, 1 days));
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // Use up 0.6 ether
        _runSessionKeyUserOp(100_000, 500_000, 1_000 gwei, 0.6 ether, sessionKey1Private, "");

        // Try to use up 0.6 ether again, but with a call that reverts during execution.

        UserOperation[] memory userOps = new UserOperation[](1);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(this), value: 0 ether, data: abi.encodeWithSelector(bytes4(0x11223344))});
        userOps[0] = _generateAndSignUserOpWithCustomExecutions(
            100_000, 500_000, 1_000 gwei, 0.6 ether, calls, sessionKey1Private, _wrapNonceWithAddr(1, sessionKey1)
        );

        skip(1 days + 1 minutes);
        entryPoint.handleOps(userOps, beneficiary);

        (, bool shouldReset) = sessionKeyPermissionsPlugin.getGasSpendLimit(address(account1), sessionKey1);

        assertTrue(shouldReset, "Session key should report that it needs to be reset");
    }

    function test_sessionKeyGasLimits_refreshInterval_resetFlag_fixWithExtraUO() public {
        // Run the above test
        test_sessionKeyGasLimits_refreshInterval_resetFlagTracking();

        // Now, attempt to fix it by running a user op that does not exceed the limit, does not revert in
        // execution, and resets the flag.

        // Use up 0.6 ether
        _runSessionKeyUserOp(100_000, 300_000, 1_000 gwei, 0.4 ether, sessionKey1Private, "");

        // The reset flag should now be false
        (ISessionKeyPermissionsPlugin.SpendLimitInfo memory spendLimitInfo, bool shouldReset) =
            sessionKeyPermissionsPlugin.getGasSpendLimit(address(account1), sessionKey1);

        assertFalse(shouldReset, "Session key should report that it does not need to be reset");
        assertEq(spendLimitInfo.limitUsed, 1 ether);
        assertEq(spendLimitInfo.lastUsedTime, block.timestamp);
    }

    function test_sessionKeyGasLimits_refreshInterval_resetFlag_fixWithOwnerReset() public {
        // Run the above test
        test_sessionKeyGasLimits_refreshInterval_resetFlagTracking();

        // Now, attempt to fix it by calling the update function with the same parameters as before.
        bytes[] memory updates = new bytes[](1);
        updates[0] = abi.encodeCall(ISessionKeyPermissionsUpdates.setGasSpendLimit, (1 ether, 1 days));
        vm.prank(owner1);
        SessionKeyPermissionsPlugin(address(account1)).updateKeyPermissions(sessionKey1, updates);

        // The reset flag should now be false
        (ISessionKeyPermissionsPlugin.SpendLimitInfo memory spendLimitInfo, bool shouldReset) =
            sessionKeyPermissionsPlugin.getGasSpendLimit(address(account1), sessionKey1);

        assertFalse(shouldReset, "Session key should report that it does not need to be reset");
        assertEq(spendLimitInfo.limitUsed, 0.6 ether);
        assertEq(spendLimitInfo.lastUsedTime, block.timestamp);
    }

    function test_sessionKeyGasLimits_refreshInterval_resetFlag_fixWithPublicReset() public {
        // Run the above test
        test_sessionKeyGasLimits_refreshInterval_resetFlagTracking();

        // Now, attempt to fix it by calling the public reset function
        sessionKeyPermissionsPlugin.resetSessionKeyGasLimitTimestamp(address(account1), sessionKey1);

        // The reset flag should now be false
        (ISessionKeyPermissionsPlugin.SpendLimitInfo memory spendLimitInfo, bool shouldReset) =
            sessionKeyPermissionsPlugin.getGasSpendLimit(address(account1), sessionKey1);

        assertFalse(shouldReset, "Session key should report that it does not need to be reset");
        assertEq(spendLimitInfo.limitUsed, 0.6 ether);
        assertEq(spendLimitInfo.lastUsedTime, block.timestamp);
    }

    function _getMaxGasCostPerUserOp(UserOperation memory userOp) internal pure returns (uint256) {
        uint256 multiplier = userOp.paymasterAndData.length > 0 ? 3 : 1;
        uint256 maxGasFee = (
            userOp.callGasLimit + userOp.verificationGasLimit * multiplier + userOp.preVerificationGas
        ) * userOp.maxFeePerGas;
        return maxGasFee;
    }

    function _generateAndSignUserOp(
        uint256 callGasLimit,
        uint256 verificationGasLimit,
        uint256 maxFeePerGas,
        uint256 expectedEtherValue,
        uint256 sessionKeyPrivate,
        uint256 nonce
    ) internal returns (UserOperation memory) {
        address sessionKey = vm.addr(sessionKeyPrivate);

        // Just creates a dummy call, since the values being checked are only in the user op's gas fields.
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: recipient, value: 0 ether, data: ""});

        UserOperation memory userOp = UserOperation({
            sender: address(account1),
            nonce: nonce,
            initCode: "",
            callData: abi.encodeCall(ISessionKeyPlugin.executeWithSessionKey, (calls, sessionKey)),
            callGasLimit: callGasLimit,
            verificationGasLimit: verificationGasLimit,
            preVerificationGas: 0,
            maxFeePerGas: maxFeePerGas,
            maxPriorityFeePerGas: 0,
            paymasterAndData: "",
            signature: ""
        });

        // Double-check that the parameters given actually result in a expected native token usage amount

        assertEq(
            _getMaxGasCostPerUserOp(userOp),
            expectedEtherValue,
            "Mismatch between expect gas fee and actual gas fee"
        );

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPrivate, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        return userOp;
    }

    function _generateAndSignUserOpWithCustomExecutions(
        uint256 callGasLimit,
        uint256 verificationGasLimit,
        uint256 maxFeePerGas,
        uint256 expectedEtherValue,
        Call[] memory calls,
        uint256 sessionKeyPrivate,
        uint256 nonce
    ) internal returns (UserOperation memory) {
        address sessionKey = vm.addr(sessionKeyPrivate);

        UserOperation memory userOp = UserOperation({
            sender: address(account1),
            nonce: nonce,
            initCode: "",
            callData: abi.encodeCall(ISessionKeyPlugin.executeWithSessionKey, (calls, sessionKey)),
            callGasLimit: callGasLimit,
            verificationGasLimit: verificationGasLimit,
            preVerificationGas: 0,
            maxFeePerGas: maxFeePerGas,
            maxPriorityFeePerGas: 0,
            paymasterAndData: "",
            signature: ""
        });

        // Double-check that the parameters given actually result in a expected native token usage amount

        assertEq(
            _getMaxGasCostPerUserOp(userOp),
            expectedEtherValue,
            "Mismatch between expect gas fee and actual gas fee"
        );

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPrivate, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        return userOp;
    }

    function _runSessionKeyUserOp(
        uint256 callGasLimit,
        uint256 verificationGasLimit,
        uint256 maxFeePerGas,
        uint256 expectedEtherValue,
        uint256 sessionKeyPrivate,
        bytes memory expectedError
    ) internal {
        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = _generateAndSignUserOp(
            callGasLimit,
            verificationGasLimit,
            maxFeePerGas,
            expectedEtherValue,
            sessionKeyPrivate,
            entryPoint.getNonce(address(account1), uint192(uint160(vm.addr(sessionKeyPrivate))))
        );

        if (expectedError.length > 0) {
            vm.expectRevert(expectedError);
        }
        entryPoint.handleOps(userOps, beneficiary);
    }

    function _wrapNonceWithAddr(uint64 nonce, address addr) internal pure returns (uint256) {
        return nonce | uint256(uint160(addr)) << 64;
    }
}