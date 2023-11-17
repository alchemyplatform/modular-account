// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";

import {UpgradeableModularAccount} from "../../../src/account/UpgradeableModularAccount.sol";
import {BasePlugin} from "../../../src/plugins/BasePlugin.sol";
import {IMultiOwnerPlugin} from "../../../src/plugins/owner/IMultiOwnerPlugin.sol";
import {MultiOwnerPlugin} from "../../../src/plugins/owner/MultiOwnerPlugin.sol";
import {ISessionKeyPlugin} from "../../../src/plugins/session/ISessionKeyPlugin.sol";
import {SessionKeyPlugin} from "../../../src/plugins/session/SessionKeyPlugin.sol";
import {IEntryPoint} from "../../../src/interfaces/erc4337/IEntryPoint.sol";
import {UserOperation} from "../../../src/interfaces/erc4337/UserOperation.sol";
import {IPluginManager} from "../../../src/interfaces/IPluginManager.sol";
import {FunctionReference, FunctionReferenceLib} from "../../../src/libraries/FunctionReferenceLib.sol";
import {Call} from "../../../src/interfaces/IStandardExecutor.sol";

import {MultiOwnerMSCAFactory} from "../../../src/factory/MultiOwnerMSCAFactory.sol";

contract SessionKeyPluginWithMultiOwnerTest is Test {
    using ECDSA for bytes32;

    IEntryPoint entryPoint;
    address payable beneficiary;
    MultiOwnerPlugin multiOwnerPlugin;
    MultiOwnerMSCAFactory factory;
    SessionKeyPlugin sessionKeyPlugin;

    address owner1;
    uint256 owner1Key;
    address[] public owners;
    UpgradeableModularAccount account1;

    uint256 constant CALL_GAS_LIMIT = 70000;
    uint256 constant VERIFICATION_GAS_LIMIT = 1000000;

    address payable recipient;

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));
        (owner1, owner1Key) = makeAddrAndKey("owner1");
        beneficiary = payable(makeAddr("beneficiary"));
        recipient = payable(makeAddr("recipient"));
        vm.deal(beneficiary, 1 wei);
        vm.deal(recipient, 1 wei);

        multiOwnerPlugin = new MultiOwnerPlugin();
        address impl = address(new UpgradeableModularAccount(entryPoint));

        factory =
        new MultiOwnerMSCAFactory(address(this), address(multiOwnerPlugin), impl, keccak256(abi.encode(multiOwnerPlugin.pluginManifest())), entryPoint);

        sessionKeyPlugin = new SessionKeyPlugin();

        owners = new address[](1);
        owners[0] = owner1;
        account1 = UpgradeableModularAccount(payable(factory.createAccount(0, owners)));
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
    }

    function test_sessionKey_addKeySuccess() public {
        address[] memory sessionKeysToAdd = new address[](1);
        sessionKeysToAdd[0] = makeAddr("sessionKey1");

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateSessionKeys(
            sessionKeysToAdd, new SessionKeyPlugin.SessionKeyToRemove[](0)
        );

        address[] memory sessionKeys = SessionKeyPlugin(address(account1)).getSessionKeys();
        assertEq(sessionKeys.length, 1);
        assertEq(sessionKeys[0], sessionKeysToAdd[0]);
    }

    function test_sessionKey_addAndRemoveKeys() public {
        address[] memory sessionKeysToAdd = new address[](2);
        sessionKeysToAdd[0] = makeAddr("sessionKey1");
        sessionKeysToAdd[1] = makeAddr("sessionKey2");

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateSessionKeys(
            sessionKeysToAdd, new SessionKeyPlugin.SessionKeyToRemove[](0)
        );

        SessionKeyPlugin.SessionKeyToRemove[] memory sessionKeysToRemove =
            new ISessionKeyPlugin.SessionKeyToRemove[](1);
        sessionKeysToRemove[0] = ISessionKeyPlugin.SessionKeyToRemove({
            sessionKey: sessionKeysToAdd[0],
            predecessor: bytes32(bytes20(sessionKeysToAdd[1]))
        });
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateSessionKeys(new address[](0), sessionKeysToRemove);

        address[] memory sessionKeys = SessionKeyPlugin(address(account1)).getSessionKeys();
        assertEq(sessionKeys.length, 1);
        assertEq(sessionKeys[0], sessionKeysToAdd[1]);
    }

    function test_sessionKey_useSessionKey() public {
        address[] memory sessionKeysToAdd = new address[](1);
        (address sessionKey, uint256 sessionKeyPrivate) = makeAddrAndKey("sessionKey1");
        sessionKeysToAdd[0] = sessionKey;

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateSessionKeys(
            sessionKeysToAdd, new SessionKeyPlugin.SessionKeyToRemove[](0)
        );

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: recipient, value: 1 wei, data: ""});

        UserOperation memory userOp = UserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(
                ISessionKeyPlugin(address(sessionKeyPlugin)).executeWithSessionKey, (calls, sessionKey)
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

    function testFuzz_sessionKey_userOpValidation_invalid(uint8 sessionKeysSeed, uint64 signerSeed) public {
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

        vm.prank(address(account1));
        uint256 result = sessionKeyPlugin.userOpValidationFunction(
            uint8(ISessionKeyPlugin.FunctionId.USER_OP_VALIDATION_SESSION_KEY), userOp, userOpHash
        );

        assertEq(result, 1);
    }

    function testFuzz_sessionKey_invalidFunctionId(uint8 functionId, UserOperation memory userOp) public {
        vm.assume(functionId != uint8(ISessionKeyPlugin.FunctionId.USER_OP_VALIDATION_SESSION_KEY));

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        vm.expectRevert(abi.encodeWithSelector(BasePlugin.NotImplemented.selector));
        sessionKeyPlugin.userOpValidationFunction(functionId, userOp, userOpHash);
    }

    // getPredecessor test case with sentinel value as predecessor
    function test_sessionKey_getPredecessor_sentinel() public {
        address[] memory sessionKeysToAdd = new address[](2);
        sessionKeysToAdd[0] = makeAddr("sessionKey1");
        sessionKeysToAdd[1] = makeAddr("sessionKey2");

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateSessionKeys(
            sessionKeysToAdd, new SessionKeyPlugin.SessionKeyToRemove[](0)
        );

        SessionKeyPlugin.SessionKeyToRemove[] memory sessionKeysToRemove =
            new ISessionKeyPlugin.SessionKeyToRemove[](1);
        sessionKeysToRemove[0] = ISessionKeyPlugin.SessionKeyToRemove({
            sessionKey: sessionKeysToAdd[0],
            predecessor: sessionKeyPlugin.findPredecessor(address(account1), sessionKeysToAdd[0])
        });
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateSessionKeys(new address[](0), sessionKeysToRemove);

        address[] memory sessionKeys = SessionKeyPlugin(address(account1)).getSessionKeys();
        assertEq(sessionKeys.length, 1);
        assertEq(sessionKeys[0], sessionKeysToAdd[1]);
    }

    // getPredecessor test case with address value as predecessor
    function test_sessionKey_getPredecessor_address() public {
        address[] memory sessionKeysToAdd = new address[](2);
        sessionKeysToAdd[0] = makeAddr("sessionKey1");
        sessionKeysToAdd[1] = makeAddr("sessionKey2");

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateSessionKeys(
            sessionKeysToAdd, new SessionKeyPlugin.SessionKeyToRemove[](0)
        );

        SessionKeyPlugin.SessionKeyToRemove[] memory sessionKeysToRemove =
            new ISessionKeyPlugin.SessionKeyToRemove[](1);
        sessionKeysToRemove[0] = ISessionKeyPlugin.SessionKeyToRemove({
            sessionKey: sessionKeysToAdd[1],
            predecessor: sessionKeyPlugin.findPredecessor(address(account1), sessionKeysToAdd[1])
        });
        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateSessionKeys(new address[](0), sessionKeysToRemove);

        address[] memory sessionKeys = SessionKeyPlugin(address(account1)).getSessionKeys();
        assertEq(sessionKeys.length, 1);
        assertEq(sessionKeys[0], sessionKeysToAdd[0]);
    }

    function test_sessionKey_getPredecessor_missing() public {
        address[] memory sessionKeysToAdd = new address[](1);
        sessionKeysToAdd[0] = makeAddr("sessionKey1");

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateSessionKeys(
            sessionKeysToAdd, new SessionKeyPlugin.SessionKeyToRemove[](0)
        );

        address key2 = makeAddr("sessionKey2");
        vm.expectRevert(abi.encodeWithSelector(ISessionKeyPlugin.SessionKeyNotFound.selector, key2));
        sessionKeyPlugin.findPredecessor(address(account1), key2);
    }

    function test_sessionKey_doesNotContainSentinelValue() public {
        assertFalse(sessionKeyPlugin.isSessionKeyOf(address(account1), address(1)));

        address[] memory sessionKeysToAdd = new address[](1);
        sessionKeysToAdd[0] = makeAddr("sessionKey1");

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateSessionKeys(
            sessionKeysToAdd, new SessionKeyPlugin.SessionKeyToRemove[](0)
        );

        assertFalse(sessionKeyPlugin.isSessionKeyOf(address(account1), address(1)));
    }

    function _createSessionKeys(uint8 seed) internal returns (uint256[] memory privateKeys) {
        uint256 addressCount = (seed % 16) + 1;

        address[] memory sessionKeysToAdd = new address[](addressCount);
        privateKeys = new uint256[](addressCount);
        for (uint256 i = 0; i < addressCount; i++) {
            (sessionKeysToAdd[i], privateKeys[i]) = makeAddrAndKey(string.concat("sessionKey", vm.toString(i)));
        }

        vm.prank(owner1);
        SessionKeyPlugin(address(account1)).updateSessionKeys(
            sessionKeysToAdd, new SessionKeyPlugin.SessionKeyToRemove[](0)
        );
    }
}
