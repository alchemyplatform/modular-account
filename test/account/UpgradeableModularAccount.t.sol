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

import {Test, console} from "forge-std/Test.sol";

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {UserOperation} from "modular-account-libs/interfaces/UserOperation.sol";
import {IPlugin, PluginManifest} from "modular-account-libs/interfaces/IPlugin.sol";
import {FunctionReference, IPluginManager} from "modular-account-libs/interfaces/IPluginManager.sol";
import {Call} from "modular-account-libs/interfaces/IStandardExecutor.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {AccountExecutor} from "../../src/account/AccountExecutor.sol";
import {PluginManagerInternals} from "../../src/account/PluginManagerInternals.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerModularAccountFactory} from "../../src/factory/MultiOwnerModularAccountFactory.sol";
import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";
import {IAccountInitializable} from "../../src/interfaces/IAccountInitializable.sol";
import {IMultiOwnerPlugin} from "../../src/plugins/owner/IMultiOwnerPlugin.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";
import {SessionKeyPlugin} from "../../src/plugins/session/SessionKeyPlugin.sol";
import {Counter} from "../mocks/Counter.sol";
import {MockPlugin} from "../mocks/MockPlugin.sol";

contract UpgradeableModularAccountTest is Test {
    using ECDSA for bytes32;

    IEntryPoint public entryPoint;
    address payable public beneficiary;
    MultiOwnerPlugin public multiOwnerPlugin;
    SessionKeyPlugin public sessionKeyPlugin;
    MultiOwnerModularAccountFactory public factory;
    address public accountImplementation;

    address public owner1;
    uint256 public owner1Key;
    UpgradeableModularAccount public account1;

    address public owner2;
    uint256 public owner2Key;
    UpgradeableModularAccount public account2;

    address[] public owners1;
    address[] public owners2;

    address public ethRecipient;
    Counter public counter;
    PluginManifest public manifest;

    uint256 public constant CALL_GAS_LIMIT = 500000;
    uint256 public constant VERIFICATION_GAS_LIMIT = 2000000;

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));
        (owner1, owner1Key) = makeAddrAndKey("owner1");
        beneficiary = payable(makeAddr("beneficiary"));
        vm.deal(beneficiary, 1 wei);

        multiOwnerPlugin = new MultiOwnerPlugin();
        sessionKeyPlugin = new SessionKeyPlugin();
        accountImplementation = address(new UpgradeableModularAccount(entryPoint));
        bytes32 manifestHash = keccak256(abi.encode(multiOwnerPlugin.pluginManifest()));
        factory = new MultiOwnerModularAccountFactory(
            address(this), address(multiOwnerPlugin), accountImplementation, manifestHash, entryPoint
        );

        // Compute counterfactual address
        owners1 = new address[](1);
        owners1[0] = owner1;
        account1 = UpgradeableModularAccount(payable(factory.getAddress(0, owners1)));
        vm.deal(address(account1), 100 ether);

        // Pre-deploy account two for different gas estimates
        (owner2, owner2Key) = makeAddrAndKey("owner2");
        owners2 = new address[](1);
        owners2[0] = owner2;
        account2 = UpgradeableModularAccount(payable(factory.createAccount(0, owners2)));
        vm.deal(address(account2), 100 ether);

        ethRecipient = makeAddr("ethRecipient");
        vm.deal(ethRecipient, 1 wei);
        counter = new Counter();
        counter.increment(); // amoritze away gas cost of zero->nonzero transition
    }

    function test_deployAccount() public {
        factory.createAccount(0, owners1);
    }

    function test_initialize_revertArrayLengthMismatch() public {
        ERC1967Proxy account = new ERC1967Proxy{salt: ""}(accountImplementation, "");
        address[] memory plugins = new address[](2);
        bytes memory pluginInitData = abi.encode(new bytes32[](1), new bytes[](1));
        vm.expectRevert(PluginManagerInternals.ArrayLengthMismatch.selector);
        IAccountInitializable(address(account)).initialize(plugins, pluginInitData);

        pluginInitData = abi.encode(new bytes32[](2), new bytes[](1));
        vm.expectRevert(PluginManagerInternals.ArrayLengthMismatch.selector);
        IAccountInitializable(address(account)).initialize(plugins, pluginInitData);
    }

    function test_basicUserOp() public {
        address[] memory owners = new address[](1);
        owners[0] = owner2;
        UserOperation memory userOp = UserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: abi.encodePacked(address(factory), abi.encodeCall(factory.createAccount, (0, owners1))),
            callData: abi.encodeCall(MultiOwnerPlugin.updateOwners, (owners, new address[](0))),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_standardExecuteEthSend() public {
        address payable recipient = payable(makeAddr("recipient"));

        UserOperation memory userOp = UserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: abi.encodePacked(address(factory), abi.encodeCall(factory.createAccount, (0, owners1))),
            callData: abi.encodeCall(UpgradeableModularAccount(payable(account1)).execute, (recipient, 1 wei, "")),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(recipient.balance, 1 wei);
    }

    function test_postDeploy_ethSend() public {
        UserOperation memory userOp = UserOperation({
            sender: address(account2),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(UpgradeableModularAccount.execute, (ethRecipient, 1 wei, "")),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 1,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(ethRecipient.balance, 2 wei);
    }

    function test_debug_upgradeableModularAccount_storageAccesses() public {
        UserOperation memory userOp = UserOperation({
            sender: address(account2),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(UpgradeableModularAccount.execute, (ethRecipient, 1 wei, "")),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 1,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        vm.record();
        entryPoint.handleOps(userOps, beneficiary);
        _printStorageReadsAndWrites(address(account2));
    }

    function test_contractInteraction() public {
        UserOperation memory userOp = UserOperation({
            sender: address(account2),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(
                UpgradeableModularAccount.execute, (address(counter), 0, abi.encodeCall(counter.increment, ()))
            ),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 1,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(counter.number(), 2);
    }

    function test_batchExecute() public {
        // Performs both an eth send and a contract interaction with counter
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: ethRecipient, value: 1 wei, data: ""});
        calls[1] = Call({target: address(counter), value: 0, data: abi.encodeCall(counter.increment, ())});

        UserOperation memory userOp = UserOperation({
            sender: address(account2),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(UpgradeableModularAccount(payable(account2)).executeBatch, (calls)),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 1,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(counter.number(), 2);
        assertEq(ethRecipient.balance, 2 wei);
    }

    // runtime validation tests
    function test_runtime_standardExecuteEthSend() public {
        factory.createAccount(0, owners1);
        address payable recipient = payable(makeAddr("recipient"));
        uint256 balBefore = recipient.balance;

        vm.startPrank(owner1);
        UpgradeableModularAccount(payable(account1)).execute(recipient, 1 wei, "");
        assertEq(recipient.balance, balBefore + 1 wei);
    }

    function test_runtime_debug_upgradeableModularAccount_storageAccesses() public {
        vm.startPrank(owner2);
        UpgradeableModularAccount(payable(account2)).execute(ethRecipient, 1 wei, "");
        _printStorageReadsAndWrites(address(account2));
    }

    function test_runtime_contractInteraction() public {
        factory.createAccount(0, owners1);
        uint256 valueBefore = counter.number();

        vm.startPrank(owner1);
        UpgradeableModularAccount(payable(account1)).execute(
            address(counter), 0, abi.encodeCall(counter.increment, ())
        );
        assertEq(counter.number(), valueBefore + 1);
    }

    function test_runtime_revertPluginCall() public {
        factory.createAccount(0, owners1);

        vm.startPrank(owner1);

        vm.expectRevert(
            abi.encodeWithSelector(AccountExecutor.PluginCallDenied.selector, address(multiOwnerPlugin))
        );
        UpgradeableModularAccount(payable(account1)).execute(
            address(multiOwnerPlugin), 0, abi.encodeCall(MultiOwnerPlugin.ownersOf, (address(account1)))
        );

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(multiOwnerPlugin), value: 1 wei, data: ""});
        vm.expectRevert(
            abi.encodeWithSelector(AccountExecutor.PluginCallDenied.selector, address(multiOwnerPlugin))
        );
        UpgradeableModularAccount(payable(account1)).executeBatch(calls);
    }

    function test_runtime_batchExecute() public {
        // Performs both an eth send and a contract interaction with counter
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: ethRecipient, value: 1 wei, data: ""});
        calls[1] = Call({target: address(counter), value: 0, data: abi.encodeCall(counter.increment, ())});
        uint256 balBefore = ethRecipient.balance;

        vm.startPrank(owner2);
        UpgradeableModularAccount(payable(account2)).executeBatch(calls);
        assertEq(counter.number(), 2);
        assertEq(ethRecipient.balance, balBefore + 1 wei);
    }

    function testFuzz_runtime_revert(bytes memory revertReason) public {
        vm.startPrank(owner2);

        bytes memory callData = abi.encodeCall(UpgradeableModularAccount.execute, (beneficiary, 0 wei, ""));

        vm.mockCallRevert(
            address(multiOwnerPlugin),
            abi.encodeCall(
                IPlugin.runtimeValidationFunction,
                (uint8(IMultiOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF), owner2, 0, callData)
            ),
            revertReason
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.RuntimeValidationFunctionReverted.selector,
                (address(multiOwnerPlugin)),
                uint8(IMultiOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF),
                revertReason
            )
        );
        account2.execute(beneficiary, 0 wei, "");
    }

    function test_view_entryPoint() public {
        factory.createAccount(0, owners1);

        assertEq(address(UpgradeableModularAccount(payable(account1)).entryPoint()), address(entryPoint));
    }

    function test_view_getNonce() public {
        factory.createAccount(0, owners1);

        assertEq(UpgradeableModularAccount(payable(account1)).getNonce(), 0);

        UserOperation memory userOp = UserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(UpgradeableModularAccount.execute, (ethRecipient, 1 wei, "")),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 1,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(UpgradeableModularAccount(payable(account1)).getNonce(), 1);
    }

    function test_validateUserOp_revertNotFromEntryPoint() public {
        UserOperation memory userOp = UserOperation({
            sender: address(account2),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(UpgradeableModularAccount.execute, (ethRecipient, 1 wei, "")),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 1,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        vm.expectRevert(UpgradeableModularAccount.UserOpNotFromEntryPoint.selector);
        account2.validateUserOp(userOp, userOpHash, 0);
    }

    function test_validateUserOp_revertUnrecognizedFunction() public {
        // Invalid calldata of length 2.
        bytes memory callData = hex"12";

        UserOperation memory userOp = UserOperation({
            sender: address(account2),
            nonce: 0,
            initCode: "",
            callData: callData,
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 1,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        vm.startPrank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(UpgradeableModularAccount.UnrecognizedFunction.selector, bytes4(callData))
        );
        account2.validateUserOp(userOp, userOpHash, 0);
        vm.stopPrank();
    }

    function test_validateUserOp_revertFunctionMissing() public {
        PluginManifest memory m;
        m.executionFunctions = new bytes4[](1);
        bytes4 fooSelector = bytes4(keccak256("foo()"));
        m.executionFunctions[0] = fooSelector;
        MockPlugin plugin = new MockPlugin(m);
        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.startPrank(owner2);
        // Install a plugin with execution function foo() that does not have an associated user op validation
        // function.
        IPluginManager(account2).installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
        vm.stopPrank();

        UserOperation memory userOp = UserOperation({
            sender: address(account2),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(fooSelector),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 1,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        vm.startPrank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(UpgradeableModularAccount.UserOpValidationFunctionMissing.selector, fooSelector)
        );
        account2.validateUserOp(userOp, userOpHash, 0);
        vm.stopPrank();
    }

    // Internal Functions

    function _printStorageReadsAndWrites(address addr) internal {
        (bytes32[] memory accountReads, bytes32[] memory accountWrites) = vm.accesses(addr);
        for (uint256 i = 0; i < accountWrites.length; i++) {
            bytes32 valWritten = vm.load(addr, accountWrites[i]);
            // solhint-disable-next-line no-console
            console.log(
                string.concat("write loc: ", vm.toString(accountWrites[i]), " val: ", vm.toString(valWritten))
            );
        }

        for (uint256 i = 0; i < accountReads.length; i++) {
            bytes32 valRead = vm.load(addr, accountReads[i]);
            // solhint-disable-next-line no-console
            console.log(string.concat("read: ", vm.toString(accountReads[i]), " val: ", vm.toString(valRead)));
        }
    }
}
