// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {ModuleEntity} from "../../src/libraries/ModuleEntityLib.sol";

import {ModuleEntityLib} from "../../src/libraries/ModuleEntityLib.sol";

import {HookConfigLib} from "../../src/libraries/HookConfigLib.sol";
import {ValidationConfigLib} from "../../src/libraries/ValidationConfigLib.sol";

import {NativeTokenLimitModule} from "../../src/modules/permissions/NativeTokenLimitModule.sol";

import {MockDeployment} from "../mocks/MockDeployment.sol";
import {MockModule} from "../mocks/modules/MockModule.sol";
import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {Call, IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract NativeTokenLimitModuleTest is AccountTestBase {
    address public recipient = address(1);
    address payable public bundler = payable(address(2));
    ExecutionManifest internal _m;
    MockModule public validationModule = new MockModule(_m);
    ModuleEntity public validationFunction;

    ModularAccount public acct;
    NativeTokenLimitModule public module = new NativeTokenLimitModule();
    uint256 public spendLimit = 10 ether;
    uint32 public entityId = 0;

    function setUp() public override {
        // Set up a validator with hooks from the gas spend limit module attached

        acct = factory.createAccount(address(this), 0, entityId);

        vm.deal(address(acct), 10 ether);

        ModuleEntity[] memory preValidationHooks = new ModuleEntity[](1);
        preValidationHooks[0] = ModuleEntityLib.pack(address(module), entityId);

        bytes[] memory hooks = new bytes[](2);
        hooks[0] =
            abi.encodePacked(HookConfigLib.packValidationHook({_module: address(module), _entityId: entityId}));
        // No init data for pre validation

        hooks[1] = abi.encodePacked(
            HookConfigLib.packExecHook({
                _module: address(module),
                _entityId: entityId,
                _hasPre: true,
                _hasPost: false
            }),
            abi.encode(entityId, spendLimit)
        );

        vm.prank(address(acct));
        acct.installValidation(
            ValidationConfigLib.pack(address(validationModule), entityId, true, true, true),
            new bytes4[](0),
            new bytes(0),
            hooks
        );

        validationFunction = ModuleEntityLib.pack(address(validationModule), entityId);
    }

    function _getExecuteWithValue(uint256 value) internal view returns (bytes memory) {
        return abi.encodeCall(ModularAccountBase.execute, (recipient, value, ""));
    }

    function _getPerformCreateCalldata(uint256 value) internal pure returns (bytes memory) {
        return abi.encodeCall(ModularAccountBase.performCreate, (value, type(MockDeployment).creationCode));
    }

    function _getPerformCreate2Calldata(uint256 value, bytes32 salt) internal pure returns (bytes memory) {
        return abi.encodeCall(ModularAccountBase.performCreate2, (value, type(MockDeployment).creationCode, salt));
    }

    function _getPackedUO(uint256 gas1, uint256 gas2, uint256 gas3, uint256 gasPrice, bytes memory callData)
        internal
        view
        returns (PackedUserOperation memory uo)
    {
        uo = PackedUserOperation({
            sender: address(acct),
            nonce: 0,
            initCode: "",
            callData: abi.encodePacked(ModularAccountBase.executeUserOp.selector, callData),
            accountGasLimits: bytes32(bytes16(uint128(gas1))) | bytes32(uint256(gas2)),
            preVerificationGas: gas3,
            gasFees: bytes32(uint256(uint128(gasPrice))),
            paymasterAndData: "",
            signature: _encodeSignature(ModuleEntityLib.pack(address(validationModule), 0), 1, "")
        });
    }

    function test_userOp_gasLimit() public {
        vm.startPrank(address(entryPoint));

        // uses 10e - 200000 of gas
        assertEq(module.limits(0, address(acct)), 10 ether);
        uint256 result = acct.validateUserOp(
            _getPackedUO(100_000, 100_000, 10 ether - 400_000, 1, _getExecuteWithValue(0)), bytes32(0), 0
        );
        assertEq(module.limits(0, address(acct)), 200_000);

        uint256 expected = uint256(type(uint48).max) << 160;
        assertEq(result, expected);

        // uses 200k + 1 wei of gas
        vm.expectRevert(NativeTokenLimitModule.ExceededNativeTokenLimit.selector);
        result = acct.validateUserOp(_getPackedUO(100_000, 100_000, 1, 1, _getExecuteWithValue(0)), bytes32(0), 0);
    }

    function test_userOp_executeLimit() public {
        vm.startPrank(address(entryPoint));

        // uses 5e of native tokens
        assertEq(module.limits(0, address(acct)), 10 ether);
        acct.executeUserOp(_getPackedUO(0, 0, 0, 0, _getExecuteWithValue(5 ether)), bytes32(0));
        assertEq(module.limits(0, address(acct)), 5 ether);

        // uses 5e + 1wei of native tokens
        vm.expectRevert(
            abi.encodePacked(
                ModularAccountBase.PreExecHookReverted.selector,
                abi.encode(
                    address(module),
                    uint32(0),
                    abi.encodePacked(NativeTokenLimitModule.ExceededNativeTokenLimit.selector)
                )
            )
        );
        acct.executeUserOp(_getPackedUO(0, 0, 0, 0, _getExecuteWithValue(5 ether + 1)), bytes32(0));
    }

    function test_userOp_executeBatchLimit() public {
        Call[] memory calls = new Call[](3);
        calls[0] = Call({target: recipient, value: 1, data: ""});
        calls[1] = Call({target: recipient, value: 1 ether, data: ""});
        calls[2] = Call({target: recipient, value: 5 ether + 100_000, data: ""});

        vm.startPrank(address(entryPoint));
        assertEq(module.limits(0, address(acct)), 10 ether);
        acct.executeUserOp(
            _getPackedUO(0, 0, 0, 0, abi.encodeCall(IModularAccount.executeBatch, (calls))), bytes32(0)
        );
        assertEq(module.limits(0, address(acct)), 10 ether - 6 ether - 100_001);
        assertEq(recipient.balance, 6 ether + 100_001);
    }

    function test_userOp_performCreateLimit() public {
        vm.startPrank(address(entryPoint));

        // uses 5e of native tokens
        assertEq(module.limits(0, address(acct)), 10 ether);
        acct.executeUserOp(_getPackedUO(0, 0, 0, 0, _getPerformCreateCalldata(5 ether)), bytes32(0));
        assertEq(module.limits(0, address(acct)), 5 ether);
    }

    function test_userOp_performCreate2Limit() public {
        vm.startPrank(address(entryPoint));

        // uses 5e of native tokens
        assertEq(module.limits(0, address(acct)), 10 ether);
        acct.executeUserOp(_getPackedUO(0, 0, 0, 0, _getPerformCreate2Calldata(5 ether, 0)), bytes32(0));
        assertEq(module.limits(0, address(acct)), 5 ether);
    }

    function test_userOp_combinedExecLimit_success() public {
        assertEq(module.limits(0, address(acct)), 10 ether);
        PackedUserOperation[] memory uos = new PackedUserOperation[](1);
        uos[0] = _getPackedUO(200_000, 200_000, 200_000, 1, _getExecuteWithValue(5 ether));
        entryPoint.handleOps(uos, bundler);

        assertEq(module.limits(0, address(acct)), 5 ether - 600_000);
        assertEq(recipient.balance, 5 ether);
    }

    function test_userOp_combinedExecBatchLimit_success() public {
        Call[] memory calls = new Call[](3);
        calls[0] = Call({target: recipient, value: 1, data: ""});
        calls[1] = Call({target: recipient, value: 1 ether, data: ""});
        calls[2] = Call({target: recipient, value: 5 ether + 100_000, data: ""});

        vm.startPrank(address(entryPoint));
        assertEq(module.limits(0, address(acct)), 10 ether);
        PackedUserOperation[] memory uos = new PackedUserOperation[](1);
        uos[0] = _getPackedUO(200_000, 200_000, 200_000, 1, abi.encodeCall(IModularAccount.executeBatch, (calls)));
        entryPoint.handleOps(uos, bundler);

        assertEq(module.limits(0, address(acct)), 10 ether - 6 ether - 700_001);
        assertEq(recipient.balance, 6 ether + 100_001);
    }

    function test_userOp_combinedExecLimit_failExec() public {
        assertEq(module.limits(0, address(acct)), 10 ether);
        PackedUserOperation[] memory uos = new PackedUserOperation[](1);
        uos[0] = _getPackedUO(200_000, 200_000, 200_000, 1, _getExecuteWithValue(10 ether));
        entryPoint.handleOps(uos, bundler);

        assertEq(module.limits(0, address(acct)), 10 ether - 600_000);
        assertEq(recipient.balance, 0);
    }

    function test_runtime_executeLimit() public {
        assertEq(module.limits(0, address(acct)), 10 ether);
        acct.executeWithRuntimeValidation(
            _getExecuteWithValue(5 ether), _encodeSignature(validationFunction, 1, "")
        );
        assertEq(module.limits(0, address(acct)), 5 ether);
    }

    function test_runtime_executeBatchLimit() public {
        Call[] memory calls = new Call[](3);
        calls[0] = Call({target: recipient, value: 1, data: ""});
        calls[1] = Call({target: recipient, value: 1 ether, data: ""});
        calls[2] = Call({target: recipient, value: 5 ether + 100_000, data: ""});

        assertEq(module.limits(0, address(acct)), 10 ether);
        acct.executeWithRuntimeValidation(
            abi.encodeCall(IModularAccount.executeBatch, (calls)), _encodeSignature(validationFunction, 1, "")
        );
        assertEq(module.limits(0, address(acct)), 4 ether - 100_001);
    }

    function test_runtime_performCreateLimit() public {
        assertEq(module.limits(0, address(acct)), 10 ether);
        bytes memory b = acct.executeWithRuntimeValidation(
            _getPerformCreateCalldata(5 ether), _encodeSignature(validationFunction, 1, "")
        );
        assertEq(module.limits(0, address(acct)), 5 ether);

        address deployed = abi.decode(b, (address));
        assertEq(deployed.balance, 5 ether);
    }

    function test_runtime_performCreate2Limit() public {
        assertEq(module.limits(0, address(acct)), 10 ether);
        bytes memory b = acct.executeWithRuntimeValidation(
            _getPerformCreate2Calldata({value: 5 ether, salt: bytes32(0)}),
            _encodeSignature(validationFunction, 1, "")
        );
        assertEq(module.limits(0, address(acct)), 5 ether);

        address deployed = abi.decode(b, (address));
        assertEq(deployed.balance, 5 ether);
    }

    function test_deleteSingleSessionKey() public {
        uint32 newEntityId = 1;

        // Add new entity, delete latest entity, old limit should still work
        ModuleEntity[] memory preValidationHooks = new ModuleEntity[](1);
        preValidationHooks[0] = ModuleEntityLib.pack(address(module), newEntityId);

        bytes[] memory hooks = new bytes[](2);
        hooks[0] =
            abi.encodePacked(HookConfigLib.packValidationHook({_module: address(module), _entityId: newEntityId}));

        hooks[1] = abi.encodePacked(
            HookConfigLib.packExecHook({
                _module: address(module),
                _entityId: entityId,
                _hasPre: true,
                _hasPost: false
            }),
            abi.encode(newEntityId, spendLimit)
        );

        vm.startPrank(address(acct));
        acct.installValidation(
            ValidationConfigLib.pack(address(validationModule), newEntityId, true, true, true),
            new bytes4[](0),
            new bytes(0),
            hooks
        );

        acct.uninstallValidation(
            ModuleEntityLib.pack(address(module), newEntityId), abi.encode(newEntityId), new bytes[](0)
        );

        // prev test passes, implying that the previously allocated limit still exists
        test_userOp_executeLimit();
    }
}
