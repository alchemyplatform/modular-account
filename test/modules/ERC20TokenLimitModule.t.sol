// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {MockERC20} from "../mocks/MockERC20.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {Call, IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {HookConfigLib} from "../../src/libraries/HookConfigLib.sol";
import {ModuleEntity} from "../../src/libraries/ModuleEntityLib.sol";
import {ModuleEntityLib} from "../../src/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "../../src/libraries/ValidationConfigLib.sol";
import {ERC20TokenLimitModule} from "../../src/modules/permissions/ERC20TokenLimitModule.sol";

import {MockModule} from "../mocks/modules/MockModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract ERC20TokenLimitModuleTest is AccountTestBase {
    address public recipient = address(1);
    MockERC20 public erc20;
    address payable public bundler = payable(address(2));
    ExecutionManifest internal _m;
    MockModule public validationModule = new MockModule(_m);
    ModuleEntity public validationFunction;

    ModularAccount public acct;
    ERC20TokenLimitModule public module = new ERC20TokenLimitModule();
    uint256 public spendLimit = 10 ether;

    function setUp() public {
        // Set up a validator with hooks from the erc20 spend limit module attached
        acct = factory.createAccount(address(this), 0, 0);

        erc20 = new MockERC20();
        erc20.mint(address(acct), 10 ether);

        ERC20TokenLimitModule.ERC20SpendLimit[] memory limit = new ERC20TokenLimitModule.ERC20SpendLimit[](1);
        limit[0] = ERC20TokenLimitModule.ERC20SpendLimit({token: address(erc20), limit: spendLimit});

        bytes[] memory hooks = new bytes[](1);
        hooks[0] = abi.encodePacked(
            HookConfigLib.packExecHook({_module: address(module), _entityId: 0, _hasPre: true, _hasPost: false}),
            abi.encode(uint32(0), limit)
        );

        vm.prank(address(acct));
        acct.installValidation(
            ValidationConfigLib.pack(address(validationModule), 0, true, true, true), new bytes4[](0), "", hooks
        );

        validationFunction = ModuleEntityLib.pack(address(validationModule), 0);
    }

    function _getPackedUO(bytes memory callData) internal view returns (PackedUserOperation memory uo) {
        uo = PackedUserOperation({
            sender: address(acct),
            nonce: 0,
            initCode: "",
            callData: abi.encodePacked(ModularAccountBase.executeUserOp.selector, callData),
            accountGasLimits: bytes32(bytes16(uint128(200_000))) | bytes32(uint256(200_000)),
            preVerificationGas: 200_000,
            gasFees: bytes32(uint256(uint128(0))),
            paymasterAndData: "",
            signature: _encodeSignature(ModuleEntityLib.pack(address(validationModule), 0), 1, "")
        });
    }

    function _getExecuteWithSpend(uint256 value) internal view returns (bytes memory) {
        return abi.encodeCall(
            ModularAccountBase.execute, (address(erc20), 0, abi.encodeCall(IERC20.transfer, (recipient, value)))
        );
    }

    function test_userOp_executeLimit() public {
        vm.startPrank(address(entryPoint));

        (, uint256 limit) = module.limits(0, address(erc20), address(acct));

        assertEq(limit, 10 ether);
        acct.executeUserOp(_getPackedUO(_getExecuteWithSpend(5 ether)), bytes32(0));

        (, limit) = module.limits(0, address(erc20), address(acct));
        assertEq(limit, 5 ether);
    }

    function test_userOp_executeBatchLimit() public {
        Call[] memory calls = new Call[](3);
        calls[0] =
            Call({target: address(erc20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient, 1 wei))});
        calls[1] =
            Call({target: address(erc20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient, 1 ether))});
        calls[2] = Call({
            target: address(erc20),
            value: 0,
            data: abi.encodeCall(IERC20.transfer, (recipient, 5 ether + 100_000))
        });

        vm.startPrank(address(entryPoint));
        (, uint256 limit) = module.limits(0, address(erc20), address(acct));
        assertEq(limit, 10 ether);
        acct.executeUserOp(_getPackedUO(abi.encodeCall(IModularAccount.executeBatch, (calls))), bytes32(0));

        (, limit) = module.limits(0, address(erc20), address(acct));
        assertEq(limit, 10 ether - 6 ether - 100_001);
    }

    function test_userOp_executeBatch_approveAndTransferLimit() public {
        Call[] memory calls = new Call[](3);
        calls[0] =
            Call({target: address(erc20), value: 0, data: abi.encodeCall(IERC20.approve, (recipient, 1 wei))});
        calls[1] =
            Call({target: address(erc20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient, 1 ether))});
        calls[2] = Call({
            target: address(erc20),
            value: 0,
            data: abi.encodeCall(IERC20.approve, (recipient, 5 ether + 100_000))
        });

        vm.startPrank(address(entryPoint));
        (, uint256 limit) = module.limits(0, address(erc20), address(acct));
        assertEq(limit, 10 ether);
        acct.executeUserOp(_getPackedUO(abi.encodeCall(IModularAccount.executeBatch, (calls))), bytes32(0));

        (, limit) = module.limits(0, address(erc20), address(acct));
        assertEq(limit, 10 ether - 6 ether - 100_001);
    }

    function test_userOp_executeBatch_approveAndTransferLimit_fail() public {
        Call[] memory calls = new Call[](3);
        calls[0] =
            Call({target: address(erc20), value: 0, data: abi.encodeCall(IERC20.approve, (recipient, 1 wei))});
        calls[1] =
            Call({target: address(erc20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient, 1 ether))});
        calls[2] = Call({
            target: address(erc20),
            value: 0,
            data: abi.encodeCall(IERC20.approve, (recipient, 9 ether + 100_000))
        });

        vm.startPrank(address(entryPoint));
        (, uint256 limit) = module.limits(0, address(erc20), address(acct));
        assertEq(limit, 10 ether);
        PackedUserOperation[] memory uos = new PackedUserOperation[](1);
        uos[0] = _getPackedUO(abi.encodeCall(IModularAccount.executeBatch, (calls)));
        entryPoint.handleOps(uos, bundler);
        // no spend consumed

        (, limit) = module.limits(0, address(erc20), address(acct));
        assertEq(limit, 10 ether);
    }

    function test_runtime_executeLimit() public {
        (, uint256 limit) = module.limits(0, address(erc20), address(acct));
        assertEq(limit, 10 ether);
        acct.executeWithRuntimeValidation(
            _getExecuteWithSpend(5 ether),
            _encodeSignature(ModuleEntityLib.pack(address(validationModule), 0), 1, "")
        );

        (, limit) = module.limits(0, address(erc20), address(acct));
        assertEq(limit, 5 ether);
    }

    function test_runtime_executeBatchLimit() public {
        Call[] memory calls = new Call[](3);
        calls[0] =
            Call({target: address(erc20), value: 0, data: abi.encodeCall(IERC20.approve, (recipient, 1 wei))});
        calls[1] =
            Call({target: address(erc20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient, 1 ether))});
        calls[2] = Call({
            target: address(erc20),
            value: 0,
            data: abi.encodeCall(IERC20.approve, (recipient, 5 ether + 100_000))
        });

        (, uint256 limit) = module.limits(0, address(erc20), address(acct));
        assertEq(limit, 10 ether);
        acct.executeWithRuntimeValidation(
            abi.encodeCall(IModularAccount.executeBatch, (calls)),
            _encodeSignature(ModuleEntityLib.pack(address(validationModule), 0), 1, "")
        );

        (, limit) = module.limits(0, address(erc20), address(acct));
        assertEq(limit, 10 ether - 6 ether - 100_001);
    }
}
