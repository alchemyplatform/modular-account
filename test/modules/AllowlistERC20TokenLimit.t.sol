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

pragma solidity ^0.8.26;

import {MockERC20} from "../mocks/MockERC20.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {Call, IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {AllowlistModule} from "../../src/modules/permissions/AllowlistModule.sol";

import {MockModule} from "../mocks/modules/MockModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";
import {CODELESS_ADDRESS} from "../utils/TestConstants.sol";

contract AllowlistERC20TokenLimitTest is AccountTestBase {
    address public recipient = CODELESS_ADDRESS;
    MockERC20 public erc20;
    ExecutionManifest internal _m;
    MockModule public validationModule = new MockModule(_m);
    ModuleEntity public validationFunction;
    AllowlistModule public module = new AllowlistModule();

    uint256 public spendLimit = 10 ether;

    uint32 public constant ENTITY_ID = 1;

    function setUp() public override {
        _revertSnapshot = vm.snapshotState();
        // Set up a validator with hooks from the erc20 spend limit module attached

        erc20 = new MockERC20();
        erc20.mint(address(account1), 10 ether);

        AllowlistModule.AllowlistInput[] memory inputs = new AllowlistModule.AllowlistInput[](1);
        inputs[0] = AllowlistModule.AllowlistInput({
            target: address(erc20),
            hasSelectorAllowlist: false,
            hasERC20SpendLimit: true,
            erc20SpendLimit: spendLimit,
            selectors: new bytes4[](0)
        });

        bytes[] memory hooks = new bytes[](1);
        hooks[0] = abi.encodePacked(
            HookConfigLib.packExecHook({
                _module: address(module),
                _entityId: ENTITY_ID,
                _hasPre: true,
                _hasPost: false
            }),
            abi.encode(ENTITY_ID, inputs)
        );

        vm.prank(address(account1));
        account1.installValidation(
            ValidationConfigLib.pack(address(validationModule), ENTITY_ID, true, true, true),
            new bytes4[](0),
            "",
            hooks
        );

        validationFunction = ModuleEntityLib.pack(address(validationModule), ENTITY_ID);
    }

    function test_install() public withSMATest {
        uint256 limit = module.erc20SpendLimits(ENTITY_ID, address(erc20), address(account1));
        assertEq(limit, 10 ether);
    }

    function _getPackedUO(bytes memory callData) internal view returns (PackedUserOperation memory uo) {
        uo = PackedUserOperation({
            sender: address(account1),
            nonce: _encodeNonce(validationFunction, GLOBAL_V, 0),
            initCode: "",
            callData: abi.encodePacked(ModularAccountBase.executeUserOp.selector, callData),
            accountGasLimits: bytes32(bytes16(uint128(200_000))) | bytes32(uint256(200_000)),
            preVerificationGas: 200_000,
            gasFees: bytes32(uint256(uint128(0))),
            paymasterAndData: "",
            signature: _encodeSignature("")
        });
    }

    function _getExecuteWithSpend(uint256 value) internal view returns (bytes memory) {
        return abi.encodeCall(
            ModularAccountBase.execute, (address(erc20), 0, abi.encodeCall(IERC20.transfer, (recipient, value)))
        );
    }

    function test_userOp_executeLimit() public withSMATest {
        vm.startPrank(address(entryPoint));

        uint256 limit = module.erc20SpendLimits(ENTITY_ID, address(erc20), address(account1));

        assertEq(limit, 10 ether);
        account1.executeUserOp(_getPackedUO(_getExecuteWithSpend(5 ether)), bytes32(0));

        limit = module.erc20SpendLimits(ENTITY_ID, address(erc20), address(account1));
        assertEq(limit, 5 ether);
        vm.stopPrank();
    }

    function test_userOp_executeBatchLimit() public withSMATest {
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
        account1.executeUserOp(_getPackedUO(abi.encodeCall(IModularAccount.executeBatch, (calls))), bytes32(0));

        uint256 limit = module.erc20SpendLimits(ENTITY_ID, address(erc20), address(account1));
        assertEq(limit, 10 ether - 6 ether - 100_001);
        vm.stopPrank();
    }

    function test_userOp_executeBatch_approveAndTransferLimit() public withSMATest {
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
        account1.executeUserOp(_getPackedUO(abi.encodeCall(IModularAccount.executeBatch, (calls))), bytes32(0));

        uint256 limit = module.erc20SpendLimits(ENTITY_ID, address(erc20), address(account1));
        assertEq(limit, 10 ether - 6 ether - 100_001);
        vm.stopPrank();
    }

    function test_userOp_executeBatch_approveAndTransferLimit_fail() public withSMATest {
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
        PackedUserOperation[] memory uos = new PackedUserOperation[](1);
        uos[0] = _getPackedUO(abi.encodeCall(IModularAccount.executeBatch, (calls)));
        entryPoint.handleOps(uos, beneficiary);
        // no spend consumed

        uint256 limit = module.erc20SpendLimits(ENTITY_ID, address(erc20), address(account1));
        assertEq(limit, 10 ether);
        vm.stopPrank();
    }

    function test_runtime_executeLimit() public withSMATest {
        account1.executeWithRuntimeValidation(
            _getExecuteWithSpend(5 ether), _encodeSignature(validationFunction, 1, "")
        );

        uint256 limit = module.erc20SpendLimits(ENTITY_ID, address(erc20), address(account1));
        assertEq(limit, 5 ether);
    }

    function test_runtime_executeBatchLimit() public withSMATest {
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
        account1.executeWithRuntimeValidation(
            abi.encodeCall(IModularAccount.executeBatch, (calls)), _encodeSignature(validationFunction, 1, "")
        );

        uint256 limit = module.erc20SpendLimits(ENTITY_ID, address(erc20), address(account1));
        assertEq(limit, 10 ether - 6 ether - 100_001);
    }
}
