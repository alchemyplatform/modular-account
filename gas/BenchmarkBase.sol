// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {console} from "forge-std/console.sol";

import {MockERC20} from "../test/mocks/MockERC20.sol";
import {OptimizedTest} from "../test/utils/OptimizedTest.sol";

abstract contract BenchmarkBase is OptimizedTest {
    EntryPoint public entryPoint;
    address payable public beneficiary;

    address public owner1;
    uint256 public owner1Key;

    address public recipient;
    MockERC20 public mockErc20;

    string internal _accountImplName;

    enum BenchmarkType {
        RUNTIME,
        USER_OP
    }

    BenchmarkType public constant RUNTIME = BenchmarkType.RUNTIME;
    BenchmarkType public constant USER_OP = BenchmarkType.USER_OP;

    constructor(string memory accountImplName) {
        _accountImplName = accountImplName;

        (owner1, owner1Key) = makeAddrAndKey("owner1");

        recipient = makeAddr("recipient");
        beneficiary = payable(makeAddr("beneficiary"));

        vm.deal(recipient, 1 wei);
        vm.deal(beneficiary, 1 wei);

        entryPoint = _deployEntryPoint070();

        mockErc20 = new MockERC20();
    }

    function _runtimeBenchmark(address prank, address callee, bytes memory call)
        internal
        returns (uint256 gasUsed)
    {
        vm.prank(prank);
        (bool success,) = callee.call(call);

        require(success, "runtime call failed");

        gasUsed = vm.lastCallGas().gasTotalUsed;
    }

    function _userOpBenchmark(PackedUserOperation memory userOp) internal returns (uint256 gasUsed) {
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        vm.prank(beneficiary);
        entryPoint.handleOps(userOps, beneficiary);

        gasUsed = vm.lastCallGas().gasTotalUsed;
    }

    function _snap(BenchmarkType bType, string memory testCase, uint256 gasValue) internal {
        string memory consoleLine = string.concat(_benchmarkTypeToString(bType), ": ", testCase, ": ");

        console.log(consoleLine);
        console.log("gasTotalUsed: %d", gasValue);

        string memory snapName = string.concat(_benchmarkTypeToString(bType), "_", testCase);

        vm.snapshotValue({group: _accountImplName, name: snapName, value: gasValue});
    }

    function _benchmarkTypeToString(BenchmarkType bType) internal pure returns (string memory) {
        return bType == BenchmarkType.RUNTIME ? "Runtime" : "UserOp";
    }

    function _encodeGasLimits(uint128 callGasLimit, uint128 verificationGasLimit)
        internal
        pure
        returns (bytes32)
    {
        return bytes32(uint256(verificationGasLimit) << 128 | uint256(callGasLimit));
    }

    function _encodeGasFees(uint128 maxFeePerGas, uint128 maxPriorityFeePerGas) internal pure returns (bytes32) {
        return bytes32(uint256(maxPriorityFeePerGas) << 128 | uint256(maxFeePerGas));
    }
}
