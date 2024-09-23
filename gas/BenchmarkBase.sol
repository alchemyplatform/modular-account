// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {GasSnapshot} from "forge-gas-snapshot/GasSnapshot.sol";

import {MockERC20} from "../test/mocks/MockERC20.sol";

import {OptimizedTest} from "../test/utils/OptimizedTest.sol";

abstract contract BenchmarkBase is OptimizedTest, GasSnapshot {
    EntryPoint public entryPoint;
    address payable public beneficiary;

    address public owner1;
    uint256 public owner1Key;

    address public recipient;
    MockERC20 public mockErc20;

    constructor() {
        (owner1, owner1Key) = makeAddrAndKey("owner1");

        recipient = makeAddr("recipient");
        beneficiary = payable(makeAddr("beneficiary"));

        vm.deal(recipient, 1 wei);
        vm.deal(beneficiary, 1 wei);

        entryPoint = _deployEntryPoint070();

        mockErc20 = new MockERC20();
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
