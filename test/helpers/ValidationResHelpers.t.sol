// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test} from "forge-std/src/Test.sol";

import {_packValidationData} from "@eth-infinitism/account-abstraction/core/Helpers.sol";

import {_coalesceValidationRes} from "../../src/helpers/ValidationResHelpers.sol";

contract ValidationResHelpersTest is Test {
    function test_coalesceValidationRes() public pure {
        // both validation res have all three values
        assertEq(
            _coalesceValidationRes(
                _packValidationData(false, uint48(5), uint48(0)), _packValidationData(false, uint48(6), uint48(1))
            ),
            _packValidationData(false, uint48(5), uint48(1))
        );

        assertEq(
            _coalesceValidationRes(
                _packValidationData(true, uint48(5), uint48(0)), _packValidationData(false, uint48(6), uint48(1))
            ),
            _packValidationData(true, uint48(5), uint48(1))
        );

        // one validation res missing
        assertEq(
            _coalesceValidationRes(0, _packValidationData(false, uint48(6), uint48(1))),
            _packValidationData(false, uint48(6), uint48(1))
        );
        assertEq(
            _coalesceValidationRes(0, _packValidationData(true, uint48(6), uint48(1))),
            _packValidationData(true, uint48(6), uint48(1))
        );
        assertEq(
            _coalesceValidationRes(_packValidationData(false, uint48(5), uint48(0)), 0),
            _packValidationData(false, uint48(5), uint48(0))
        );
        assertEq(
            _coalesceValidationRes(_packValidationData(true, uint48(5), uint48(0)), 0),
            _packValidationData(true, uint48(5), uint48(0))
        );
    }
}
