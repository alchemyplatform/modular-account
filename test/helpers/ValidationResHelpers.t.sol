// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test} from "forge-std/src/Test.sol";

import {
    ValidationData,
    _packValidationData,
    _packValidationData
} from "@eth-infinitism/account-abstraction/core/Helpers.sol";

import {_coalescePreValidation, _coalesceValidation} from "../../src/helpers/ValidationResHelpers.sol";

contract ValidationResHelpersTest is Test {
    function test_coalesceValidation() public pure {
        // both validation res have all three values, one return aggregator address, one success
        assertEq(
            _coalesceValidation(
                _packValidationData(false, uint48(5), uint48(1)),
                _packValidationData(ValidationData(address(2), uint48(2), uint48(6)))
            ),
            _packValidationData(ValidationData(address(2), uint48(2), uint48(5)))
        );

        // both validation res have all three values, one return aggregator address, one fail
        assertEq(
            _coalesceValidation(
                _packValidationData(true, uint48(5), uint48(1)),
                _packValidationData(ValidationData(address(2), uint48(2), uint48(6)))
            ),
            _packValidationData(true, uint48(5), uint48(2))
        );
        // both validation res have all three values
        assertEq(
            _coalesceValidation(
                _packValidationData(false, uint48(5), uint48(1)), _packValidationData(false, uint48(6), uint48(2))
            ),
            _packValidationData(false, uint48(5), uint48(2))
        );
        assertEq(
            _coalesceValidation(
                _packValidationData(true, uint48(5), uint48(1)), _packValidationData(false, uint48(6), uint48(2))
            ),
            _packValidationData(true, uint48(5), uint48(2))
        );

        // one validation res missing
        assertEq(
            _coalesceValidation(0, _packValidationData(false, uint48(6), uint48(1))),
            _packValidationData(false, uint48(6), uint48(1))
        );
        assertEq(
            _coalesceValidation(0, _packValidationData(true, uint48(6), uint48(1))),
            _packValidationData(true, uint48(6), uint48(1))
        );
        assertEq(
            _coalesceValidation(_packValidationData(false, uint48(5), uint48(0)), 0),
            _packValidationData(false, uint48(5), uint48(0))
        );
        assertEq(
            _coalesceValidation(_packValidationData(true, uint48(5), uint48(0)), 0),
            _packValidationData(true, uint48(5), uint48(0))
        );

        // one validation only has validUntil
        assertEq(
            _coalesceValidation(
                _packValidationData(false, uint48(5), uint48(0)), _packValidationData(false, uint48(6), uint48(1))
            ),
            _packValidationData(false, uint48(5), uint48(1))
        );
        assertEq(
            _coalesceValidation(
                _packValidationData(false, uint48(6), uint48(1)), _packValidationData(false, uint48(5), uint48(0))
            ),
            _packValidationData(false, uint48(5), uint48(1))
        );

        // one validation only has validUntil, one only has validAfter
        assertEq(
            _coalesceValidation(
                _packValidationData(false, uint48(5), uint48(0)), _packValidationData(false, uint48(0), uint48(1))
            ),
            _packValidationData(false, uint48(5), uint48(1))
        );
        assertEq(
            _coalesceValidation(
                _packValidationData(false, uint48(0), uint48(1)), _packValidationData(false, uint48(5), uint48(0))
            ),
            _packValidationData(false, uint48(5), uint48(1))
        );
    }

    function test_coalescePreValidation() public pure {
        // both validation res have all three values
        assertEq(
            _coalescePreValidation(
                _packValidationData(false, uint48(5), uint48(1)), _packValidationData(false, uint48(6), uint48(2))
            ),
            _packValidationData(false, uint48(5), uint48(2))
        );
        assertEq(
            _coalescePreValidation(
                _packValidationData(true, uint48(5), uint48(1)), _packValidationData(false, uint48(6), uint48(2))
            ),
            _packValidationData(true, uint48(5), uint48(2))
        );

        // one validation res missing
        assertEq(
            _coalescePreValidation(0, _packValidationData(false, uint48(6), uint48(1))),
            _packValidationData(false, uint48(6), uint48(1))
        );
        assertEq(
            _coalescePreValidation(0, _packValidationData(true, uint48(6), uint48(1))),
            _packValidationData(true, uint48(6), uint48(1))
        );
        assertEq(
            _coalescePreValidation(_packValidationData(false, uint48(5), uint48(0)), 0),
            _packValidationData(false, uint48(5), uint48(0))
        );
        assertEq(
            _coalescePreValidation(_packValidationData(true, uint48(5), uint48(0)), 0),
            _packValidationData(true, uint48(5), uint48(0))
        );

        // one validation only has validUntil
        assertEq(
            _coalescePreValidation(
                _packValidationData(false, uint48(5), uint48(0)), _packValidationData(false, uint48(6), uint48(1))
            ),
            _packValidationData(false, uint48(5), uint48(1))
        );
        assertEq(
            _coalescePreValidation(
                _packValidationData(false, uint48(6), uint48(1)), _packValidationData(false, uint48(5), uint48(0))
            ),
            _packValidationData(false, uint48(5), uint48(1))
        );

        // one validation only has validUntil, one only has validAfter
        assertEq(
            _coalescePreValidation(
                _packValidationData(false, uint48(5), uint48(0)), _packValidationData(false, uint48(0), uint48(1))
            ),
            _packValidationData(false, uint48(5), uint48(1))
        );
        assertEq(
            _coalescePreValidation(
                _packValidationData(false, uint48(0), uint48(1)), _packValidationData(false, uint48(5), uint48(0))
            ),
            _packValidationData(false, uint48(5), uint48(1))
        );
    }
}
