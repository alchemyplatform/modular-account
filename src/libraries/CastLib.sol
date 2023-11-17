// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {FunctionReference} from "./FunctionReferenceLib.sol";
import {SetValue} from "./LinkedListSetUtils.sol";

/// @title Cast Library
/// @author Alchemy
/// @notice Library for various data type conversions.
library CastLib {
    function toFunctionReferenceArray(SetValue[] memory vals)
        internal
        pure
        returns (FunctionReference[] memory ret)
    {
        assembly ("memory-safe") {
            ret := vals
        }
    }

    function toAddressArray(SetValue[] memory values) internal pure returns (address[] memory addresses) {
        bytes32[] memory valuesBytes;

        assembly ("memory-safe") {
            valuesBytes := values
        }

        uint256 length = values.length;
        for (uint256 i = 0; i < length;) {
            valuesBytes[i] >>= 96;

            unchecked {
                i++;
            }
        }

        assembly ("memory-safe") {
            addresses := valuesBytes
        }

        return addresses;
    }

    function toSetValue(FunctionReference functionReference) internal pure returns (SetValue) {
        return SetValue.wrap(bytes30(FunctionReference.unwrap(functionReference)));
    }

    function toSetValue(address value) internal pure returns (SetValue) {
        return SetValue.wrap(bytes30(bytes20(value)));
    }
}
