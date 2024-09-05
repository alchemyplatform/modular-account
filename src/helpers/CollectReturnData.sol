// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

function collectReturnData() pure returns (bytes memory returnData) {
    assembly ("memory-safe") {
        // Allocate a buffer of that size, advancing the memory pointer to the nearest word
        returnData := mload(0x40)
        mstore(returnData, returndatasize())
        mstore(0x40, and(add(add(returnData, returndatasize()), 0x3f), not(0x1f)))

        // Copy over the return data
        returndatacopy(add(returnData, 0x20), 0, returndatasize())
    }
}
