// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

function getEmptyCalldataSlice() pure returns (bytes calldata) {
    bytes calldata empty;

    assembly ("memory-safe") {
        empty.length := 0
    }

    return empty;
}
