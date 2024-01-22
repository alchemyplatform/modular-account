// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

library Utils {
    function reverseAddressArray(address[] calldata array) public pure returns (address[] memory reversedArray) {
        uint256 len = array.length;
        reversedArray = new address[](len);
        for (uint256 i; i < len; i++) {
            reversedArray[i] = array[len - i - 1];
        }
    }
}
