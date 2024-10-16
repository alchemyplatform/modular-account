// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

contract MockRevertingConstructor {
    constructor() {
        revert("Constructor reverts");
    }
}
