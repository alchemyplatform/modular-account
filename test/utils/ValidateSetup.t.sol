// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {OptimizedTest} from "./OptimizedTest.sol";

contract ValidateSetupTest is OptimizedTest {
    function test_deployedEntryPoint() public {
        _deployEntryPoint070();

        address entryPoint = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
        address senderCreator = 0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C;

        assertEq(entryPoint.codehash, 0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58);
        assertEq(senderCreator.codehash, 0x283c9d14378f5f4c4e24045b87d621d48443fa5b4af7dd7180a599b3756a7689);
    }
}
