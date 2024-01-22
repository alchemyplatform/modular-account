// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {Test} from "forge-std/Test.sol";

import {LinkedListSetHandler} from "./handlers/LinkedListSetHandler.sol";
import {AssociatedLinkedListSetHandler} from "./handlers/AssociatedLinkedListSetHandler.sol";

contract LLSLReproTest is Test {
    LinkedListSetHandler public handler;
    AssociatedLinkedListSetHandler public associatedHandler;

    function setUp() public {
        handler = new LinkedListSetHandler();
        associatedHandler = new AssociatedLinkedListSetHandler();
    }

    function test_repro_1() public {
        handler.removeRandKeyIterate(0);
        handler.add(0xeeeb07e4676e566803e52fe9a102d0fe0c0ae5007215518bffb33d6c07e2);
        handler.removeRandKnownPrevKey(
            0xeeeb07e4676e566803e52fe9a102d0fe0c0ae5007215518bffb33d6c07e2,
            0x0000000000000000000000000000000000000000000000000000000000001b01
        );
    }

    function test_repro_2() public {
        associatedHandler.removeRandKeyIterate(0, 0, 0);
        associatedHandler.add(0xeeeb07e4676e566803e52fe9a102d0fe0c0ae5007215518bffb33d6c07e2, 0, 0);
        associatedHandler.removeRandKnownPrevKey(
            0xeeeb07e4676e566803e52fe9a102d0fe0c0ae5007215518bffb33d6c07e2,
            0x0000000000000000000000000000000000000000000000000000000000001b01,
            0,
            0
        );
    }
}
