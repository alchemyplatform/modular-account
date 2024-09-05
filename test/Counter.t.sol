// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Counter} from "../src/Counter.sol";
import {Test} from "forge-std/Test.sol";

contract CounterTest is Test {
    Counter public counter;

    function setUp() public {
        counter = new Counter();
        counter.setNumber(0);
    }

    function testIncrement() public {
        counter.increment();
        assertEq(counter.number(), 1);
    }

    function testSetNumber(uint256 x) public {
        counter.setNumber(x);
        assertEq(counter.number(), x);
    }
}
