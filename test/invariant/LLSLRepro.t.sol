// This file is part of Modular Account.
//
// Copyright 2024 Alchemy Insights, Inc.
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General
// Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with this program.  If not, see
// <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.22;

import {Test} from "forge-std/Test.sol";

import {AssociatedLinkedListSetHandler} from "./handlers/AssociatedLinkedListSetHandler.sol";
import {LinkedListSetHandler} from "./handlers/LinkedListSetHandler.sol";

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
