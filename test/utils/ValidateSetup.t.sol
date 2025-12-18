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
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.28;

import {OptimizedTest} from "./OptimizedTest.sol";

contract ValidateSetupTest is OptimizedTest {
    function test_deployedEntryPoint() public {
        _deployEntryPoint090();

        address entryPoint = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;
        address senderCreator = 0x0A630a99Df908A81115A3022927Be82f9299987e;

        assertEq(entryPoint.codehash, 0x14ee3fe0191de027aecf20ffd7dbd985f5023b898fa429485d2dfe2286b42750);
        // update
        assertEq(senderCreator.codehash, 0xa7d4dd260bca9c96da49f7c0682fdda7f0074694d935815a336d3e60ee3ec6ad);
        // update
    }
}
