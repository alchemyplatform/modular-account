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

pragma solidity ^0.8.22;

import {Test, console} from "forge-std/Test.sol";

contract TestUtils is Test {
    function printStorageReadsAndWrites(address addr) internal {
        (bytes32[] memory accountReads, bytes32[] memory accountWrites) = vm.accesses(addr);
        for (uint256 i = 0; i < accountWrites.length; i++) {
            bytes32 valWritten = vm.load(addr, accountWrites[i]);
            console.log(
                string.concat("write loc: ", vm.toString(accountWrites[i]), " val: ", vm.toString(valWritten))
            );
        }

        for (uint256 i = 0; i < accountReads.length; i++) {
            bytes32 valRead = vm.load(addr, accountReads[i]);
            console.log(string.concat("read: ", vm.toString(accountReads[i]), " val: ", vm.toString(valRead)));
        }
    }
}
