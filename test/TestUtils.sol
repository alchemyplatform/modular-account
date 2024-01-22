// SPDX-License-Identifier: UNLICENSED
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
