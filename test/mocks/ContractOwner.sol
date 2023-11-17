// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

contract ContractOwner is IERC1271 {
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;

    function sign(bytes32 digest) public pure returns (bytes memory) {
        return abi.encodePacked("Signed: ", digest);
    }

    function isValidSignature(bytes32 digest, bytes memory signature) public pure override returns (bytes4) {
        if (keccak256(signature) == keccak256(sign(digest))) {
            return _1271_MAGIC_VALUE;
        }
        return 0xffffffff;
    }
}
