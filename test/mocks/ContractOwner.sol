// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract ContractOwner is IERC1271 {
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function sign(bytes32 digest) public pure returns (bytes memory) {
        return abi.encodePacked("Signed: ", digest);
    }

    function isValidSignature(bytes32 digest, bytes memory signature) public view override returns (bytes4) {
        if (keccak256(signature) == keccak256(sign(digest))) {
            // simple owner sig validation path
            return _1271_MAGIC_VALUE;
        } else {
            // EOA owner of this contractOwner path
            (address signer,) = ECDSA.tryRecover(digest, signature);
            if (signer == owner) {
                return _1271_MAGIC_VALUE;
            }
        }
        return 0xffffffff;
    }
}
