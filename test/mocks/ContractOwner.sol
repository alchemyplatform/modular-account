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
